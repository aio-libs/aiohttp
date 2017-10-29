import asyncio
import contextlib
import os
import platform
import signal
import socket
import ssl
import subprocess
import sys
from unittest import mock
from uuid import uuid4

import pytest

from aiohttp import web
from aiohttp.test_utils import loop_context


# Test for features of OS' socket support
_has_unix_domain_socks = hasattr(socket, 'AF_UNIX')
if _has_unix_domain_socks:
    _abstract_path_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        _abstract_path_sock.bind(b"\x00" + uuid4().hex.encode('ascii'))
    except FileNotFoundError:
        _abstract_path_failed = True
    else:
        _abstract_path_failed = False
    finally:
        _abstract_path_sock.close()
        del _abstract_path_sock
else:
    _abstract_path_failed = True

skip_if_no_abstract_paths = pytest.mark.skipif(
    _abstract_path_failed,
    reason="Linux-style abstract paths are not supported."
)
skip_if_no_unix_socks = pytest.mark.skipif(
    not _has_unix_domain_socks,
    reason="Unix domain sockets are not supported"
)
del _has_unix_domain_socks, _abstract_path_failed

has_ipv6 = socket.has_ipv6
if has_ipv6:
    # The socket.has_ipv6 flag may be True if Python was built with IPv6
    # support, but the target system still may not have it.
    # So let's ensure that we really have IPv6 support.
    try:
        socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    except OSError:
        has_ipv6 = False


# tokio event loop does not allow to override attributes
def skip_if_no_dict(loop):
    if not hasattr(loop, '__dict__'):
        pytest.skip("can not override loop attributes")


def skip_if_on_windows():
    if platform.system() == "Windows":
        pytest.skip("the test is not valid for Windows")


def stopper(loop):
    def f(*args):
        loop.call_later(0.001, loop.stop)
    return f


def test_run_app_http(loop, mocker):
    skip_if_no_dict(loop)

    mocker.spy(loop, 'create_server')

    app = web.Application()
    mocker.spy(app, 'startup')

    web.run_app(app, loop=loop, print=stopper(loop))

    assert not loop.is_closed()
    loop.create_server.assert_called_with(mock.ANY, '0.0.0.0', 8080,
                                          ssl=None, backlog=128)
    app.startup.assert_called_once_with()


def test_run_app_close_loop(loop, mocker):
    skip_if_no_dict(loop)

    mocker.spy(loop, 'create_server')

    asyncio.set_event_loop(loop)

    app = web.Application()
    mocker.spy(app, 'startup')

    web.run_app(app, print=stopper(loop))

    assert loop.is_closed()
    loop.create_server.assert_called_with(mock.ANY, '0.0.0.0', 8080,
                                          ssl=None, backlog=128)
    app.startup.assert_called_once_with()
    asyncio.set_event_loop(None)


mock_unix_server_single = [
    mock.call(mock.ANY, '/tmp/testsock1.sock', ssl=None, backlog=128),
]
mock_unix_server_multi = [
    mock.call(mock.ANY, '/tmp/testsock1.sock', ssl=None, backlog=128),
    mock.call(mock.ANY, '/tmp/testsock2.sock', ssl=None, backlog=128),
]
mock_server_single = [
    mock.call(mock.ANY, '127.0.0.1', 8080, ssl=None, backlog=128),
]
mock_server_multi = [
    mock.call(mock.ANY, ('127.0.0.1', '192.168.1.1'), 8080, ssl=None,
              backlog=128),
]
mock_server_default_8989 = [
    mock.call(mock.ANY, '0.0.0.0', 8989, ssl=None, backlog=128)
]
mock_socket = mock.Mock(getsockname=lambda: ('mock-socket', 123))
mixed_bindings_tests = (
    (
        "Nothing Specified",
        {},
        [mock.call(mock.ANY, '0.0.0.0', 8080, ssl=None, backlog=128)],
        []
    ),
    (
        "Port Only",
        {'port': 8989},
        mock_server_default_8989,
        []
    ),
    (
        "Multiple Hosts",
        {'host': ('127.0.0.1', '192.168.1.1')},
        mock_server_multi,
        []
    ),
    (
        "Multiple Paths",
        {'path': ('/tmp/testsock1.sock', '/tmp/testsock2.sock')},
        [],
        mock_unix_server_multi
    ),
    (
        "Multiple Paths, Port",
        {'path': ('/tmp/testsock1.sock', '/tmp/testsock2.sock'),
         'port': 8989},
        mock_server_default_8989,
        mock_unix_server_multi,
    ),
    (
        "Multiple Paths, Single Host",
        {'path': ('/tmp/testsock1.sock', '/tmp/testsock2.sock'),
         'host': '127.0.0.1'},
        mock_server_single,
        mock_unix_server_multi
    ),
    (
        "Single Path, Single Host",
        {'path': '/tmp/testsock1.sock', 'host': '127.0.0.1'},
        mock_server_single,
        mock_unix_server_single
    ),
    (
        "Single Path, Multiple Hosts",
        {'path': '/tmp/testsock1.sock', 'host': ('127.0.0.1', '192.168.1.1')},
        mock_server_multi,
        mock_unix_server_single
    ),
    (
        "Single Path, Port",
        {'path': '/tmp/testsock1.sock', 'port': 8989},
        mock_server_default_8989,
        mock_unix_server_single
    ),
    (
        "Multiple Paths, Multiple Hosts, Port",
        {'path': ('/tmp/testsock1.sock', '/tmp/testsock2.sock'),
         'host': ('127.0.0.1', '192.168.1.1'), 'port': 8000},
        [mock.call(mock.ANY, ('127.0.0.1', '192.168.1.1'), 8000, ssl=None,
                   backlog=128)],
        mock_unix_server_multi
    ),
    (
        "Only socket",
        {"sock": [mock_socket]},
        [mock.call(mock.ANY, ssl=None, sock=mock_socket, backlog=128)],
        [],
    ),
    (
        "Socket, port",
        {"sock": [mock_socket], "port": 8765},
        [mock.call(mock.ANY, '0.0.0.0', 8765, ssl=None, backlog=128),
         mock.call(mock.ANY, sock=mock_socket, ssl=None, backlog=128)],
        [],
    ),
    (
        "Socket, Host, No port",
        {"sock": [mock_socket], "host": 'localhost'},
        [mock.call(mock.ANY, 'localhost', 8080, ssl=None, backlog=128),
         mock.call(mock.ANY, sock=mock_socket, ssl=None, backlog=128)],
        [],
    ),
)
mixed_bindings_test_ids = [test[0] for test in mixed_bindings_tests]
mixed_bindings_test_params = [test[1:] for test in mixed_bindings_tests]


@pytest.mark.parametrize(
    'run_app_kwargs, expected_server_calls, expected_unix_server_calls',
    mixed_bindings_test_params,
    ids=mixed_bindings_test_ids
)
def test_run_app_mixed_bindings(mocker, run_app_kwargs, expected_server_calls,
                                expected_unix_server_calls):
    app = mocker.MagicMock()
    loop = mocker.MagicMock()
    mocker.patch('asyncio.gather')

    web.run_app(app, loop=loop, print=None, **run_app_kwargs)

    assert loop.create_unix_server.mock_calls == expected_unix_server_calls
    assert loop.create_server.mock_calls == expected_server_calls


def test_run_app_http_access_format(loop, mocker):
    skip_if_no_dict(loop)

    mocker.spy(loop, 'create_server')

    app = web.Application()
    mocker.spy(app, 'startup')

    web.run_app(app, loop=loop,
                print=stopper(loop), access_log_format='%a')

    assert not loop.is_closed()
    cs = loop.create_server
    cs.assert_called_with(mock.ANY, '0.0.0.0', 8080, ssl=None, backlog=128)
    assert cs.call_args[0][0]._kwargs['access_log_format'] == '%a'
    app.startup.assert_called_once_with()


def test_run_app_https(loop, mocker):
    skip_if_no_dict(loop)

    mocker.spy(loop, 'create_server')

    app = web.Application()
    mocker.spy(app, 'startup')

    ssl_context = ssl.create_default_context()

    web.run_app(app, loop=loop,
                ssl_context=ssl_context, print=stopper(loop))

    assert not loop.is_closed()
    loop.create_server.assert_called_with(mock.ANY, '0.0.0.0', 8443,
                                          ssl=ssl_context, backlog=128)
    app.startup.assert_called_once_with()


def test_run_app_nondefault_host_port(loop, unused_port, mocker):
    skip_if_no_dict(loop)

    port = unused_port()
    host = '127.0.0.1'

    mocker.spy(loop, 'create_server')

    app = web.Application()
    mocker.spy(app, 'startup')

    web.run_app(app, loop=loop,
                host=host, port=port, print=stopper(loop))

    assert not loop.is_closed()
    loop.create_server.assert_called_with(mock.ANY, host, port,
                                          ssl=None, backlog=128)
    app.startup.assert_called_once_with()


def test_run_app_custom_backlog(loop, mocker):
    skip_if_no_dict(loop)

    mocker.spy(loop, 'create_server')

    app = web.Application()
    mocker.spy(app, 'startup')

    web.run_app(app, loop=loop, backlog=10, print=stopper(loop))

    assert not loop.is_closed()
    loop.create_server.assert_called_with(mock.ANY, '0.0.0.0', 8080,
                                          ssl=None, backlog=10)
    app.startup.assert_called_once_with()


@skip_if_no_unix_socks
def test_run_app_http_unix_socket(loop, mocker, shorttmpdir):
    skip_if_no_dict(loop)

    mocker.spy(loop, 'create_unix_server')

    app = web.Application()
    mocker.spy(app, 'startup')

    sock_path = str(shorttmpdir.join('socket.sock'))
    printer = mock.Mock(wraps=stopper(loop))
    web.run_app(app, loop=loop, path=sock_path,
                print=printer)

    assert not loop.is_closed()
    loop.create_unix_server.assert_called_with(mock.ANY, sock_path,
                                               ssl=None, backlog=128)
    app.startup.assert_called_once_with()
    assert "http://unix:{}:".format(sock_path) in printer.call_args[0][0]


@skip_if_no_unix_socks
def test_run_app_https_unix_socket(loop, mocker, shorttmpdir):
    skip_if_no_dict(loop)

    mocker.spy(loop, 'create_unix_server')

    app = web.Application()
    mocker.spy(app, 'startup')

    sock_path = str(shorttmpdir.join('socket.sock'))
    ssl_context = ssl.create_default_context()
    printer = mock.Mock(wraps=stopper(loop))
    web.run_app(app, loop=loop, path=sock_path, ssl_context=ssl_context,
                print=printer)

    assert not loop.is_closed()
    loop.create_unix_server.assert_called_with(mock.ANY, sock_path,
                                               ssl=ssl_context, backlog=128)
    app.startup.assert_called_once_with()
    assert "https://unix:{}:".format(sock_path) in printer.call_args[0][0]


@skip_if_no_unix_socks
def test_run_app_stale_unix_socket(loop, mocker, shorttmpdir):
    """Older asyncio event loop implementations are known to halt server
    creation when a socket path from a previous server bind still exists.
    """
    skip_if_no_dict(loop)

    app = web.Application()

    sock_path = shorttmpdir.join('socket.sock')
    sock_path_string = str(sock_path)

    web.run_app(app, loop=loop,
                path=sock_path_string, print=stopper(loop))
    assert not loop.is_closed()

    if sock_path.check():
        # New app run using same socket path
        with loop_context() as loop:
            mocker.spy(loop, 'create_unix_server')

            app = web.Application()

            mocker.spy(app, 'startup')
            mocker.spy(os, 'remove')
            printer = mock.Mock(wraps=stopper(loop))

            web.run_app(app, loop=loop,
                        path=sock_path_string, print=printer)
            os.remove.assert_called_with(sock_path_string)
            loop.create_unix_server.assert_called_with(
                mock.ANY,
                sock_path_string,
                ssl=None,
                backlog=128
            )
            app.startup.assert_called_once_with()
            assert ("http://unix:{}:".format(sock_path)
                    in printer.call_args[0][0])


@skip_if_no_unix_socks
@skip_if_no_abstract_paths
def test_run_app_abstract_linux_socket(loop, mocker):
    sock_path = b"\x00" + uuid4().hex.encode('ascii')

    app = web.Application()
    web.run_app(
        app, path=sock_path.decode('ascii', 'ignore'), loop=loop,
        print=stopper(loop))

    # New app run using same socket path
    with loop_context() as loop:
        mocker.spy(loop, 'create_unix_server')

        app = web.Application()

        mocker.spy(app, 'startup')
        mocker.spy(os, 'remove')

        web.run_app(app, path=sock_path, print=stopper(loop), loop=loop)

        # Abstract paths don't exist on the file system, so no attempt should
        # be made to remove.
        assert mock.call([sock_path]) not in os.remove.mock_calls

        loop.create_unix_server.assert_called_with(
            mock.ANY,
            sock_path,
            ssl=None,
            backlog=128
        )
        app.startup.assert_called_once_with()


@skip_if_no_unix_socks
def test_run_app_existing_file_conflict(loop, mocker, shorttmpdir):
    app = web.Application()
    sock_path = shorttmpdir.join('socket.sock')
    sock_path.ensure()
    sock_path_str = str(sock_path)
    mocker.spy(os, 'remove')

    with pytest.raises(OSError):
        web.run_app(app, loop=loop,
                    path=sock_path_str, print=mock.Mock())

    # No attempt should be made to remove a non-socket file
    assert mock.call([sock_path_str]) not in os.remove.mock_calls


def test_run_app_preexisting_inet_socket(loop, mocker):
    skip_if_no_dict(loop)

    mocker.spy(loop, 'create_server')

    app = web.Application()
    mocker.spy(app, 'startup')

    sock = socket.socket()
    with contextlib.closing(sock):
        sock.bind(('0.0.0.0', 0))
        _, port = sock.getsockname()

        printer = mock.Mock(wraps=stopper(loop))
        web.run_app(app, loop=loop, sock=sock, print=printer)

        assert not loop.is_closed()
        loop.create_server.assert_called_with(
            mock.ANY, sock=sock, backlog=128, ssl=None
        )
        app.startup.assert_called_once_with()
        assert "http://0.0.0.0:{}".format(port) in printer.call_args[0][0]


@pytest.mark.skipif(not has_ipv6, reason="IPv6 is not available")
def test_run_app_preexisting_inet6_socket(loop, mocker):
    skip_if_no_dict(loop)

    mocker.spy(loop, 'create_server')

    app = web.Application()
    mocker.spy(app, 'startup')

    sock = socket.socket(socket.AF_INET6)
    with contextlib.closing(sock):
        sock.bind(('::', 0))
        port = sock.getsockname()[1]

        printer = mock.Mock(wraps=stopper(loop))
        web.run_app(app, loop=loop, sock=sock, print=printer)

        assert not loop.is_closed()
        loop.create_server.assert_called_with(
            mock.ANY, sock=sock, backlog=128, ssl=None
        )
        app.startup.assert_called_once_with()
        assert "http://:::{}".format(port) in printer.call_args[0][0]


@skip_if_no_unix_socks
def test_run_app_preexisting_unix_socket(loop, mocker):
    skip_if_no_dict(loop)

    mocker.spy(loop, 'create_server')

    app = web.Application()
    mocker.spy(app, 'startup')

    sock_path = '/tmp/test_preexisting_sock1'
    sock = socket.socket(socket.AF_UNIX)
    with contextlib.closing(sock):
        sock.bind(sock_path)
        os.unlink(sock_path)

        printer = mock.Mock(wraps=stopper(loop))
        web.run_app(app, loop=loop, sock=sock, print=printer)

        assert not loop.is_closed()
        loop.create_server.assert_called_with(
            mock.ANY, sock=sock, backlog=128, ssl=None
        )
        app.startup.assert_called_once_with()
        assert "http://unix:{}:".format(sock_path) in printer.call_args[0][0]


def test_run_app_multiple_preexisting_sockets(loop, mocker):
    skip_if_no_dict(loop)

    mocker.spy(loop, 'create_server')

    app = web.Application()
    mocker.spy(app, 'startup')

    sock1 = socket.socket()
    sock2 = socket.socket()
    with contextlib.closing(sock1), contextlib.closing(sock2):
        sock1.bind(('0.0.0.0', 0))
        _, port1 = sock1.getsockname()
        sock2.bind(('0.0.0.0', 0))
        _, port2 = sock2.getsockname()

        printer = mock.Mock(wraps=stopper(loop))
        web.run_app(app, loop=loop, sock=(sock1, sock2), print=printer)

        loop.create_server.assert_has_calls([
            mock.call(mock.ANY, sock=sock1, backlog=128, ssl=None),
            mock.call(mock.ANY, sock=sock2, backlog=128, ssl=None)
        ])
        app.startup.assert_called_once_with()
        assert "http://0.0.0.0:{}".format(port1) in printer.call_args[0][0]
        assert "http://0.0.0.0:{}".format(port2) in printer.call_args[0][0]


_script_test_signal = """
from aiohttp import web

app = web.Application()
web.run_app(app, host=())
"""


def test_sigint(loop, mocker):
    skip_if_on_windows()

    proc = subprocess.Popen([sys.executable, "-u", "-c", _script_test_signal],
                            stdout=subprocess.PIPE)
    for line in proc.stdout:
        if line.startswith(b"======== Running on"):
            break
    proc.send_signal(signal.SIGINT)
    assert proc.wait() == 0


def test_sigterm(loop, mocker):
    skip_if_on_windows()

    proc = subprocess.Popen([sys.executable, "-u", "-c", _script_test_signal],
                            stdout=subprocess.PIPE)
    for line in proc.stdout:
        if line.startswith(b"======== Running on"):
            break
    proc.terminate()
    assert proc.wait() == 0


def test_startup_cleanup_signals(loop, mocker):
    skip_if_no_dict(loop)

    mocker.spy(loop, 'create_server')

    app = web.Application()
    mocker.spy(app, 'startup')
    mocker.spy(app, 'cleanup')

    web.run_app(app, loop=loop, host=(), print=stopper(loop))

    app.startup.assert_called_once_with()
    app.cleanup.assert_called_once_with()


def test_startup_cleanup_signals_even_on_failure(loop, mocker):
    skip_if_no_dict(loop)

    setattr(loop, 'create_server', mock.Mock(side_effect=RuntimeError()))

    app = web.Application()
    mocker.spy(app, 'startup')
    mocker.spy(app, 'cleanup')

    with pytest.raises(RuntimeError):
        web.run_app(app, loop=loop, print=stopper(loop))

    app.startup.assert_called_once_with()
    app.cleanup.assert_called_once_with()
