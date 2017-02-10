import os
import socket
import ssl

from io import StringIO
from unittest import mock

import pytest

from aiohttp import web
from aiohttp.test_utils import loop_context


def test_run_app_http(loop, mocker):
    mocker.spy(loop, 'create_server')
    loop.call_later(0.05, loop.stop)

    app = web.Application(loop=loop)
    mocker.spy(app, 'startup')

    web.run_app(app, print=lambda *args: None)

    assert loop.is_closed()
    loop.create_server.assert_called_with(mock.ANY, '0.0.0.0', 8080,
                                          ssl=None, backlog=128)
    app.startup.assert_called_once_with()


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
    )
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
    mocker.patch('asyncio.gather')

    web.run_app(app, print=lambda *args: None, **run_app_kwargs)

    assert app.loop.create_unix_server.mock_calls == expected_unix_server_calls
    assert app.loop.create_server.mock_calls == expected_server_calls


def test_run_app_http_access_format(loop, mocker):
    mocker.spy(loop, 'create_server')
    loop.call_later(0.05, loop.stop)

    app = web.Application(loop=loop)
    mocker.spy(app, 'startup')

    web.run_app(app, print=lambda *args: None, access_log_format='%a')

    assert loop.is_closed()
    cs = loop.create_server
    cs.assert_called_with(mock.ANY, '0.0.0.0', 8080, ssl=None, backlog=128)
    assert cs.call_args[0][0]._kwargs['access_log_format'] == '%a'
    app.startup.assert_called_once_with()


def test_run_app_https(loop, mocker):
    mocker.spy(loop, 'create_server')
    loop.call_later(0.05, loop.stop)

    app = web.Application(loop=loop)
    mocker.spy(app, 'startup')

    ssl_context = ssl.create_default_context()

    web.run_app(app, ssl_context=ssl_context, print=lambda *args: None)

    assert loop.is_closed()
    loop.create_server.assert_called_with(mock.ANY, '0.0.0.0', 8443,
                                          ssl=ssl_context, backlog=128)
    app.startup.assert_called_once_with()


def test_run_app_nondefault_host_port(loop, unused_port, mocker):
    port = unused_port()
    host = 'localhost'

    mocker.spy(loop, 'create_server')
    loop.call_later(0.05, loop.stop)

    app = web.Application(loop=loop)
    mocker.spy(app, 'startup')

    web.run_app(app, host=host, port=port, print=lambda *args: None)

    assert loop.is_closed()
    loop.create_server.assert_called_with(mock.ANY, host, port,
                                          ssl=None, backlog=128)
    app.startup.assert_called_once_with()


def test_run_app_custom_backlog(loop, mocker):
    mocker.spy(loop, 'create_server')
    loop.call_later(0.05, loop.stop)

    app = web.Application(loop=loop)
    mocker.spy(app, 'startup')

    web.run_app(app, backlog=10, print=lambda *args: None)

    assert loop.is_closed()
    loop.create_server.assert_called_with(mock.ANY, '0.0.0.0', 8080,
                                          ssl=None, backlog=10)
    app.startup.assert_called_once_with()


@pytest.mark.skipif(not hasattr(socket, 'AF_UNIX'),
                    reason="UNIX sockets are not supported")
def test_run_app_http_unix_socket(loop, mocker, shorttmpdir):
    mocker.spy(loop, 'create_unix_server')
    loop.call_later(0.05, loop.stop)

    app = web.Application(loop=loop)
    mocker.spy(app, 'startup')

    sock_path = str(shorttmpdir.join('socket.sock'))
    printed = StringIO()
    web.run_app(app, path=sock_path, print=printed.write)

    assert loop.is_closed()
    loop.create_unix_server.assert_called_with(mock.ANY, sock_path,
                                               ssl=None, backlog=128)
    app.startup.assert_called_once_with()
    assert "http://unix:{}:".format(sock_path) in printed.getvalue()


@pytest.mark.skipif(not hasattr(socket, 'AF_UNIX'),
                    reason="UNIX sockets are not supported")
def test_run_app_https_unix_socket(loop, mocker, shorttmpdir):
    mocker.spy(loop, 'create_unix_server')
    loop.call_later(0.05, loop.stop)

    app = web.Application(loop=loop)
    mocker.spy(app, 'startup')

    sock_path = str(shorttmpdir.join('socket.sock'))
    printed = StringIO()
    ssl_context = ssl.create_default_context()
    web.run_app(app, path=sock_path, ssl_context=ssl_context,
                print=printed.write)

    assert loop.is_closed()
    loop.create_unix_server.assert_called_with(mock.ANY, sock_path,
                                               ssl=ssl_context, backlog=128)
    app.startup.assert_called_once_with()
    assert "https://unix:{}:".format(sock_path) in printed.getvalue()


@pytest.mark.skipif(not hasattr(socket, 'AF_UNIX'),
                    reason="UNIX sockets are not supported")
def test_run_app_stale_unix_socket(loop, mocker, shorttmpdir):
    """Older asyncio event loop implementations are known to halt server
    creation when a socket path from a previous server bind still exists.
    """
    loop.call_later(0.05, loop.stop)

    app = web.Application(loop=loop)

    sock_path = shorttmpdir.join('socket.sock')
    sock_path_string = str(sock_path)

    web.run_app(app, path=sock_path_string, print=lambda *args: None)
    assert loop.is_closed()

    if sock_path.check():
        # New app run using same socket path
        with loop_context() as loop:
            mocker.spy(loop, 'create_unix_server')
            loop.call_later(0.05, loop.stop)

            app = web.Application(loop=loop)

            mocker.spy(app, 'startup')
            mocker.spy(os, 'remove')
            printed = StringIO()

            web.run_app(app, path=sock_path_string, print=printed.write)
            os.remove.assert_called_with(sock_path_string)
            loop.create_unix_server.assert_called_with(
                mock.ANY,
                sock_path_string,
                ssl=None,
                backlog=128
            )
            app.startup.assert_called_once_with()
            assert "http://unix:{}:".format(sock_path) in \
                   printed.getvalue()
