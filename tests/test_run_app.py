import asyncio
import contextlib
import logging
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
from aiohttp.helpers import PY_37
from aiohttp.test_utils import make_mocked_coro

# Test for features of OS' socket support
_has_unix_domain_socks = hasattr(socket, "AF_UNIX")
if _has_unix_domain_socks:
    _abstract_path_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        _abstract_path_sock.bind(b"\x00" + uuid4().hex.encode("ascii"))  # type: ignore
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
    _abstract_path_failed, reason="Linux-style abstract paths are not supported."
)
skip_if_no_unix_socks = pytest.mark.skipif(
    not _has_unix_domain_socks, reason="Unix domain sockets are not supported"
)
del _has_unix_domain_socks, _abstract_path_failed

HAS_IPV6 = socket.has_ipv6
if HAS_IPV6:
    # The socket.has_ipv6 flag may be True if Python was built with IPv6
    # support, but the target system still may not have it.
    # So let's ensure that we really have IPv6 support.
    try:
        socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    except OSError:
        HAS_IPV6 = False


# tokio event loop does not allow to override attributes
def skip_if_no_dict(loop):
    if not hasattr(loop, "__dict__"):
        pytest.skip("can not override loop attributes")


def skip_if_on_windows():
    if platform.system() == "Windows":
        pytest.skip("the test is not valid for Windows")


@pytest.fixture
def patched_loop(loop):
    skip_if_no_dict(loop)
    server = mock.Mock()
    server.wait_closed = make_mocked_coro(None)
    loop.create_server = make_mocked_coro(server)
    unix_server = mock.Mock()
    unix_server.wait_closed = make_mocked_coro(None)
    loop.create_unix_server = make_mocked_coro(unix_server)
    asyncio.set_event_loop(loop)
    return loop


def stopper(loop):
    def raiser():
        raise KeyboardInterrupt

    def f(*args):
        loop.call_soon(raiser)

    return f


def test_run_app_http(patched_loop) -> None:
    app = web.Application()
    startup_handler = make_mocked_coro()
    app.on_startup.append(startup_handler)
    cleanup_handler = make_mocked_coro()
    app.on_cleanup.append(cleanup_handler)

    web.run_app(app, print=stopper(patched_loop))

    patched_loop.create_server.assert_called_with(
        mock.ANY, None, 8080, ssl=None, backlog=128, reuse_address=None, reuse_port=None
    )
    startup_handler.assert_called_once_with(app)
    cleanup_handler.assert_called_once_with(app)


def test_run_app_close_loop(patched_loop) -> None:
    app = web.Application()
    web.run_app(app, print=stopper(patched_loop))

    patched_loop.create_server.assert_called_with(
        mock.ANY, None, 8080, ssl=None, backlog=128, reuse_address=None, reuse_port=None
    )
    assert patched_loop.is_closed()


mock_unix_server_single = [
    mock.call(mock.ANY, "/tmp/testsock1.sock", ssl=None, backlog=128),
]
mock_unix_server_multi = [
    mock.call(mock.ANY, "/tmp/testsock1.sock", ssl=None, backlog=128),
    mock.call(mock.ANY, "/tmp/testsock2.sock", ssl=None, backlog=128),
]
mock_server_single = [
    mock.call(
        mock.ANY,
        "127.0.0.1",
        8080,
        ssl=None,
        backlog=128,
        reuse_address=None,
        reuse_port=None,
    ),
]
mock_server_multi = [
    mock.call(
        mock.ANY,
        "127.0.0.1",
        8080,
        ssl=None,
        backlog=128,
        reuse_address=None,
        reuse_port=None,
    ),
    mock.call(
        mock.ANY,
        "192.168.1.1",
        8080,
        ssl=None,
        backlog=128,
        reuse_address=None,
        reuse_port=None,
    ),
]
mock_server_default_8989 = [
    mock.call(
        mock.ANY, None, 8989, ssl=None, backlog=128, reuse_address=None, reuse_port=None
    )
]
mock_socket = mock.Mock(getsockname=lambda: ("mock-socket", 123))
mixed_bindings_tests = (
    (  # type: ignore
        "Nothing Specified",
        {},
        [
            mock.call(
                mock.ANY,
                None,
                8080,
                ssl=None,
                backlog=128,
                reuse_address=None,
                reuse_port=None,
            )
        ],
        [],
    ),
    ("Port Only", {"port": 8989}, mock_server_default_8989, []),
    ("Multiple Hosts", {"host": ("127.0.0.1", "192.168.1.1")}, mock_server_multi, []),
    (
        "Multiple Paths",
        {"path": ("/tmp/testsock1.sock", "/tmp/testsock2.sock")},
        [],
        mock_unix_server_multi,
    ),
    (
        "Multiple Paths, Port",
        {"path": ("/tmp/testsock1.sock", "/tmp/testsock2.sock"), "port": 8989},
        mock_server_default_8989,
        mock_unix_server_multi,
    ),
    (
        "Multiple Paths, Single Host",
        {"path": ("/tmp/testsock1.sock", "/tmp/testsock2.sock"), "host": "127.0.0.1"},
        mock_server_single,
        mock_unix_server_multi,
    ),
    (
        "Single Path, Single Host",
        {"path": "/tmp/testsock1.sock", "host": "127.0.0.1"},
        mock_server_single,
        mock_unix_server_single,
    ),
    (
        "Single Path, Multiple Hosts",
        {"path": "/tmp/testsock1.sock", "host": ("127.0.0.1", "192.168.1.1")},
        mock_server_multi,
        mock_unix_server_single,
    ),
    (
        "Single Path, Port",
        {"path": "/tmp/testsock1.sock", "port": 8989},
        mock_server_default_8989,
        mock_unix_server_single,
    ),
    (
        "Multiple Paths, Multiple Hosts, Port",
        {
            "path": ("/tmp/testsock1.sock", "/tmp/testsock2.sock"),
            "host": ("127.0.0.1", "192.168.1.1"),
            "port": 8000,
        },
        [
            mock.call(
                mock.ANY,
                "127.0.0.1",
                8000,
                ssl=None,
                backlog=128,
                reuse_address=None,
                reuse_port=None,
            ),
            mock.call(
                mock.ANY,
                "192.168.1.1",
                8000,
                ssl=None,
                backlog=128,
                reuse_address=None,
                reuse_port=None,
            ),
        ],
        mock_unix_server_multi,
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
        [
            mock.call(
                mock.ANY,
                None,
                8765,
                ssl=None,
                backlog=128,
                reuse_address=None,
                reuse_port=None,
            ),
            mock.call(mock.ANY, sock=mock_socket, ssl=None, backlog=128),
        ],
        [],
    ),
    (
        "Socket, Host, No port",
        {"sock": [mock_socket], "host": "localhost"},
        [
            mock.call(
                mock.ANY,
                "localhost",
                8080,
                ssl=None,
                backlog=128,
                reuse_address=None,
                reuse_port=None,
            ),
            mock.call(mock.ANY, sock=mock_socket, ssl=None, backlog=128),
        ],
        [],
    ),
    (
        "reuse_port",
        {"reuse_port": True},
        [
            mock.call(
                mock.ANY,
                None,
                8080,
                ssl=None,
                backlog=128,
                reuse_address=None,
                reuse_port=True,
            )
        ],
        [],
    ),
    (
        "reuse_address",
        {"reuse_address": False},
        [
            mock.call(
                mock.ANY,
                None,
                8080,
                ssl=None,
                backlog=128,
                reuse_address=False,
                reuse_port=None,
            )
        ],
        [],
    ),
    (
        "reuse_port, reuse_address",
        {"reuse_address": True, "reuse_port": True},
        [
            mock.call(
                mock.ANY,
                None,
                8080,
                ssl=None,
                backlog=128,
                reuse_address=True,
                reuse_port=True,
            )
        ],
        [],
    ),
    (
        "Port, reuse_port",
        {"port": 8989, "reuse_port": True},
        [
            mock.call(
                mock.ANY,
                None,
                8989,
                ssl=None,
                backlog=128,
                reuse_address=None,
                reuse_port=True,
            )
        ],
        [],
    ),
    (
        "Multiple Hosts, reuse_port",
        {"host": ("127.0.0.1", "192.168.1.1"), "reuse_port": True},
        [
            mock.call(
                mock.ANY,
                "127.0.0.1",
                8080,
                ssl=None,
                backlog=128,
                reuse_address=None,
                reuse_port=True,
            ),
            mock.call(
                mock.ANY,
                "192.168.1.1",
                8080,
                ssl=None,
                backlog=128,
                reuse_address=None,
                reuse_port=True,
            ),
        ],
        [],
    ),
    (
        "Multiple Paths, Port, reuse_address",
        {
            "path": ("/tmp/testsock1.sock", "/tmp/testsock2.sock"),
            "port": 8989,
            "reuse_address": False,
        },
        [
            mock.call(
                mock.ANY,
                None,
                8989,
                ssl=None,
                backlog=128,
                reuse_address=False,
                reuse_port=None,
            )
        ],
        mock_unix_server_multi,
    ),
    (
        "Multiple Paths, Single Host, reuse_address, reuse_port",
        {
            "path": ("/tmp/testsock1.sock", "/tmp/testsock2.sock"),
            "host": "127.0.0.1",
            "reuse_address": True,
            "reuse_port": True,
        },
        [
            mock.call(
                mock.ANY,
                "127.0.0.1",
                8080,
                ssl=None,
                backlog=128,
                reuse_address=True,
                reuse_port=True,
            ),
        ],
        mock_unix_server_multi,
    ),
)
mixed_bindings_test_ids = [test[0] for test in mixed_bindings_tests]
mixed_bindings_test_params = [test[1:] for test in mixed_bindings_tests]


@pytest.mark.parametrize(
    "run_app_kwargs, expected_server_calls, expected_unix_server_calls",
    mixed_bindings_test_params,
    ids=mixed_bindings_test_ids,
)
def test_run_app_mixed_bindings(
    run_app_kwargs, expected_server_calls, expected_unix_server_calls, patched_loop
):
    app = web.Application()
    web.run_app(app, print=stopper(patched_loop), **run_app_kwargs)

    assert patched_loop.create_unix_server.mock_calls == expected_unix_server_calls
    assert patched_loop.create_server.mock_calls == expected_server_calls


def test_run_app_https(patched_loop) -> None:
    app = web.Application()

    ssl_context = ssl.create_default_context()
    web.run_app(app, ssl_context=ssl_context, print=stopper(patched_loop))

    patched_loop.create_server.assert_called_with(
        mock.ANY,
        None,
        8443,
        ssl=ssl_context,
        backlog=128,
        reuse_address=None,
        reuse_port=None,
    )


def test_run_app_nondefault_host_port(patched_loop, aiohttp_unused_port) -> None:
    port = aiohttp_unused_port()
    host = "127.0.0.1"

    app = web.Application()
    web.run_app(app, host=host, port=port, print=stopper(patched_loop))

    patched_loop.create_server.assert_called_with(
        mock.ANY, host, port, ssl=None, backlog=128, reuse_address=None, reuse_port=None
    )


def test_run_app_multiple_hosts(patched_loop) -> None:
    hosts = ("127.0.0.1", "127.0.0.2")

    app = web.Application()
    web.run_app(app, host=hosts, print=stopper(patched_loop))

    calls = map(
        lambda h: mock.call(
            mock.ANY,
            h,
            8080,
            ssl=None,
            backlog=128,
            reuse_address=None,
            reuse_port=None,
        ),
        hosts,
    )
    patched_loop.create_server.assert_has_calls(calls)


def test_run_app_custom_backlog(patched_loop) -> None:
    app = web.Application()
    web.run_app(app, backlog=10, print=stopper(patched_loop))

    patched_loop.create_server.assert_called_with(
        mock.ANY, None, 8080, ssl=None, backlog=10, reuse_address=None, reuse_port=None
    )


def test_run_app_custom_backlog_unix(patched_loop) -> None:
    app = web.Application()
    web.run_app(app, path="/tmp/tmpsock.sock", backlog=10, print=stopper(patched_loop))

    patched_loop.create_unix_server.assert_called_with(
        mock.ANY, "/tmp/tmpsock.sock", ssl=None, backlog=10
    )


@skip_if_no_unix_socks
def test_run_app_http_unix_socket(patched_loop, shorttmpdir) -> None:
    app = web.Application()

    sock_path = str(shorttmpdir / "socket.sock")
    printer = mock.Mock(wraps=stopper(patched_loop))
    web.run_app(app, path=sock_path, print=printer)

    patched_loop.create_unix_server.assert_called_with(
        mock.ANY, sock_path, ssl=None, backlog=128
    )
    assert f"http://unix:{sock_path}:" in printer.call_args[0][0]


@skip_if_no_unix_socks
def test_run_app_https_unix_socket(patched_loop, shorttmpdir) -> None:
    app = web.Application()

    sock_path = str(shorttmpdir / "socket.sock")
    ssl_context = ssl.create_default_context()
    printer = mock.Mock(wraps=stopper(patched_loop))
    web.run_app(app, path=sock_path, ssl_context=ssl_context, print=printer)

    patched_loop.create_unix_server.assert_called_with(
        mock.ANY, sock_path, ssl=ssl_context, backlog=128
    )
    assert f"https://unix:{sock_path}:" in printer.call_args[0][0]


@skip_if_no_unix_socks
@skip_if_no_abstract_paths
def test_run_app_abstract_linux_socket(patched_loop) -> None:
    sock_path = b"\x00" + uuid4().hex.encode("ascii")
    app = web.Application()
    web.run_app(
        app, path=sock_path.decode("ascii", "ignore"), print=stopper(patched_loop)
    )

    patched_loop.create_unix_server.assert_called_with(
        mock.ANY, sock_path.decode("ascii"), ssl=None, backlog=128
    )


def test_run_app_preexisting_inet_socket(patched_loop, mocker) -> None:
    app = web.Application()

    sock = socket.socket()
    with contextlib.closing(sock):
        sock.bind(("0.0.0.0", 0))
        _, port = sock.getsockname()

        printer = mock.Mock(wraps=stopper(patched_loop))
        web.run_app(app, sock=sock, print=printer)

        patched_loop.create_server.assert_called_with(
            mock.ANY, sock=sock, backlog=128, ssl=None
        )
        assert f"http://0.0.0.0:{port}" in printer.call_args[0][0]


@pytest.mark.skipif(not HAS_IPV6, reason="IPv6 is not available")
def test_run_app_preexisting_inet6_socket(patched_loop) -> None:
    app = web.Application()

    sock = socket.socket(socket.AF_INET6)
    with contextlib.closing(sock):
        sock.bind(("::", 0))
        port = sock.getsockname()[1]

        printer = mock.Mock(wraps=stopper(patched_loop))
        web.run_app(app, sock=sock, print=printer)

        patched_loop.create_server.assert_called_with(
            mock.ANY, sock=sock, backlog=128, ssl=None
        )
        assert f"http://[::]:{port}" in printer.call_args[0][0]


@skip_if_no_unix_socks
def test_run_app_preexisting_unix_socket(patched_loop, mocker) -> None:
    app = web.Application()

    sock_path = "/tmp/test_preexisting_sock1"
    sock = socket.socket(socket.AF_UNIX)
    with contextlib.closing(sock):
        sock.bind(sock_path)
        os.unlink(sock_path)

        printer = mock.Mock(wraps=stopper(patched_loop))
        web.run_app(app, sock=sock, print=printer)

        patched_loop.create_server.assert_called_with(
            mock.ANY, sock=sock, backlog=128, ssl=None
        )
        assert f"http://unix:{sock_path}:" in printer.call_args[0][0]


def test_run_app_multiple_preexisting_sockets(patched_loop) -> None:
    app = web.Application()

    sock1 = socket.socket()
    sock2 = socket.socket()
    with contextlib.closing(sock1), contextlib.closing(sock2):
        sock1.bind(("0.0.0.0", 0))
        _, port1 = sock1.getsockname()
        sock2.bind(("0.0.0.0", 0))
        _, port2 = sock2.getsockname()

        printer = mock.Mock(wraps=stopper(patched_loop))
        web.run_app(app, sock=(sock1, sock2), print=printer)

        patched_loop.create_server.assert_has_calls(
            [
                mock.call(mock.ANY, sock=sock1, backlog=128, ssl=None),
                mock.call(mock.ANY, sock=sock2, backlog=128, ssl=None),
            ]
        )
        assert f"http://0.0.0.0:{port1}" in printer.call_args[0][0]
        assert f"http://0.0.0.0:{port2}" in printer.call_args[0][0]


_script_test_signal = """
from aiohttp import web

app = web.Application()
web.run_app(app, host=())
"""


def test_sigint() -> None:
    skip_if_on_windows()

    proc = subprocess.Popen(
        [sys.executable, "-u", "-c", _script_test_signal], stdout=subprocess.PIPE
    )
    for line in proc.stdout:
        if line.startswith(b"======== Running on"):
            break
    proc.send_signal(signal.SIGINT)
    assert proc.wait() == 0


def test_sigterm() -> None:
    skip_if_on_windows()

    proc = subprocess.Popen(
        [sys.executable, "-u", "-c", _script_test_signal], stdout=subprocess.PIPE
    )
    for line in proc.stdout:
        if line.startswith(b"======== Running on"):
            break
    proc.terminate()
    assert proc.wait() == 0


def test_startup_cleanup_signals_even_on_failure(patched_loop) -> None:
    patched_loop.create_server = mock.Mock(side_effect=RuntimeError())

    app = web.Application()
    startup_handler = make_mocked_coro()
    app.on_startup.append(startup_handler)
    cleanup_handler = make_mocked_coro()
    app.on_cleanup.append(cleanup_handler)

    with pytest.raises(RuntimeError):
        web.run_app(app, print=stopper(patched_loop))

    startup_handler.assert_called_once_with(app)
    cleanup_handler.assert_called_once_with(app)


def test_run_app_coro(patched_loop) -> None:
    startup_handler = cleanup_handler = None

    async def make_app():
        nonlocal startup_handler, cleanup_handler
        app = web.Application()
        startup_handler = make_mocked_coro()
        app.on_startup.append(startup_handler)
        cleanup_handler = make_mocked_coro()
        app.on_cleanup.append(cleanup_handler)
        return app

    web.run_app(make_app(), print=stopper(patched_loop))

    patched_loop.create_server.assert_called_with(
        mock.ANY, None, 8080, ssl=None, backlog=128, reuse_address=None, reuse_port=None
    )
    startup_handler.assert_called_once_with(mock.ANY)
    cleanup_handler.assert_called_once_with(mock.ANY)


def test_run_app_default_logger(monkeypatch, patched_loop):
    patched_loop.set_debug(True)
    logger = web.access_logger
    attrs = {
        "hasHandlers.return_value": False,
        "level": logging.NOTSET,
        "name": "aiohttp.access",
    }
    mock_logger = mock.create_autospec(logger, name="mock_access_logger")
    mock_logger.configure_mock(**attrs)

    app = web.Application()
    web.run_app(app, print=stopper(patched_loop), access_log=mock_logger)
    mock_logger.setLevel.assert_any_call(logging.DEBUG)
    mock_logger.hasHandlers.assert_called_with()
    assert isinstance(mock_logger.addHandler.call_args[0][0], logging.StreamHandler)


def test_run_app_default_logger_setup_requires_debug(patched_loop):
    patched_loop.set_debug(False)
    logger = web.access_logger
    attrs = {
        "hasHandlers.return_value": False,
        "level": logging.NOTSET,
        "name": "aiohttp.access",
    }
    mock_logger = mock.create_autospec(logger, name="mock_access_logger")
    mock_logger.configure_mock(**attrs)

    app = web.Application()
    web.run_app(app, print=stopper(patched_loop), access_log=mock_logger)
    mock_logger.setLevel.assert_not_called()
    mock_logger.hasHandlers.assert_not_called()
    mock_logger.addHandler.assert_not_called()


def test_run_app_default_logger_setup_requires_default_logger(patched_loop):
    patched_loop.set_debug(True)
    logger = web.access_logger
    attrs = {
        "hasHandlers.return_value": False,
        "level": logging.NOTSET,
        "name": None,
    }
    mock_logger = mock.create_autospec(logger, name="mock_access_logger")
    mock_logger.configure_mock(**attrs)

    app = web.Application()
    web.run_app(app, print=stopper(patched_loop), access_log=mock_logger)
    mock_logger.setLevel.assert_not_called()
    mock_logger.hasHandlers.assert_not_called()
    mock_logger.addHandler.assert_not_called()


def test_run_app_default_logger_setup_only_if_unconfigured(patched_loop):
    patched_loop.set_debug(True)
    logger = web.access_logger
    attrs = {
        "hasHandlers.return_value": True,
        "level": None,
        "name": "aiohttp.access",
    }
    mock_logger = mock.create_autospec(logger, name="mock_access_logger")
    mock_logger.configure_mock(**attrs)

    app = web.Application()
    web.run_app(app, print=stopper(patched_loop), access_log=mock_logger)
    mock_logger.setLevel.assert_not_called()
    mock_logger.hasHandlers.assert_called_with()
    mock_logger.addHandler.assert_not_called()


def test_run_app_cancels_all_pending_tasks(patched_loop):
    app = web.Application()
    task = None

    async def on_startup(app):
        nonlocal task
        loop = asyncio.get_event_loop()
        task = loop.create_task(asyncio.sleep(1000))

    app.on_startup.append(on_startup)

    web.run_app(app, print=stopper(patched_loop))
    assert task.cancelled()


def test_run_app_cancels_done_tasks(patched_loop):
    app = web.Application()
    task = None

    async def coro():
        return 123

    async def on_startup(app):
        nonlocal task
        loop = asyncio.get_event_loop()
        task = loop.create_task(coro())

    app.on_startup.append(on_startup)

    web.run_app(app, print=stopper(patched_loop))
    assert task.done()


def test_run_app_cancels_failed_tasks(patched_loop):
    app = web.Application()
    task = None

    exc = RuntimeError("FAIL")

    async def fail():
        try:
            await asyncio.sleep(1000)
        except asyncio.CancelledError:
            raise exc

    async def on_startup(app):
        nonlocal task
        loop = asyncio.get_event_loop()
        task = loop.create_task(fail())
        await asyncio.sleep(0.01)

    app.on_startup.append(on_startup)

    exc_handler = mock.Mock()
    patched_loop.set_exception_handler(exc_handler)
    web.run_app(app, print=stopper(patched_loop))
    assert task.done()

    msg = {
        "message": "unhandled exception during asyncio.run() shutdown",
        "exception": exc,
        "task": task,
    }
    exc_handler.assert_called_with(patched_loop, msg)


@pytest.mark.skipif(not PY_37, reason="contextvars support is required")
def test_run_app_context_vars(patched_loop):
    from contextvars import ContextVar

    count = 0
    VAR = ContextVar("VAR", default="default")

    async def on_startup(app):
        nonlocal count
        assert "init" == VAR.get()
        VAR.set("on_startup")
        count += 1

    async def on_cleanup(app):
        nonlocal count
        assert "on_startup" == VAR.get()
        count += 1

    async def init():
        nonlocal count
        assert "default" == VAR.get()
        VAR.set("init")
        app = web.Application()

        app.on_startup.append(on_startup)
        app.on_cleanup.append(on_cleanup)
        count += 1
        return app

    web.run_app(init(), print=stopper(patched_loop))
    assert count == 3
