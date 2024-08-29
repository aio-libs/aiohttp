import asyncio
import platform
import signal
from typing import Any
from unittest.mock import patch

import pytest

from aiohttp import web
from aiohttp.test_utils import get_unused_port_socket


@pytest.fixture
def app():
    return web.Application()


@pytest.fixture
def make_runner(loop: Any, app: Any):
    asyncio.set_event_loop(loop)
    runners = []

    def go(**kwargs):
        runner = web.AppRunner(app, **kwargs)
        runners.append(runner)
        return runner

    yield go
    for runner in runners:
        loop.run_until_complete(runner.cleanup())


async def test_site_for_nonfrozen_app(make_runner: Any) -> None:
    runner = make_runner()
    with pytest.raises(RuntimeError):
        web.TCPSite(runner)
    assert len(runner.sites) == 0


@pytest.mark.skipif(
    platform.system() == "Windows", reason="the test is not valid for Windows"
)
async def test_runner_setup_handle_signals(make_runner: Any) -> None:
    runner = make_runner(handle_signals=True)
    await runner.setup()
    assert signal.getsignal(signal.SIGTERM) is not signal.SIG_DFL
    await runner.cleanup()
    assert signal.getsignal(signal.SIGTERM) is signal.SIG_DFL


@pytest.mark.skipif(
    platform.system() == "Windows", reason="the test is not valid for Windows"
)
async def test_runner_setup_without_signal_handling(make_runner: Any) -> None:
    runner = make_runner(handle_signals=False)
    await runner.setup()
    assert signal.getsignal(signal.SIGTERM) is signal.SIG_DFL
    await runner.cleanup()
    assert signal.getsignal(signal.SIGTERM) is signal.SIG_DFL


async def test_site_double_added(make_runner: Any) -> None:
    _sock = get_unused_port_socket("127.0.0.1")
    runner = make_runner()
    await runner.setup()
    site = web.SockSite(runner, _sock)
    await site.start()
    with pytest.raises(RuntimeError):
        await site.start()

    assert len(runner.sites) == 1


async def test_site_stop_not_started(make_runner: Any) -> None:
    runner = make_runner()
    await runner.setup()
    site = web.TCPSite(runner)
    with pytest.raises(RuntimeError):
        await site.stop()

    assert len(runner.sites) == 0


async def test_custom_log_format(make_runner: Any) -> None:
    runner = make_runner(access_log_format="abc")
    await runner.setup()
    assert runner.server._kwargs["access_log_format"] == "abc"


async def test_unreg_site(make_runner: Any) -> None:
    runner = make_runner()
    await runner.setup()
    site = web.TCPSite(runner)
    with pytest.raises(RuntimeError):
        runner._unreg_site(site)


async def test_app_property(make_runner: Any, app: Any) -> None:
    runner = make_runner()
    assert runner.app is app


def test_non_app() -> None:
    with pytest.raises(TypeError):
        web.AppRunner(object())


async def test_addresses(make_runner, unix_sockname) -> None:
    _sock = get_unused_port_socket("127.0.0.1")
    runner = make_runner()
    await runner.setup()
    tcp = web.SockSite(runner, _sock)
    await tcp.start()
    unix = web.UnixSite(runner, unix_sockname)
    await unix.start()
    actual_addrs = runner.addresses
    expected_host, expected_post = _sock.getsockname()[:2]
    assert actual_addrs == [(expected_host, expected_post), unix_sockname]


@pytest.mark.skipif(
    platform.system() != "Windows", reason="Proactor Event loop present only in Windows"
)
async def test_named_pipe_runner_wrong_loop(
    app: Any, selector_loop: Any, pipe_name: Any
) -> None:
    runner = web.AppRunner(app)
    await runner.setup()
    with pytest.raises(RuntimeError):
        web.NamedPipeSite(runner, pipe_name)


@pytest.mark.skipif(
    platform.system() != "Windows", reason="Proactor Event loop present only in Windows"
)
async def test_named_pipe_runner_proactor_loop(
    proactor_loop: Any, app: Any, pipe_name: Any
) -> None:
    runner = web.AppRunner(app)
    await runner.setup()
    pipe = web.NamedPipeSite(runner, pipe_name)
    await pipe.start()
    await runner.cleanup()


async def test_tcpsite_default_host(make_runner: Any) -> None:
    runner = make_runner()
    await runner.setup()
    site = web.TCPSite(runner)
    assert site.name == "http://0.0.0.0:8080"

    calls = []

    async def mock_create_server(*args, **kwargs):
        calls.append((args, kwargs))

    with patch("asyncio.get_event_loop") as mock_get_loop:
        mock_get_loop.return_value.create_server = mock_create_server
        await site.start()

    assert len(calls) == 1
    server, host, port = calls[0][0]
    assert server is runner.server
    assert host is None
    assert port == 8080


async def test_tcpsite_empty_str_host(make_runner: Any) -> None:
    runner = make_runner()
    await runner.setup()
    site = web.TCPSite(runner, host="")
    assert site.name == "http://0.0.0.0:8080"


def test_run_after_asyncio_run() -> None:
    async def nothing():
        pass

    def spy():
        spy.called = True

    spy.called = False

    async def shutdown():
        spy()
        raise web.GracefulExit()

    # asyncio.run() creates a new loop and closes it.
    asyncio.run(nothing())

    app = web.Application()
    # create_task() will delay the function until app is run.
    app.on_startup.append(lambda a: asyncio.create_task(shutdown()))

    web.run_app(app)
    assert spy.called, "run_app() should work after asyncio.run()."


async def test_app_handler_args_failure() -> None:
    app = web.Application(handler_args={"unknown_parameter": 5})
    runner = web.AppRunner(app)
    await runner.setup()
    assert runner._server
    rh = runner._server()
    assert rh._timeout_ceil_threshold == 5
    await runner.cleanup()
    assert app


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        (2, 2),
        (None, 5),
        ("2", 2),
    ),
)
async def test_app_handler_args_ceil_threshold(value: Any, expected: Any) -> None:
    app = web.Application(handler_args={"timeout_ceil_threshold": value})
    runner = web.AppRunner(app)
    await runner.setup()
    assert runner._server
    rh = runner._server()
    assert rh._timeout_ceil_threshold == expected
    await runner.cleanup()
    assert app
