import asyncio
import platform
import signal
from typing import Any, Iterator, NoReturn, Protocol, Union
from unittest import mock

import pytest

from aiohttp import web
from aiohttp.abc import AbstractAccessLogger
from aiohttp.test_utils import get_unused_port_socket
from aiohttp.web_log import AccessLogger


class _RunnerMaker(Protocol):
    def __call__(self, handle_signals: bool = ..., **kwargs: Any) -> web.AppRunner: ...


@pytest.fixture
def app() -> web.Application:
    return web.Application()


@pytest.fixture
def make_runner(
    loop: asyncio.AbstractEventLoop, app: web.Application
) -> Iterator[_RunnerMaker]:
    asyncio.set_event_loop(loop)
    runners = []

    def go(handle_signals: bool = False, **kwargs: Any) -> web.AppRunner:
        runner = web.AppRunner(app, handle_signals=handle_signals, **kwargs)
        runners.append(runner)
        return runner

    yield go
    for runner in runners:
        loop.run_until_complete(runner.cleanup())


async def test_site_for_nonfrozen_app(make_runner: _RunnerMaker) -> None:
    runner = make_runner()
    with pytest.raises(RuntimeError):
        web.TCPSite(runner)
    assert len(runner.sites) == 0


@pytest.mark.skipif(
    platform.system() == "Windows", reason="the test is not valid for Windows"
)
async def test_runner_setup_handle_signals(make_runner: _RunnerMaker) -> None:
    runner = make_runner(handle_signals=True)
    await runner.setup()
    assert signal.getsignal(signal.SIGTERM) is not signal.SIG_DFL
    await runner.cleanup()
    assert signal.getsignal(signal.SIGTERM) is signal.SIG_DFL


@pytest.mark.skipif(
    platform.system() == "Windows", reason="the test is not valid for Windows"
)
async def test_runner_setup_without_signal_handling(make_runner: _RunnerMaker) -> None:
    runner = make_runner(handle_signals=False)
    await runner.setup()
    assert signal.getsignal(signal.SIGTERM) is signal.SIG_DFL
    await runner.cleanup()
    assert signal.getsignal(signal.SIGTERM) is signal.SIG_DFL


async def test_site_double_added(make_runner: _RunnerMaker) -> None:
    _sock = get_unused_port_socket("127.0.0.1")
    runner = make_runner()
    await runner.setup()
    site = web.SockSite(runner, _sock)
    await site.start()
    with pytest.raises(RuntimeError):
        await site.start()

    assert len(runner.sites) == 1


async def test_site_stop_not_started(make_runner: _RunnerMaker) -> None:
    runner = make_runner()
    await runner.setup()
    site = web.TCPSite(runner)
    with pytest.raises(RuntimeError):
        await site.stop()

    assert len(runner.sites) == 0


async def test_custom_log_format(make_runner: _RunnerMaker) -> None:
    runner = make_runner(access_log_format="abc")
    await runner.setup()
    assert runner.server is not None
    assert runner.server._kwargs["access_log_format"] == "abc"


async def test_unreg_site(make_runner: _RunnerMaker) -> None:
    runner = make_runner()
    await runner.setup()
    site = web.TCPSite(runner)
    with pytest.raises(RuntimeError):
        runner._unreg_site(site)


async def test_app_property(make_runner: _RunnerMaker, app: web.Application) -> None:
    runner = make_runner()
    assert runner.app is app


def test_non_app() -> None:
    with pytest.raises(TypeError):
        web.AppRunner(object())  # type: ignore[arg-type]


def test_app_handler_args() -> None:
    app = web.Application(handler_args={"test": True})
    runner = web.AppRunner(app)
    assert runner._kwargs == {"access_log_class": AccessLogger, "test": True}


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
async def test_app_handler_args_ceil_threshold(
    value: Union[int, str, None], expected: int
) -> None:
    app = web.Application(handler_args={"timeout_ceil_threshold": value})
    runner = web.AppRunner(app)
    await runner.setup()
    assert runner._server
    rh = runner._server()
    assert rh._timeout_ceil_threshold == expected
    await runner.cleanup()
    assert app


async def test_app_make_handler_access_log_class_bad_type1() -> None:
    class Logger:
        pass

    app = web.Application()

    with pytest.raises(TypeError):
        web.AppRunner(app, access_log_class=Logger)  # type: ignore[arg-type]


async def test_app_make_handler_access_log_class_bad_type2() -> None:
    class Logger:
        pass

    app = web.Application(handler_args={"access_log_class": Logger})

    with pytest.raises(TypeError):
        web.AppRunner(app)


async def test_app_make_handler_access_log_class1() -> None:
    class Logger(AbstractAccessLogger):
        def log(
            self, request: web.BaseRequest, response: web.StreamResponse, time: float
        ) -> None:
            """Pass log method."""

    app = web.Application()
    runner = web.AppRunner(app, access_log_class=Logger)
    assert runner._kwargs["access_log_class"] is Logger


async def test_app_make_handler_access_log_class2() -> None:
    class Logger(AbstractAccessLogger):
        def log(
            self, request: web.BaseRequest, response: web.StreamResponse, time: float
        ) -> None:
            """Pass log method."""

    app = web.Application(handler_args={"access_log_class": Logger})
    runner = web.AppRunner(app)
    assert runner._kwargs["access_log_class"] is Logger


async def test_addresses(make_runner: _RunnerMaker, unix_sockname: str) -> None:
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
    app: web.Application, selector_loop: asyncio.AbstractEventLoop, pipe_name: str
) -> None:
    runner = web.AppRunner(app)
    await runner.setup()
    with pytest.raises(RuntimeError):
        web.NamedPipeSite(runner, pipe_name)


@pytest.mark.skipif(
    platform.system() != "Windows", reason="Proactor Event loop present only in Windows"
)
async def test_named_pipe_runner_proactor_loop(
    proactor_loop: asyncio.AbstractEventLoop, app: web.Application, pipe_name: str
) -> None:
    runner = web.AppRunner(app)
    await runner.setup()
    pipe = web.NamedPipeSite(runner, pipe_name)
    await pipe.start()
    await runner.cleanup()


async def test_tcpsite_default_host(make_runner: _RunnerMaker) -> None:
    runner = make_runner()
    await runner.setup()
    site = web.TCPSite(runner)
    assert site.name == "http://0.0.0.0:8080"

    m = mock.create_autospec(asyncio.AbstractEventLoop, spec_set=True, instance=True)
    m.create_server.return_value = mock.create_autospec(asyncio.Server, spec_set=True)
    with mock.patch(
        "asyncio.get_event_loop", autospec=True, spec_set=True, return_value=m
    ):
        await site.start()

    m.create_server.assert_called_once()
    args, kwargs = m.create_server.call_args
    assert args == (runner.server, None, 8080)


async def test_tcpsite_empty_str_host(make_runner: _RunnerMaker) -> None:
    runner = make_runner()
    await runner.setup()
    site = web.TCPSite(runner, host="")
    assert site.name == "http://0.0.0.0:8080"


def test_run_after_asyncio_run() -> None:
    called = False

    async def nothing() -> None:
        pass

    def spy() -> None:
        nonlocal called
        called = True

    async def shutdown() -> NoReturn:
        spy()
        raise web.GracefulExit()

    # asyncio.run() creates a new loop and closes it.
    asyncio.run(nothing())

    app = web.Application()
    # create_task() will delay the function until app is run.
    app.on_startup.append(lambda a: asyncio.create_task(shutdown()))

    web.run_app(app)
    assert called, "run_app() should work after asyncio.run()."
