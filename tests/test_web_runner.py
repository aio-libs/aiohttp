import asyncio
import platform
import signal
from typing import Optional

import pytest

from aiohttp import web
from aiohttp.abc import AbstractAccessLogger
from aiohttp.test_utils import get_unused_port_socket


@pytest.fixture
def app():
    return web.Application()


@pytest.fixture
def make_runner(loop, app):
    asyncio.set_event_loop(loop)
    runners = []

    def go(app_param: Optional[web.AppRunner] = None, **kwargs):
        runner = web.AppRunner(app_param or app, **kwargs)
        runners.append(runner)
        return runner
    yield go
    for runner in runners:
        loop.run_until_complete(runner.cleanup())


async def test_site_for_nonfrozen_app(make_runner) -> None:
    runner = make_runner()
    with pytest.raises(RuntimeError):
        web.TCPSite(runner)
    assert len(runner.sites) == 0


@pytest.mark.skipif(platform.system() == "Windows",
                    reason="the test is not valid for Windows")
async def test_runner_setup_handle_signals(make_runner) -> None:
    runner = make_runner(handle_signals=True)
    await runner.setup()
    assert signal.getsignal(signal.SIGTERM) is not signal.SIG_DFL
    await runner.cleanup()
    assert signal.getsignal(signal.SIGTERM) is signal.SIG_DFL


@pytest.mark.skipif(platform.system() == "Windows",
                    reason="the test is not valid for Windows")
async def test_runner_setup_without_signal_handling(make_runner) -> None:
    runner = make_runner(handle_signals=False)
    await runner.setup()
    assert signal.getsignal(signal.SIGTERM) is signal.SIG_DFL
    await runner.cleanup()
    assert signal.getsignal(signal.SIGTERM) is signal.SIG_DFL


async def test_site_double_added(make_runner) -> None:
    _sock = get_unused_port_socket('127.0.0.1')
    runner = make_runner()
    await runner.setup()
    site = web.SockSite(runner, _sock)
    await site.start()
    with pytest.raises(RuntimeError):
        await site.start()

    assert len(runner.sites) == 1


async def test_site_stop_not_started(make_runner) -> None:
    runner = make_runner()
    await runner.setup()
    site = web.TCPSite(runner)
    with pytest.raises(RuntimeError):
        await site.stop()

    assert len(runner.sites) == 0


async def test_custom_log_format(make_runner) -> None:
    runner = make_runner(access_log_format='abc')
    await runner.setup()
    assert runner.server._kwargs['access_log_format'] == 'abc'


async def test_unreg_site(make_runner) -> None:
    runner = make_runner()
    await runner.setup()
    site = web.TCPSite(runner)
    with pytest.raises(RuntimeError):
        runner._unreg_site(site)


async def test_app_property(make_runner, app) -> None:
    runner = make_runner()
    assert runner.app is app


def test_non_app() -> None:
    with pytest.raises(TypeError):
        web.AppRunner(object())


def test_app_handler_args() -> None:
    app = web.Application(handler_args={'test': True})
    runner = web.AppRunner(app)
    assert runner._kwargs == {'access_log_class': web.AccessLogger,
                              'test': True}


async def test_app_make_handler_access_log_class_bad_type1() -> None:
    class Logger:
        pass

    app = web.Application()

    with pytest.raises(TypeError):
        web.AppRunner(app, access_log_class=Logger)


async def test_app_make_handler_access_log_class_bad_type2() -> None:
    class Logger:
        pass

    app = web.Application(handler_args={'access_log_class': Logger})

    with pytest.raises(TypeError):
        web.AppRunner(app)


async def test_app_make_handler_access_log_class1() -> None:

    class Logger(AbstractAccessLogger):

        def log(self, request, response, time):
            pass

    app = web.Application()
    runner = web.AppRunner(app, access_log_class=Logger)
    assert runner._kwargs['access_log_class'] is Logger


async def test_app_make_handler_access_log_class2() -> None:

    class Logger(AbstractAccessLogger):

        def log(self, request, response, time):
            pass

    app = web.Application(handler_args={'access_log_class': Logger})
    runner = web.AppRunner(app)
    assert runner._kwargs['access_log_class'] is Logger


async def test_addresses(make_runner, unix_sockname) -> None:
    _sock = get_unused_port_socket('127.0.0.1')
    runner = make_runner()
    await runner.setup()
    tcp = web.SockSite(runner, _sock)
    await tcp.start()
    unix = web.UnixSite(runner, unix_sockname)
    await unix.start()
    actual_addrs = runner.addresses
    expected_host, expected_post = _sock.getsockname()[:2]
    assert actual_addrs == [(expected_host, expected_post), unix_sockname]


@pytest.mark.skipif(platform.system() != "Windows",
                    reason="Proactor Event loop present only in Windows")
async def test_named_pipe_runner_wrong_loop(app, pipe_name) -> None:
    runner = web.AppRunner(app)
    await runner.setup()
    with pytest.raises(RuntimeError):
        web.NamedPipeSite(runner, pipe_name)


@pytest.mark.skipif(platform.system() != "Windows",
                    reason="Proactor Event loop present only in Windows")
async def test_named_pipe_runner_proactor_loop(
    proactor_loop,
    app,
    pipe_name
) -> None:
    runner = web.AppRunner(app)
    await runner.setup()
    pipe = web.NamedPipeSite(runner, pipe_name)
    await pipe.start()
    await runner.cleanup()


async def test_app_runner_serve_forever_uninitialized(
        make_runner, loop) -> None:
    runner = make_runner()
    with pytest.raises(RuntimeError):
        await runner.serve_forever()


async def test_app_runner_serve_forever_concurrent_call(
        make_runner, loop) -> None:
    runner = make_runner()
    task = loop.create_task(runner.serve_forever())
    await asyncio.sleep(0.01)
    with pytest.raises(RuntimeError):
        await runner.serve_forever()
    task.cancel()


async def test_app_runner_serve_forever_multiple_times(
        make_runner, loop) -> None:
    runner = make_runner()
    for i in range(3):
        await runner.setup()
        task = loop.create_task(runner.serve_forever())
        await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

async def test_app_runner_serve_forever_cleanup_called(
        make_runner, app, loop) -> None:

    called = False

    async def on_cleanup(app_param):
        nonlocal called
        assert app is app_param
        called = True

    app.on_cleanup.append(on_cleanup)
    app.freeze()
    runner = make_runner(app)
    await runner.setup()

    task = loop.create_task(runner.serve_forever())
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert called
