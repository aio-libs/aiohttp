import asyncio
import platform
import signal

import pytest

from aiohttp import web
from aiohttp.test_utils import get_unused_port_socket


@pytest.fixture
def app():
    return web.Application()


@pytest.fixture
def make_runner(loop, app):
    asyncio.set_event_loop(loop)
    runners = []

    def go(**kwargs):
        runner = web.AppRunner(app, **kwargs)
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


@pytest.mark.skipif(platform.system() == "Windows",
                    reason="Unix socket support is required")
async def test_addresses(make_runner, shorttmpdir) -> None:
    _sock = get_unused_port_socket('127.0.0.1')
    runner = make_runner()
    await runner.setup()
    tcp = web.SockSite(runner, _sock)
    await tcp.start()
    path = str(shorttmpdir / 'tmp.sock')
    unix = web.UnixSite(runner, path)
    await unix.start()
    actual_addrs = runner.addresses
    expected_host, expected_post = _sock.getsockname()[:2]
    assert actual_addrs == [(expected_host, expected_post), path]
