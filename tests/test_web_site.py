import asyncio
import platform
import signal

import pytest

from aiohttp import web


async def test_site_for_nonfrozen_app():
    app = web.Application()
    runner = web.AppRunner(app)
    with pytest.raises(RuntimeError):
        web.TCPSite(runner)
    assert len(runner.sites) == 0


@pytest.mark.skipif(platform.system() == "Windows",
                    reason="the test is not valid for Windows")
async def test_runner_setup_handle_signals(loop):
    asyncio.set_event_loop(loop)
    app = web.Application()
    runner = web.AppRunner(app)
    await runner.setup()
    assert signal.getsignal(signal.SIGTERM) is not signal.SIG_DFL
    await runner.cleanup()
    assert signal.getsignal(signal.SIGTERM) is signal.SIG_DFL


@pytest.mark.skipif(platform.system() == "Windows",
                    reason="the test is not valid for Windows")
async def test_runner_setup_without_signal_handling(loop):
    asyncio.set_event_loop(loop)
    app = web.Application()
    runner = web.AppRunner(app, handle_signals=False)
    await runner.setup()
    assert signal.getsignal(signal.SIGTERM) is signal.SIG_DFL
    await runner.cleanup()
    assert signal.getsignal(signal.SIGTERM) is signal.SIG_DFL


async def test_site_double_added():
    app = web.Application()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner)
    await site.start()
    with pytest.raises(RuntimeError):
        await site.start()

    assert len(runner.sites) == 1


async def test_site_stop_not_started():
    app = web.Application()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner)
    with pytest.raises(RuntimeError):
        await site.stop()

    assert len(runner.sites) == 0


async def test_custom_log_format():
    app = web.Application()
    runner = web.AppRunner(app, access_log_format='abc')
    await runner.setup()
    assert runner._handler._kwargs['access_log_format'] == 'abc'


async def test_unreg_site():
    app = web.Application()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner)
    with pytest.raises(RuntimeError):
        runner._unreg_site(site)
