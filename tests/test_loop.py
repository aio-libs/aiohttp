import asyncio
import platform
import threading

import pytest

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop


@pytest.mark.skipif(
    platform.system() == "Windows", reason="the test is not valid for Windows"
)
async def test_subprocess_co(loop) -> None:
    assert isinstance(threading.current_thread(), threading._MainThread)
    proc = await asyncio.create_subprocess_shell(
        "exit 0",
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await proc.wait()


class TestCase(AioHTTPTestCase):
    async def get_application(self):
        app = web.Application()
        app.on_startup.append(self.on_startup_hook)
        return app

    async def on_startup_hook(self, app):
        self.on_startup_called = True

    @unittest_run_loop
    async def test_on_startup_hook(self) -> None:
        self.assertTrue(self.on_startup_called)

    def test_default_loop(self) -> None:
        self.assertIs(self.loop, asyncio.get_event_loop())


def test_default_loop(loop) -> None:
    assert asyncio.get_event_loop() is loop
