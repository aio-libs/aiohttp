import asyncio
import platform
import threading
from typing import Any

import pytest

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase


@pytest.mark.skipif(
    platform.system() == "Windows", reason="the test is not valid for Windows"
)
async def test_subprocess_co(loop: Any) -> None:
    assert threading.current_thread() is threading.main_thread()
    proc = await asyncio.create_subprocess_shell(
        "exit 0",
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await proc.wait()


class TestCase(AioHTTPTestCase):
    on_startup_called: bool

    async def get_application(self) -> web.Application:
        app = web.Application()
        app.on_startup.append(self.on_startup_hook)
        return app

    async def on_startup_hook(self, app: Any) -> None:
        self.on_startup_called = True

    async def test_on_startup_hook(self) -> None:
        self.assertTrue(self.on_startup_called)

    def test_default_loop(self) -> None:
        self.assertIs(self.loop, asyncio.get_event_loop())


def test_default_loop(loop: Any) -> None:
    assert asyncio.get_event_loop() is loop
