import asyncio
import platform
import threading

import pytest

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase, loop_context


@pytest.mark.skipif(
    platform.system() == "Windows", reason="the test is not valid for Windows"
)
async def test_subprocess_co(loop) -> None:
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

    async def test_on_startup_hook(self) -> None:
        self.assertTrue(self.on_startup_called)

    def test_default_loop(self) -> None:
        self.assertIs(self.loop, asyncio.get_event_loop_policy().get_event_loop())


def test_default_loop(loop) -> None:
    assert asyncio.get_event_loop_policy().get_event_loop() is loop


def test_setup_loop_non_main_thread() -> None:
    child_exc = None

    def target() -> None:
        try:
            with loop_context() as loop:
                assert asyncio.get_event_loop_policy().get_event_loop() is loop
                loop.run_until_complete(test_subprocess_co(loop))
        except Exception as exc:
            nonlocal child_exc
            child_exc = exc

    # Ensures setup_test_loop can be called by pytest-xdist in non-main thread.
    t = threading.Thread(target=target)
    t.start()
    t.join()

    assert child_exc is None
