import asyncio
import platform
import threading

import pytest

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop


@pytest.mark.skipif(platform.system() == "Windows",
                    reason="the test is not valid for Windows")
@asyncio.coroutine
def test_subprocess_co(loop):
    assert isinstance(threading.current_thread(), threading._MainThread)
    proc = yield from asyncio.create_subprocess_shell(
        "exit 0", loop=loop, stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
    yield from proc.wait()


class TestCase(AioHTTPTestCase):
    @asyncio.coroutine
    def get_application(self):
        app = web.Application()
        app.on_startup.append(self.on_startup_hook)
        return app

    @asyncio.coroutine
    def on_startup_hook(self, app):
        self.startup_loop = app.loop

    @unittest_run_loop
    @asyncio.coroutine
    def test_on_startup_hook(self):
        assert self.startup_loop is not None
