import asyncio

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop


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
