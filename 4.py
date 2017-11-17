#!/usr/bin/env python
# run it as:
#   python -m unittest test_example.TestClientCase

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop
from aiohttp.test_utils import TestClient, TestServer


class TestClientCase(AioHTTPTestCase):
    def _app_index(self, request):
        return web.Response(body="<html><body>Here we are</body></html",
                            content_type='text/html')

    async def get_application(self):
        app = web.Application()
        app.router.add_get('/', self._app_index)

        return app

    @unittest_run_loop
    async def test_using_class_attribute(self):
        request = await self.client.request("GET", "/")
        print(request.status)
        assert request.status == 200

    @unittest_run_loop
    async def test_using_client(self):
        tc = TestClient(
            TestServer(self.app, loop=self.loop),
            loop=self.loop)
        request = await tc.request("GET", "/")
        print(request.status)
        assert request.status == 200
