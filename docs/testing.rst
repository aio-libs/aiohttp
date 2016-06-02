.. _aiohttp-testing:

Testing
=======

Testing aiohttp servers
-----------------------

aiohttp provides test framework agnostic utilities for web
servers. An example would be::

    from aiohttp.test_utils import TestClient, loop_context
    from aiohttp import request

    # loop_context is provided as a utility. You can use any
    # asyncio.BaseEventLoop class in it's place.
    with loop_context() as loop:
        app = _create_example_app(loop)
        with TestClient(app) as client:

            async def test_get_route():
                nonlocal client
                resp = await client.request("GET", "/")
                assert resp.status == 200
                text = await resp.text()
                assert "Hello, world" in text

            loop.run_until_complete(test_get_route())


If it's preferred to handle the creation / teardown on a more granular
basis, the TestClient object can be used directly::

    from aiohttp.test_utils import TestClient

    with loop_context() as loop:
        app = _create_example_app(loop)
        client = TestClient(app)
        root = "http://127.0.0.1:{}".format(port)

        async def test_get_route():
            resp = await test_client.request("GET", url)
            assert resp.status == 200
            text = await resp.text()
            assert "Hello, world" in text

        loop.run_until_complete(test_get_route())
        # the server is cleaned up implicitly, through
        # the deletion of the TestServer.
        del client

pytest example
==============

A pytest example could look like::

    # assuming you are using pytest-asyncio
    from asyncio.test_utils import TestClient, loop_context

    @pytest.yield_fixture
    def loop():
        with loop_context() as loop:
            yield loop

    @pytest.fixture
    def app(test_loop):
        return create_app(event_loop)


    @pytest.yield_fixture
    def test_client(app):
        server = TestClient(app)
        yield client
        client.close()

    def test_get_route(loop, test_client):
        @asyncio.coroutine
        def test_get_route():
            nonlocal test_client
            resp = yield from test_client.request("GET", "/")
            assert resp.status == 200
            text = yield from resp.text()
            assert "Hello, world" in text

        loop.run_until_complete(test_get_route())


unittest example
================

To test applications with the standard library's unittest or unittest-based
functionality, the AioHTTPTestCase is provided::

    from aiohttp.test_utils import AioHTTPTestCase, run_loop
    from aiohttp import web

    class MyAppTestCase(AioHTTPTestCase):

        def get_app(self, loop):
            """
            override the get_app method to return
            your application.
            """
            # it's important to use the loop passed here.
            return web.Application(loop=loop)

        # the run_loop decorator can be used in tandem with
        # the AioHTTPTestCase to simplify running
        # tests that are asynchronous
        @run_loop
        async def test_example(self):
            request = await self.client.request("GET", "/")
            assert request.status == 200
            text = await request.text()
            assert "Hello, world" in text

        # a vanilla example
        def test_example(self):
            async def test_get_route():
                url = root + "/"
                resp = await self.client.request("GET", url, loop=loop)
                assert resp.status == 200
                text = await resp.text()
                assert "Hello, world" in text

            self.loop.run_until_complete(test_get_route())
