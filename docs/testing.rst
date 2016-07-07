.. _aiohttp-testing:

Testing
=======

.. currentmodule:: aiohttp.test_utils

Testing aiohttp web servers
---------------------------

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
                resp = await client.get("/")
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
            resp = await client.get("/")
            assert resp.status == 200
            text = await resp.text()
            assert "Hello, world" in text

        loop.run_until_complete(test_get_route())
        # the server is cleaned up implicitly, through
        # the deletion of the TestServer.
        del client


A full list of the utilities provided can be found at the
:data:`api reference <aiohttp.test_utils>`

The Test Client
~~~~~~~~~~~~~~~

The :data:`aiohttp.test_utils.TestClient` creates an asyncio server
for the web.Application object, as well as a ClientSession to perform
requests. In addition, TestClient provides proxy methods to the client for
common operations such as ws_connect, get, post, etc.

Please see the full api at the :class:`TestClass api reference <aiohttp.test_utils.TestClient>`



Pytest example
~~~~~~~~~~~~~~

A pytest example could look like::

    from aiohttp.test_utils import TestClient, loop_context

    @pytest.yield_fixture
    def loop():
        with loop_context() as loop:
            yield loop

    @pytest.fixture
    def app(loop):
        return create_app(loop)


    @pytest.yield_fixture
    def test_client(app):
        client = TestClient(app)
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


Unittest example
~~~~~~~~~~~~~~~~

To test applications with the standard library's unittest or unittest-based
functionality, the AioHTTPTestCase is provided::

    from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop
    from aiohttp import web

    class MyAppTestCase(AioHTTPTestCase):

        def get_app(self, loop):
            """
            override the get_app method to return
            your application.
            """
            # it's important to use the loop passed here.
            return web.Application(loop=loop)

        # the unittest_run_loop decorator can be used in tandem with
        # the AioHTTPTestCase to simplify running
        # tests that are asynchronous
        @unittest_run_loop
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

Faking request object
---------------------

aiohttp provides test utility for creating fake `web.Request` objects:
:data:`aiohttp.test_utils.make_mocked_request`, it could be useful in case of
simple unit tests, like handler tests, or simulate error conditions that
hard to reproduce on real server. ::

    from aiohttp import web

    def handler(request):
        assert request.headers.get('token') == 'x'
        return web.Response(body=b'data')

    def test_handler()
        req = make_request('get', 'http://python.org/', headers={'token': 'x')
        resp = header(req)
        assert resp.body == b'data'


aiohttp.test_utils
------------------

.. automodule:: aiohttp.test_utils
   :members: TestClient, AioHTTPTestCase, run_loop, loop_context, setup_test_loop, teardown_test_loop make_mocked_request
   :undoc-members:
   :show-inheritance:
