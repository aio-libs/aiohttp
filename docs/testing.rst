.. _aiohttp-testing:

Testing
=======

.. currentmodule:: aiohttp.test_utils

Testing aiohttp web servers
---------------------------

aiohttp provides plugin for pytest_ making writing web
server tests extremely easy, it also provides
:ref:`test framework agnostic utilities <framework-agnostic-utilities>` for
testing with other frameworks such as :ref:`unittest <unittest-example>`.

Pytest example
~~~~~~~~~~~~~~

The :data:`test_client` fixture available from :data:`aiohttp.pytest_plugin`
allows you to create a client to make requests to test your app.

A simple would be::

    from aiohttp import web
    pytest_plugins = 'aiohttp.pytest_plugin'

    async def hello(request):
        return web.Response(body=b'Hello, world')

    def create_app(loop):
        app = web.Application(loop=loop)
        app.router.add_route('GET', '/', hello)
        return app

    async def test_hello(test_client):
        client = await test_client(create_app)
        resp = await client.get('/')
        assert resp.status == 200
        text = await resp.text()
        assert 'Hello, world' in text


It also provides access to the app instance allowing tests to check the state
of the app. Tests can be made even more succinct with a fixture to create an
app test client::

    import pytest
    from aiohttp import web
    pytest_plugins = 'aiohttp.pytest_plugin'


    async def previous(request):
        if request.method == 'POST':
            request.app['value'] = (await request.post())['value']
            return web.Response(body=b'thanks for the data')
        return web.Response(body='value: {}'.format(request.app['value']).encode())

    def create_app(loop):
        app = web.Application(loop=loop)
        app.router.add_route('*', '/', previous)
        return app

    @pytest.fixture
    def cli(loop, test_client):
        return loop.run_until_complete(test_client(create_app))

    async def test_set_value(cli):
        resp = await cli.post('/', data={'value': 'foo'})
        assert resp.status == 200
        assert await resp.text() == 'thanks for the data'
        assert cli.app['value'] == 'foo'

    async def test_get_value(cli):
        cli.app['value'] = 'bar'
        resp = await cli.get('/')
        assert resp.status == 200
        assert await resp.text() == 'value: bar'


.. _framework-agnostic-utilities:

Framework agnostic utilities
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

High level test creation::

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

Please see the full api at the
:class:`TestClass api reference <aiohttp.test_utils.TestClient>`


.. _unittest-example:

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

.. _pytest: http://pytest.org/latest/
.. automodule:: aiohttp.test_utils
   :members: TestClient, AioHTTPTestCase, run_loop, loop_context, setup_test_loop, teardown_test_loop make_mocked_request
   :undoc-members:
   :show-inheritance:
