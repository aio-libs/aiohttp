.. _aiohttp-testing:

Testing
=======

.. currentmodule:: aiohttp.test_utils

Testing aiohttp web servers
---------------------------

aiohttp provides plugin for pytest_ making writing web server tests
extremely easy, it also provides :ref:`test framework agnostic
utilities <aiohttp-testing-framework-agnostic-utilities>` for testing
with other frameworks such as :ref:`unittest
<aiohttp-testing-unittest-example>`.

Before starting to write your tests, you may also be interested on
reading :ref:`how to write testable
services<aiohttp-testing-writing-testable-services>` that interact
with the loop.


For using pytest plugin please install pytest-aiohttp_ library:

.. code-block:: shell

   $ pip install pytest-aiohttp

If you don't want to install *pytest-aiohttp* for some reason you may
insert ``pytest_plugins = 'aiohttp.pytest_plugin'`` line into
``conftest.py`` instead for the same functionality.



Provisional Status
~~~~~~~~~~~~~~~~~~

The module is a **provisional**.

*aiohttp* has a year and half period for removing deprecated API
(:ref:`aiohttp-backward-compatibility-policy`).

But for :mod:`aiohttp.test_tools` the deprecation period could be reduced.

Moreover we may break *backward compatibility* without *deprecation
peroid* for some very strong reason.


Pytest Example
~~~~~~~~~~~~~~

The :data:`test_client` fixture available from pytest-aiohttp_ plugin
allows you to create a client to make requests to test your app.

A simple would be::

    from aiohttp import web

    async def hello(request):
        return web.Response(text='Hello, world')

    async def test_hello(test_client, loop):
        app = web.Application(loop=loop)
        app.router.add_get('/', hello)
        client = await test_client(app)
        resp = await client.get('/')
        assert resp.status == 200
        text = await resp.text()
        assert 'Hello, world' in text


It also provides access to the app instance allowing tests to check the state
of the app. Tests can be made even more succinct with a fixture to create an
app test client::

    import pytest
    from aiohttp import web


    async def previous(request):
        if request.method == 'POST':
            request.app['value'] = (await request.post())['value']
            return web.Response(body=b'thanks for the data')
        return web.Response(
            body='value: {}'.format(request.app['value']).encode('utf-8'))

    @pytest.fixture
    def cli(loop, test_client):
        app = web.Application(loop=loop)
        app.router.add_get('/', hello)
        return loop.run_until_complete(test_client(app))

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


.. _aiohttp-testing-framework-agnostic-utilities:

Framework Agnostic Utilities
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
        loop.run_until_complete(client.start_server())
        root = "http://127.0.0.1:{}".format(port)

        async def test_get_route():
            resp = await client.get("/")
            assert resp.status == 200
            text = await resp.text()
            assert "Hello, world" in text

        loop.run_until_complete(test_get_route())
        loop.run_until_complete(client.close())


A full list of the utilities provided can be found at the
:data:`api reference <aiohttp.test_utils>`

The Test Client
~~~~~~~~~~~~~~~

The :class:`aiohttp.test_utils.TestClient` creates an asyncio server
for the web.Application object, as well as a ClientSession to perform
requests. In addition, TestClient provides proxy methods to the client for
common operations such as ws_connect, get, post, etc.

Please see the full api at the
:class:`TestClass api reference <aiohttp.test_utils.TestClient>`


.. _aiohttp-testing-unittest-example:

Unittest Example
~~~~~~~~~~~~~~~~

To test applications with the standard library's unittest or unittest-based
functionality, the AioHTTPTestCase is provided::

    from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop
    from aiohttp import web

    class MyAppTestCase(AioHTTPTestCase):

        def get_app(self, loop):
            """Override the get_app method to return your application.
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

aiohttp provides test utility for creating fake
:class:`aiohttp.web.Request` objects:
:func:`aiohttp.test_utils.make_mocked_request`, it could be useful in
case of simple unit tests, like handler tests, or simulate error
conditions that hard to reproduce on real server::

    from aiohttp import web
    from aiohttp.test_utils import make_mocked_request

    def handler(request):
        assert request.headers.get('token') == 'x'
        return web.Response(body=b'data')

    def test_handler():
        req = make_mocked_request('GET', '/', headers={'token': 'x'})
        resp = handler(req)
        assert resp.body == b'data'

.. warning::

   We don't recommend to apply
   :func:`~aiohttp.test_utils.make_mocked_request` everywhere for
   testing web-handler's business object -- please use test client and
   real networking via 'localhost' as shown in examples before.

   :func:`~aiohttp.test_utils.make_mocked_request` exists only for
   testing complex cases (e.g. emulating network errors) which
   are extremely hard or even impossible to test by conventional
   way.


.. _aiohttp-testing-writing-testable-services:

Writing testable services
-------------------------

Some libraries like motor, aioes and others depend on the asyncio loop for
executing the code. When running your normal program, these libraries pick
the main event loop by doing ``asyncio.get_event_loop``. The problem during
testing is that there is no main loop assigned because an independent
loop for each test is created without assigning it as the main one.

This raises a problem when those libraries try to find it. Luckily, the ones
that are well written, allow passing the loop explicitly. Let's have a look
at the aioes client signature::

  def __init__(self, endpoints, *, loop=None, **kwargs)

As you can see, there is an optional ``loop`` kwarg. Of course, we are not
going to test directly the aioes client but our service that depends on it
will. So, if we want our ``AioESService`` to be easily testable, we should
define it as follows::

  import asyncio

  from aioes import Elasticsearch


  class AioESService:

      def __init__(self, loop=None):
          self.es = Elasticsearch(["127.0.0.1:9200"], loop=loop)

      async def get_info(self):
          cluster_info = await self.es.info()
          print(cluster_info)

  if __name__ == "__main__":
      client = AioESService()
      loop = asyncio.get_event_loop()
      loop.run_until_complete(client.get_info())


Note that it is accepting an optional ``loop`` kwarg. For the normal flow of
execution it won't affect because we can still call the service without passing
the loop explicitly having a main loop available. The problem comes when you
try to do a test like::

  import pytest

  from main import AioESService


  class TestAioESService:

      async def test_get_info(self):
          cluster_info = await AioESService().get_info()
          assert isinstance(cluster_info, dict)

If you try to run the test, it will fail with a similar error::

  ...
  RuntimeError: There is no current event loop in thread 'MainThread'.


If you check the stack trace, you will see aioes is complaining that there is
no current event loop in the main thread. Pass explicit loop to solve it.

If you rely on code which works with *implicit* loops only you may try
to use hackish approach from :ref:`FAQ <aiohttp_faq_tests_and_implicit_loop>`.

aiohttp.test_utils
------------------

.. automodule:: aiohttp.test_utils
   :members: TestClient, AioHTTPTestCase, unittest_run_loop,
             loop_context, setup_test_loop, teardown_test_loop,
             make_mocked_request
   :undoc-members:
   :show-inheritance:

.. function:: make_mocked_coro(return_value)

  Creates a coroutine mock.

  Behaves like a coroutine which returns `return_value`.
  But it is also a mock object, you might test it as usual Mock::

      mocked = make_mocked_coro(1)
      assert 1 == await mocked(1, 2)
      mocked.assert_called_with(1, 2)


  :param return_value: A value that the the mock object will return when
      called.
  :returns: A mock object that behaves as a coroutine which returns
      `return_value` when called.


.. _pytest: http://pytest.org/latest/
.. _pytest-aiohttp: https://pypi.python.org/pypi/pytest-aiohttp


.. disqus::
  :title: aiohttp testing
