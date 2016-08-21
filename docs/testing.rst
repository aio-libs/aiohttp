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

Before starting to write your tests, you may also be interested on reading
:ref:`how to write testable services<writing-testable-services>` that interact
with the loop.


For using pytest plugin please install pytest-aiohttp_ library:

.. code-block:: shell

   $ pip install pytest-aiohttp

If you don't want to install *pytest-aiohttp* for some reason you may
insert ``pytest_plugins = 'aiohttp.pytest_plugin'`` line into
``conftest.py`` instead for the same functionality.



Pytest example
~~~~~~~~~~~~~~

The :data:`test_client` fixture available from :data:`aiohttp.pytest_plugin`
allows you to create a client to make requests to test your app.

A simple would be::

    from aiohttp import web

    async def hello(request):
        return web.Response(body=b'Hello, world')

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
    pytest_plugins = 'aiohttp.pytest_plugin'


    async def previous(request):
        if request.method == 'POST':
            request.app['value'] = (await request.post())['value']
            return web.Response(body=b'thanks for the data')
        return web.Response(
            body='value: {}'.format(request.app['value']).encode())

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


.. _writing-testable-services:

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

  main.py:9: in __init__
      self.es = Elasticsearch(["127.0.0.1:9200"], loop=loop)
  ../../.virtualenvs/aiohttp_test/lib/python3.5/site-packages/aioes/client/__init__.py:18: in __init__
      self._transport = Transport(endpoints, loop=loop, **kwargs)
  ../../.virtualenvs/aiohttp_test/lib/python3.5/site-packages/aioes/transport.py:52: in __init__
      self._pool = ConnectionPool([], loop=loop)
  ../../.virtualenvs/aiohttp_test/lib/python3.5/site-packages/aioes/pool.py:41: in __init__
      self._dead = asyncio.PriorityQueue(len(connections), loop=loop)
  /usr/local/Cellar/python3/3.5.1/Frameworks/Python.framework/Versions/3.5/lib/python3.5/asyncio/queues.py:43: in __init__
      self._loop = events.get_event_loop()
  /usr/local/Cellar/python3/3.5.1/Frameworks/Python.framework/Versions/3.5/lib/python3.5/asyncio/events.py:626: in get_event_loop
      return get_event_loop_policy().get_event_loop()

  def get_event_loop(self):
      """Get the event loop.

          This may be None or an instance of EventLoop.
          """
      if (self._local._loop is None and
          not self._local._set_called and
          isinstance(threading.current_thread(), threading._MainThread)):
          self.set_event_loop(self.new_event_loop())
      if self._local._loop is None:
          raise RuntimeError('There is no current event loop in thread %r.'
  >                              % threading.current_thread().name)
  E           RuntimeError: There is no current event loop in thread 'MainThread'.


If you check the stack trace, you will see aioes is complaining that there is
no current event loop in the main thread. We can solve this in two different
ways:

  - Passing the loop explicitly (``loop`` is a pytest fixture from the
    ``pytest-aiohttp`` package::

      class TestAioESService:

          async def test_get_info(self, loop):
              cluster_info = await AioESService(loop=loop).get_info()
              assert isinstance(cluster_info, dict)

  - Using the ``pytest.mark.asyncio`` decorator from ``pytest-asyncio``::

      class TestAioESService:

          @pytest.mark.asyncio
          async def test_get_info(self):
              cluster_info = await AioESService().get_info()
              assert isinstance(cluster_info, dict)

At some point, you may decide that using the decorator is easier but, in case
you want to use let's say the ``test_client`` fixture provided by aiohttp, you
will find problems because your test and the fixture will be using different
event loops. To solve this issue, there is a
`hack <https://github.com/KeepSafe/aiohttp/issues/1069>`_ but as a conclusion,
you should pass the loop explicitly to your services.

In case you have many nested services, this may sound horrible, but you can
always patch your low level service that depends on aioes, to inject the loop
at that level. This way, you just need your ``AioESService`` with the loop
in its signature. An example would be the following::

  import pytest

  from unittest.mock import patch, MagicMock

  from main import AioESService, create_app

  class TestAcceptance:

      async def test_get(self, test_client, loop):
          with patch("main.AioESService", MagicMock(return_value=AioESService(loop=loop))):
              client = await test_client(create_app)
              resp = await client.get("/")
              assert resp.status == 200

Note how we are patching the ``AioESService`` with and instance of itself but
adding the explicit loop as an extra (you need to load the loop fixture in your
test signature).

The final code to test all this (you will need a local instance of
elasticsearch running)::

  import asyncio

  from aioes import Elasticsearch
  from aiohttp import web


  class AioESService:

      def __init__(self, loop=None):
          self.es = Elasticsearch(["127.0.0.1:9200"], loop=loop)

      async def get_info(self):
          return await self.es.info()


  class MyService:

      def __init__(self):
          self.aioes_service = AioESService()

      async def get_es_info(self):
          return await self.aioes_service.get_info()


  async def hello_aioes(request):
      my_service = MyService()
      cluster_info = await my_service.get_es_info()
      return web.Response(text="{}".format(cluster_info))


  def create_app(loop=None):

      app = web.Application(loop=loop)
      app.router.add_route('GET', '/', hello_aioes)
      return app


  if __name__ == "__main__":
      web.run_app(create_app())


And the full tests file::


  from unittest.mock import patch, MagicMock

  from main import AioESService, create_app


  class TestAioESService:

      async def test_get_info(self, loop):
          cluster_info = await AioESService("random_arg", loop=loop).get_info()
          assert isinstance(cluster_info, dict)


  class TestAcceptance:

      async def test_get(self, test_client, loop):
          with patch("main.AioESService", MagicMock(
                  side_effect=lambda *args, **kwargs: AioESService(*args, **kwargs, loop=loop))):
              client = await test_client(create_app)
              resp = await client.get("/")
              assert resp.status == 200

Note how we are using the ``side_effect`` feature for injecting the loop to the
``AioESService.__init__`` call. The use of ``**args, **kwargs`` is mandatory
in order to propagate the arguments being used by the caller.


aiohttp.test_utils
------------------

.. automodule:: aiohttp.test_utils
   :members: TestClient, AioHTTPTestCase, unittest_run_loop, loop_context, setup_test_loop, teardown_test_loop, make_mocked_request
   :undoc-members:
   :show-inheritance:


.. _pytest: http://pytest.org/latest/
.. _pytest-aiohttp: https://pypi.python.org/pypi/pytest-aiohttp
