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


The Test Client and Servers
~~~~~~~~~~~~~~~~~~~~~~~~~~~

*aiohttp* test utils provides a scaffolding for testing aiohttp-based
web servers.

They are consist of two parts: running test server and making HTTP
requests to this server.

:class:`~aiohttp.test_utils.TestServer` runs :class:`aiohttp.web.Application`
based server, :class:`~aiohttp.test_utils.RawTestServer` starts
:class:`aiohttp.web.WebServer` low level server.

For performing HTTP requests to these servers you have to create a
test client: :class:`~aiohttp.test_utils.TestClient` instance.

The client incapsulates :class:`aiohttp.ClientSession` by providing
proxy methods to the client for common operations such as
*ws_connect*, *get*, *post*, etc.



Pytest
~~~~~~

The :data:`test_client` fixture available from pytest-aiohttp_ plugin
allows you to create a client to make requests to test your app.

A simple would be::

    from aiohttp import web

    async def hello(request):
        return web.Response(text='Hello, world')

    async def test_hello(test_client, loop):
        app = web.Application()
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
        app = web.Application()
        app.router.add_get('/', previous)
        app.router.add_post('/', previous)
        return loop.run_until_complete(test_client(app))

    async def test_set_value(cli):
        resp = await cli.post('/', data={'value': 'foo'})
        assert resp.status == 200
        assert await resp.text() == 'thanks for the data'
        assert cli.server.app['value'] == 'foo'

    async def test_get_value(cli):
        cli.server.app['value'] = 'bar'
        resp = await cli.get('/')
        assert resp.status == 200
        assert await resp.text() == 'value: bar'


Pytest tooling has the following fixtures:

.. data:: test_server(app, **kwargs)

   A fixture factory that creates
   :class:`~aiohttp.test_utils.TestServer`::

      async def test_f(test_server):
          app = web.Application()
          # fill route table

          server = await test_server(app)

   The server will be destroyed on exit from test function.

   *app* is the :class:`aiohttp.web.Application` used
                           to start server.

   *kwargs* are parameters passed to
                  :meth:`aiohttp.web.Application.make_handler`


.. data:: test_client(app, **kwargs)
          test_client(server, **kwargs)
          test_client(raw_server, **kwargs)

   A fixture factory that creates
   :class:`~aiohttp.test_utils.TestClient` for access to tested server::

      async def test_f(test_client):
          app = web.Application()
          # fill route table

          client = await test_client(app)
          resp = await client.get('/')

   *client* and responses are cleaned up after test function finishing.

   The fixture accepts :class:`aiohttp.web.Application`,
   :class:`aiohttp.test_utils.TestServer` or
   :class:`aiohttp.test_utils.RawTestServer` instance.

   *kwargs* are parameters passed to
   :class:`aiohttp.test_utils.TestClient` constructor.

.. data:: raw_test_server(handler, **kwargs)

   A fixture factory that creates
   :class:`~aiohttp.test_utils.RawTestServer` instance from given web
   handler.

   *handler* should be a coroutine which accepts a request and returns
   response, e.g.::

      async def test_f(raw_test_server, test_client):

          async def handler(request):
              return web.Response(text="OK")

          raw_server = await raw_test_server(handler)
          client = await test_client(raw_server)
          resp = await client.get('/')

.. _aiohttp-testing-unittest-example:

.. _aiohttp-testing-unittest-style:

Unittest
~~~~~~~~

To test applications with the standard library's unittest or unittest-based
functionality, the AioHTTPTestCase is provided::

    from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop
    from aiohttp import web

    class MyAppTestCase(AioHTTPTestCase):

        async def get_application(self):
            """
            Override the get_app method to return your application.
            """
            return web.Application()

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

.. class:: AioHTTPTestCase

    A base class to allow for unittest web applications using aiohttp.

    Derived from :class:`unittest.TestCase`

    Provides the following:

    .. attribute:: client

       an aiohttp test client, :class:`TestClient` instance.

    .. attribute:: loop

       The event loop in which the application and server are running.

    .. attribute:: app

       The application returned by :meth:`get_app`
       (:class:`aiohttp.web.Application` instance).

    .. comethod:: get_application()

       This async method should be overridden
       to return the :class:`aiohttp.web.Application`
       object to test.

       :return: :class:`aiohttp.web.Application` instance.

    .. method:: setUp()

       Standard test initialization method.

    .. method:: tearDown()

       Standard test finalization method.


   .. note::

      The ``TestClient``'s methods are asynchronous: you have to
      execute function on the test client using asynchronous methods.

      A basic test class wraps every test method by
      :func:`unittest_run_loop` decorator::

         class TestA(AioHTTPTestCase):

             @unittest_run_loop
             async def test_f(self):
                 resp = await self.client.get('/')


.. decorator:: unittest_run_loop:

   A decorator dedicated to use with asynchronous methods of an
   :class:`AioHTTPTestCase`.

   Handles executing an asynchronous function, using
   the :attr:`AioHTTPTestCase.loop` of the :class:`AioHTTPTestCase`.


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


.. function:: make_mocked_request(method, path, headers=None, *, \
                                  version=HttpVersion(1, 1), \
                                  closing=False, \
                                  app=None, \
                                  reader=sentinel, \
                                  writer=sentinel, \
                                  transport=sentinel, \
                                  payload=sentinel, \
                                  sslcontext=None, \
                                  secure_proxy_ssl_header=None)

   Creates mocked web.Request testing purposes.

   Useful in unit tests, when spinning full web server is overkill or
   specific conditions and errors are hard to trigger.

   :param method: str, that represents HTTP method, like; GET, POST.
   :type method: str

   :param path: str, The URL including *PATH INFO* without the host or scheme
   :type path: str

   :param headers: mapping containing the headers. Can be anything accepted
       by the multidict.CIMultiDict constructor.
   :type headers: dict, multidict.CIMultiDict, list of pairs

   :param version: namedtuple with encoded HTTP version
   :type version: aiohttp.protocol.HttpVersion

   :param closing: flag indicates that connection should be closed after
       response.
   :type closing: bool

   :param app: the aiohttp.web application attached for fake request
   :type app: aiohttp.web.Application

   :param writer: object for managing outcoming data
   :type wirter: aiohttp.streams.StreamWriter

   :param transport: asyncio transport instance
   :type transport: asyncio.transports.Transport

   :param payload: raw payload reader object
   :type  payload: aiohttp.streams.FlowControlStreamReader

   :param sslcontext: ssl.SSLContext object, for HTTPS connection
   :type sslcontext: ssl.SSLContext

   :param secure_proxy_ssl_header: A tuple representing a HTTP header/value
       combination that signifies a request is secure.
   :type secure_proxy_ssl_header: tuple

   :return: :class:`aiohttp.web.Request` object.


.. _aiohttp-testing-writing-testable-services:

.. _aiohttp-testing-framework-agnostic-utilities:


Framework Agnostic Utilities
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

High level test creation::

    from aiohttp.test_utils import TestClient, loop_context
    from aiohttp import request

    # loop_context is provided as a utility. You can use any
    # asyncio.BaseEventLoop class in it's place.
    with loop_context() as loop:
        app = _create_example_app()
        with TestClient(app, loop=loop) as client:

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
        app = _create_example_app()
        client = TestClient(app, loop=loop)
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

Testing API Reference
---------------------

Test server
~~~~~~~~~~~

Runs given :class:`aiohttp.web.Application` instance on random TCP port.

After creation the server is not started yet, use
:meth:`~aiohttp.test_utils.TestServer.start_server` for actual server
starting and :meth:`~aiohttp.test_utils.TestServer.close` for
stopping/cleanup.

Test server usually works in conjunction with
:class:`aiohttp.test_utils.TestClient` which provides handy client methods
for accessing to the server.

.. class:: BaseTestServer(*, scheme='http', host='127.0.0.1')

   Base class for test servers.

   :param str scheme: HTTP scheme, non-protected ``"http"`` by default.

   :param str host: a host for TCP socket, IPv4 *local host*
      (``'127.0.0.1'``) by default.


   .. attribute:: scheme

      A *scheme* for tested application, ``'http'`` for non-protected
      run and ``'https'`` for TLS encrypted server.

   .. attribute:: host

      *host* used to start a test server.

   .. attribute:: port

      A random *port* used to start a server.

   .. attribute:: handler

      :class:`aiohttp.web.WebServer` used for HTTP requests serving.

   .. attribute:: server

      :class:`asyncio.AbstractServer` used for managing accepted connections.

   .. comethod:: start_server(loop=None, **kwargs)

      :param loop: the event_loop to use
      :type loop: asyncio.AbstractEventLoop

      Start a test server.

   .. comethod:: close()

      Stop and finish executed test server.

   .. method:: make_url(path)

      Return an *absolute* :class:`~yarl.URL` for given *path*.


.. class:: RawTestServer(handler, *, scheme="http", host='127.0.0.1')

   Low-level test server (derived from :class:`BaseTestServer`).

   :param handler: a coroutine for handling web requests. The
                   handler should accept
                   :class:`aiohttp.web.BaseRequest` and return a
                   response instance,
                   e.g. :class:`~aiohttp.web.StreamResponse` or
                   :class:`~aiohttp.web.Response`.

                   The handler could raise
                   :class:`~aiohttp.web.HTTPException` as a signal for
                   non-200 HTTP response.

   :param str scheme: HTTP scheme, non-protected ``"http"`` by default.

   :param str host: a host for TCP socket, IPv4 *local host*
      (``'127.0.0.1'``) by default.


.. class:: TestServer(app, *, scheme="http", host='127.0.0.1')

   Test server (derived from :class:`BaseTestServer`) for starting
   :class:`~aiohttp.web.Application`.

   :param app: :class:`aiohttp.web.Application` instance to run.

   :param str scheme: HTTP scheme, non-protected ``"http"`` by default.

   :param str host: a host for TCP socket, IPv4 *local host*
      (``'127.0.0.1'``) by default.


   .. attribute:: app

      :class:`aiohttp.web.Application` instance to run.


Test Client
~~~~~~~~~~~

.. class:: TestClient(app_or_server, *, loop=None, \
                      scheme='http', host='127.0.0.1', \
                      cookie_jar=None, **kwargs)

   A test client used for making calls to tested server.

   :param app_or_server: :class:`BaseTestServer` instance for making
                         client requests to it.

                         If the parameter is
                         :class:`aiohttp.web.Application` the tool
                         creates :class:`TestServer` implicitly for
                         serving the application.

   :param cookie_jar: an optional :class:`aiohttp.CookieJar` instance,
                      may be useful with ``CookieJar(unsafe=True)``
                      option.

   :param str scheme: HTTP scheme, non-protected ``"http"`` by default.

   :param asyncio.AbstractEventLoop loop: the event_loop to use

   :param str host: a host for TCP socket, IPv4 *local host*
      (``'127.0.0.1'``) by default.

   .. attribute:: scheme

      A *scheme* for tested application, ``'http'`` for non-protected
      run and ``'https'`` for TLS encrypted server.

   .. attribute:: host

      *host* used to start a test server.

   .. attribute:: port

      A random *port* used to start a server.

   .. attribute:: server

      :class:`BaseTestServer` test server instance used in conjunction
      with client.

   .. attribute:: session

      An internal :class:`aiohttp.ClientSession`.

      Unlike the methods on the :class:`TestClient`, client session
      requests do not automatically include the host in the url
      queried, and will require an absolute path to the resource.

   .. comethod:: start_server(**kwargs)

      Start a test server.

   .. comethod:: close()

      Stop and finish executed test server.

   .. method:: make_url(path)

      Return an *absolute* :class:`~yarl.URL` for given *path*.

   .. comethod:: request(method, path, *args, **kwargs)

      Routes a request to tested http server.

      The interface is identical to
      :meth:`asyncio.ClientSession.request`, except the loop kwarg is
      overridden by the instance used by the test server.

   .. comethod:: get(path, *args, **kwargs)

      Perform an HTTP GET request.

   .. comethod:: post(path, *args, **kwargs)

      Perform an HTTP POST request.

   .. comethod:: options(path, *args, **kwargs)

      Perform an HTTP OPTIONS request.

   .. comethod:: head(path, *args, **kwargs)

      Perform an HTTP HEAD request.

   .. comethod:: put(path, *args, **kwargs)

      Perform an HTTP PUT request.

   .. comethod:: patch(path, *args, **kwargs)

      Perform an HTTP PATCH request.

   .. comethod:: delete(path, *args, **kwargs)

      Perform an HTTP DELETE request.

   .. comethod:: ws_connect(path, *args, **kwargs)

      Initiate websocket connection.

      The api corresponds to :meth:`aiohttp.ClientSession.ws_connect`.


Utilities
~~~~~~~~~

.. function:: make_mocked_coro(return_value)

  Creates a coroutine mock.

  Behaves like a coroutine which returns *return_value*.  But it is
  also a mock object, you might test it as usual
  :class:`~unittest.mock.Mock`::

      mocked = make_mocked_coro(1)
      assert 1 == await mocked(1, 2)
      mocked.assert_called_with(1, 2)


  :param return_value: A value that the the mock object will return when
      called.
  :returns: A mock object that behaves as a coroutine which returns
      *return_value* when called.


.. function:: unused_port()

   Return an unused port number for IPv4 TCP protocol.

   :return int: ephemeral port number which could be reused by test server.

.. function:: loop_context(loop_factory=<function asyncio.new_event_loop>)

   A contextmanager that creates an event_loop, for test purposes.

   Handles the creation and cleanup of a test loop.

.. function:: setup_test_loop(loop_factory=<function asyncio.new_event_loop>)

   Create and return an :class:`asyncio.AbstractEventLoop` instance.

   The caller should also call teardown_test_loop, once they are done
   with the loop.

.. function:: teardown_test_loop(loop)

   Teardown and cleanup an event_loop created by setup_test_loop.

   :param loop: the loop to teardown
   :type loop: asyncio.AbstractEventLoop



.. _pytest: http://pytest.org/latest/
.. _pytest-aiohttp: https://pypi.python.org/pypi/pytest-aiohttp


.. disqus::
  :title: aiohttp testing
