.. _aiohttp-web-advanced:

Web Server Advanced
===================

.. currentmodule:: aiohttp.web


Web Handler Cancellation
------------------------

.. warning::

   :term:`web-handler` execution could be canceled on every ``await``
   if client drops connection without reading entire response's BODY.

   The behavior is very different from classic WSGI frameworks like
   Flask and Django.

Sometimes it is a desirable behavior: on processing ``GET`` request the
code might fetch data from database or other web resource, the
fetching is potentially slow.

Canceling this fetch is very good: the peer dropped connection
already, there is no reason to waste time and resources (memory etc) by
getting data from DB without any chance to send it back to peer.

But sometimes the cancellation is bad: on ``POST`` request very often
is needed to save data to DB regardless to peer closing.

Cancellation prevention could be implemented in several ways:

* Applying :func:`asyncio.shield` to coroutine that saves data into DB.
* Spawning a new task for DB saving
* Using aiojobs_ or other third party library.

:func:`asyncio.shield` works pretty good. The only disadvantage is you
need to split web handler into exactly two async functions: one
for handler itself and other for protected code.

For example the following snippet is not safe::

   async def handler(request):
       await asyncio.shield(write_to_redis(request))
       await asyncio.shield(write_to_postgres(request))
       return web.Response('OK')

Cancellation might be occurred just after saving data in REDIS,
``write_to_postgres`` will be not called.

Spawning a new task is much worse: there is no place to ``await``
spawned tasks::

   async def handler(request):
       request.loop.create_task(write_to_redis(request))
       return web.Response('OK')

In this case errors from ``write_to_redis`` are not awaited, it leads
to many asyncio log messages *Future exception was never retrieved*
and *Task was destroyed but it is pending!*.

Moreover on :ref:`aiohttp-web-graceful-shutdown` phase *aiohttp* don't
wait for these tasks, you have a great chance to loose very important
data.

On other hand aiojobs_ provides an API for spawning new jobs and
awaiting their results etc. It stores all scheduled activity in
internal data structures and could terminate them gracefully::

   from aiojobs.aiohttp import setup, spawn

   async def coro(timeout):
       await asyncio.sleep(timeout)  # do something in background

   async def handler(request):
       await spawn(request, coro())
       return web.Response()

   app = web.Application()
   setup(app)
   app.router.add_get('/', handler)

All not finished jobs will be terminated on
:attr:`aiohttp.web.Application.on_cleanup` signal.

To prevent cancellation of the whole :term:`web-handler` use
``@atomic`` decorator::

   from aiojobs.aiohttp import atomic

   @atomic
   async def handler(request):
       await write_to_db()
       return web.Response()

   app = web.Application()
   setup(app)
   app.router.add_post('/', handler)

It prevents all ``handler`` async function from cancellation,
``write_to_db`` will be never interrupted.

.. _aiojobs: http://aiojobs.readthedocs.io/en/latest/

Custom Routing Criteria
-----------------------

Sometimes you need to register :ref:`handlers <aiohttp-web-handler>` on
more complex criteria than simply a *HTTP method* and *path* pair.

Although :class:`UrlDispatcher` does not support any extra criteria, routing
based on custom conditions can be accomplished by implementing a second layer
of routing in your application.

The following example shows custom routing based on the *HTTP Accept* header::

   class AcceptChooser:

       def __init__(self):
           self._accepts = {}

       async def do_route(self, request):
           for accept in request.headers.getall('ACCEPT', []):
               acceptor = self._accepts.get(accept)
               if acceptor is not None:
                   return (await acceptor(request))
           raise HTTPNotAcceptable()

       def reg_acceptor(self, accept, handler):
           self._accepts[accept] = handler


   async def handle_json(request):
       # do json handling

   async def handle_xml(request):
       # do xml handling

   chooser = AcceptChooser()
   app.router.add_get('/', chooser.do_route)

   chooser.reg_acceptor('application/json', handle_json)
   chooser.reg_acceptor('application/xml', handle_xml)

.. _aiohttp-web-static-file-handling:

Static file handling
--------------------

The best way to handle static files (images, JavaScripts, CSS files
etc.) is using `Reverse Proxy`_ like `nginx`_ or `CDN`_ services.

.. _Reverse Proxy: https://en.wikipedia.org/wiki/Reverse_proxy
.. _nginx: https://nginx.org/
.. _CDN: https://en.wikipedia.org/wiki/Content_delivery_network

But for development it's very convenient to handle static files by
aiohttp server itself.

To do it just register a new static route by
:meth:`UrlDispatcher.add_static` call::

   app.router.add_static('/prefix', path_to_static_folder)

When a directory is accessed within a static route then the server responses
to client with ``HTTP/403 Forbidden`` by default. Displaying folder index
instead could be enabled with ``show_index`` parameter set to ``True``::

   app.router.add_static('/prefix', path_to_static_folder, show_index=True)

When a symlink from the static directory is accessed, the server responses to
client with ``HTTP/404 Not Found`` by default. To allow the server to follow
symlinks, parameter ``follow_symlinks`` should be set to ``True``::

   app.router.add_static('/prefix', path_to_static_folder, follow_symlinks=True)

When you want to enable cache busting,
parameter ``append_version`` can be set to ``True``

Cache busting is the process of appending some form of file version hash
to the filename of resources like JavaScript and CSS files.
The performance advantage of doing this is that we can tell the browser
to cache these files indefinitely without worrying about the client not getting
the latest version when the file changes::

   app.router.add_static('/prefix', path_to_static_folder, append_version=True)

Template Rendering
------------------

:mod:`aiohttp.web` does not support template rendering out-of-the-box.

However, there is a third-party library, :mod:`aiohttp_jinja2`, which is
supported by the *aiohttp* authors.

Using it is rather simple. First, setup a *jinja2 environment* with a call
to :func:`aiohttp_jinja2.setup`::

    app = web.Application()
    aiohttp_jinja2.setup(app,
        loader=jinja2.FileSystemLoader('/path/to/templates/folder'))

After that you may use the template engine in your
:ref:`handlers <aiohttp-web-handler>`. The most convenient way is to simply
wrap your handlers with the  :func:`aiohttp_jinja2.template` decorator::

    @aiohttp_jinja2.template('tmpl.jinja2')
    def handler(request):
        return {'name': 'Andrew', 'surname': 'Svetlov'}

If you prefer the `Mako`_ template engine, please take a look at the
`aiohttp_mako`_ library.

.. _Mako: http://www.makotemplates.org/

.. _aiohttp_mako: https://github.com/aio-libs/aiohttp_mako


.. _aiohttp-web-websocket-read-same-task:

Reading from the same task in WebSockets
----------------------------------------

Reading from the *WebSocket* (``await ws.receive()``) **must only** be
done inside the request handler *task*; however, writing
(``ws.send_str(...)``) to the *WebSocket*, closing (``await
ws.close()``) and canceling the handler task may be delegated to other
tasks. See also :ref:`FAQ section
<aiohttp_faq_terminating_websockets>`.

:mod:`aiohttp.web` creates an implicit :class:`asyncio.Task` for
handling every incoming request.

.. note::

   While :mod:`aiohttp.web` itself only supports *WebSockets* without
   downgrading to *LONG-POLLING*, etc., our team supports SockJS_, an
   aiohttp-based library for implementing SockJS-compatible server
   code.

.. _SockJS: https://github.com/aio-libs/sockjs


.. warning::

   Parallel reads from websocket are forbidden, there is no
   possibility to call :meth:`aiohttp.web.WebSocketResponse.receive`
   from two tasks.

   See :ref:`FAQ section <aiohttp_faq_parallel_event_sources>` for
   instructions how to solve the problem.


.. _aiohttp-web-data-sharing:

Data Sharing aka No Singletons Please
-------------------------------------

:mod:`aiohttp.web` discourages the use of *global variables*, aka *singletons*.
Every variable should have its own context that is *not global*.

So, :class:`aiohttp.web.Application` and :class:`aiohttp.web.Request`
support a :class:`collections.abc.MutableMapping` interface (i.e. they are
dict-like objects), allowing them to be used as data stores.

For storing *global-like* variables, feel free to save them in an
:class:`~.Application` instance::

    app['my_private_key'] = data

and get it back in the :term:`web-handler`::

    async def handler(request):
        data = request.app['my_private_key']

Variables that are only needed for the lifetime of a :class:`~.Request`, can be
stored in a :class:`~.Request`::

    async def handler(request):
      request['my_private_key'] = "data"
      ...

This is mostly useful for :ref:`aiohttp-web-middlewares` and
:ref:`aiohttp-web-signals` handlers to store data for further processing by the
next handlers in the chain.

:class:`aiohttp.web.StreamResponse` and :class:`aiohttp.web.Response` objects
also support :class:`collections.abc.MutableMapping` interface. This is useful
when you want to share data with signals and middlewares once all the work in
the handler is done::

    async def handler(request):
      [ do all the work ]
      response['my_metric'] = 123
      return response


To avoid clashing with other *aiohttp* users and third-party libraries, please
choose a unique key name for storing data.

If your code is published on PyPI, then the project name is most likely unique
and safe to use as the key.
Otherwise, something based on your company name/url would be satisfactory (i.e.
``org.company.app``).

.. _aiohttp-web-middlewares:

Middlewares
-----------

:mod:`aiohttp.web` provides a powerful mechanism for customizing
:ref:`request handlers<aiohttp-web-handler>` via *middlewares*.

A *middleware* is a coroutine that can modify either the request or
response. For example, here's a simple *middleware* which appends
``' wink'`` to the response::

    from aiohttp.web import middleware

    @middleware
    async def middleware(request, handler):
        resp = await handler(request)
        resp.text = resp.text + ' wink'
        return resp

(Note: this example won't work with streamed responses or websockets)

Every *middleware* should accept two parameters, a
:class:`request <Request>` instance and a *handler*, and return the response.

When creating an :class:`Application`, these *middlewares* are passed to
the keyword-only ``middlewares`` parameter::

   app = web.Application(middlewares=[middleware_1,
                                      middleware_2])

Internally, a single :ref:`request handler <aiohttp-web-handler>` is constructed
by applying the middleware chain to the original handler in reverse order,
and is called by the :class:`RequestHandler` as a regular *handler*.

Since *middlewares* are themselves coroutines, they may perform extra
``await`` calls when creating a new handler, e.g. call database etc.

*Middlewares* usually call the handler, but they may choose to ignore it,
e.g. displaying *403 Forbidden page* or raising :exc:`HTTPForbidden` exception
if the user does not have permissions to access the underlying resource.
They may also render errors raised by the handler, perform some pre- or
post-processing like handling *CORS* and so on.

The following code demonstrates middlewares execution order::

   from aiohttp import web

   def test(request):
       print('Handler function called')
       return web.Response(text="Hello")

   @web.middleware
   async def middleware1(request, handler):
       print('Middleware 1 called')
       response = await handler(request)
       print('Middleware 1 finished')
       return response

   @web.middleware
   async def middleware2(request, handler):
       print('Middleware 2 called')
       response = await handler(request)
       print('Middleware 2 finished')
       return response


   app = web.Application(middlewares=[middleware1, middleware2])
   app.router.add_get('/', test)
   web.run_app(app)

Produced output::

   Middleware 1 called
   Middleware 2 called
   Handler function called
   Middleware 2 finished
   Middleware 1 finished

Example
^^^^^^^

A common use of middlewares is to implement custom error pages.  The following
example will render 404 errors using a JSON response, as might be appropriate
a JSON REST service::

    from aiohttp import web

    @web.middleware
    async def error_middleware(request, handler):
        try:
            response = await handler(request)
            if response.status != 404:
                return response
            message = response.message
        except web.HTTPException as ex:
            if ex.status != 404:
                raise
            message = ex.reason
        return web.json_response({'error': message})

    app = web.Application(middlewares=[error_middleware])


Old Style Middleware
^^^^^^^^^^^^^^^^^^^^

.. deprecated:: 2.3

   Prior to *v2.3* middleware required an outer *middleware factory*
   which returned the middleware coroutine. Since *v2.3* this is not
   required; instead the ``@middleware`` decorator should
   be used.

Old style middleware (with an outer factory and no ``@middleware``
decorator) is still supported. Furthermore, old and new style middleware
can be mixed.

A *middleware factory* is simply a coroutine that implements the logic of a
*middleware*. For example, here's a trivial *middleware factory*::

    async def middleware_factory(app, handler):
        async def middleware_handler(request):
            resp = await handler(request)
            resp.text = resp.text + ' wink'
            return resp
        return middleware_handler

A *middleware factory* should accept two parameters, an
:class:`app <Application>` instance and a *handler*, and return a new handler.

.. note::

   Both the outer *middleware_factory* coroutine and the inner
   *middleware_handler* coroutine are called for every request handled.

*Middleware factories* should return a new handler that has the same signature
as a :ref:`request handler <aiohttp-web-handler>`. That is, it should accept a
single :class:`Request` instance and return a :class:`Response`, or raise an
exception.

.. _aiohttp-web-signals:

Signals
-------

Although :ref:`middlewares <aiohttp-web-middlewares>` can customize
:ref:`request handlers<aiohttp-web-handler>` before or after a :class:`Response`
has been prepared, they can't customize a :class:`Response` **while** it's
being prepared. For this :mod:`aiohttp.web` provides *signals*.

For example, a middleware can only change HTTP headers for *unprepared*
responses (see :meth:`~aiohttp.web.StreamResponse.prepare`), but sometimes we
need a hook for changing HTTP headers for streamed responses and WebSockets.
This can be accomplished by subscribing to the
:attr:`~aiohttp.web.Application.on_response_prepare` signal::

    async def on_prepare(request, response):
        response.headers['My-Header'] = 'value'

    app.on_response_prepare.append(on_prepare)


Additionally, the :attr:`~aiohttp.web.Application.on_startup` and
:attr:`~aiohttp.web.Application.on_cleanup` signals can be subscribed to for
application component setup and tear down accordingly.

The following example will properly initialize and dispose an aiopg connection
engine::

    from aiopg.sa import create_engine

    async def create_aiopg(app):
        app['pg_engine'] = await create_engine(
            user='postgre',
            database='postgre',
            host='localhost',
            port=5432,
            password=''
        )

    async def dispose_aiopg(app):
        app['pg_engine'].close()
        await app['pg_engine'].wait_closed()

    app.on_startup.append(create_aiopg)
    app.on_cleanup.append(dispose_aiopg)


Signal handlers should not return a value but may modify incoming mutable
parameters.

Signal handlers will be run sequentially, in order they were added. If handler
is asynchronous, it will be awaited before calling next one.

.. warning::

   Signals API has provisional status, meaning it may be changed in future
   releases.

   Signal subscription and sending will most likely be the same, but signal
   object creation is subject to change. As long as you are not creating new
   signals, but simply reusing existing ones, you will not be affected.

.. _aiohttp-web-nested-applications:

Nested applications
-------------------

Sub applications are designed for solving the problem of the big
monolithic code base.
Let's assume we have a project with own business logic and tools like
administration panel and debug toolbar.

Administration panel is a separate application by its own nature but all
toolbar URLs are served by prefix like ``/admin``.

Thus we'll create a totally separate application named ``admin`` and
connect it to main app with prefix by
:meth:`~aiohttp.web.Application.add_subapp`::

   admin = web.Application()
   # setup admin routes, signals and middlewares

   app.add_subapp('/admin/', admin)

Middlewares and signals from ``app`` and ``admin`` are chained.

It means that if URL is ``'/admin/something'`` middlewares from
``app`` are applied first and ``admin.middlewares`` are the next in
the call chain.

The same is going for
:attr:`~aiohttp.web.Application.on_response_prepare` signal -- the
signal is delivered to both top level ``app`` and ``admin`` if
processing URL is routed to ``admin`` sub-application.

Common signals like :attr:`~aiohttp.web.Application.on_startup`,
:attr:`~aiohttp.web.Application.on_shutdown` and
:attr:`~aiohttp.web.Application.on_cleanup` are delivered to all
registered sub-applications. The passed parameter is sub-application
instance, not top-level application.


Third level sub-applications can be nested into second level ones --
there are no limitation for nesting level.

Url reversing for sub-applications should generate urls with proper prefix.

But for getting URL sub-application's router should be used::

   admin = web.Application()
   admin.router.add_get('/resource', handler, name='name')

   app.add_subapp('/admin/', admin)

   url = admin.router['name'].url_for()

The generated ``url`` from example will have a value
``URL('/admin/resource')``.

If main application should do URL reversing for sub-application it could
use the following explicit technique::

   admin = web.Application()
   admin.router.add_get('/resource', handler, name='name')

   app.add_subapp('/admin/', admin)
   app['admin'] = admin

   async def handler(request):  # main application's handler
       admin = request.app['admin']
       url = admin.router['name'].url_for()

.. _aiohttp-web-expect-header:

*Expect* Header
---------------

:mod:`aiohttp.web` supports *Expect* header. By default it sends
``HTTP/1.1 100 Continue`` line to client, or raises
:exc:`HTTPExpectationFailed` if header value is not equal to
"100-continue". It is possible to specify custom *Expect* header
handler on per route basis. This handler gets called if *Expect*
header exist in request after receiving all headers and before
processing application's :ref:`aiohttp-web-middlewares` and
route handler. Handler can return *None*, in that case the request
processing continues as usual. If handler returns an instance of class
:class:`StreamResponse`, *request handler* uses it as response. Also
handler can raise a subclass of :exc:`HTTPException`. In this case all
further processing will not happen and client will receive appropriate
http response.

.. note::
    A server that does not understand or is unable to comply with any of the
    expectation values in the Expect field of a request MUST respond with
    appropriate error status. The server MUST respond with a 417
    (Expectation Failed) status if any of the expectations cannot be met or,
    if there are other problems with the request, some other 4xx status.

    http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.20

If all checks pass, the custom handler *must* write a *HTTP/1.1 100 Continue*
status code before returning.

The following example shows how to setup a custom handler for the *Expect*
header::

   async def check_auth(request):
       if request.version != aiohttp.HttpVersion11:
           return

       if request.headers.get('EXPECT') != '100-continue':
           raise HTTPExpectationFailed(text="Unknown Expect: %s" % expect)

       if request.headers.get('AUTHORIZATION') is None:
           raise HTTPForbidden()

       request.transport.write(b"HTTP/1.1 100 Continue\r\n\r\n")

   async def hello(request):
       return web.Response(body=b"Hello, world")

   app = web.Application()
   app.router.add_get('/', hello, expect_handler=check_auth)

.. _aiohttp-web-custom-resource:

Custom resource implementation
------------------------------

To register custom resource use :meth:`UrlDispatcher.register_resource`.
Resource instance must implement `AbstractResource` interface.

.. _aiohttp-web-app-runners:

Application runners
-------------------

:func:`run_app` provides a simple *blocking* API for running an
:class:`Application`.

For starting the application *asynchronously* on serving on multiple
HOST/PORT :class:`AppRunner` exists.

The simple startup code for serving HTTP site on ``'localhost'``, port
``8080`` looks like::

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, 'localhost', 8080)
    await site.start()

To stop serving call :meth:`AppRunner.cleanup`::

    await runner.cleanup()

.. versionadded:: 3.0

.. _aiohttp-web-graceful-shutdown:

Graceful shutdown
------------------

Stopping *aiohttp web server* by just closing all connections is not
always satisfactory.

The problem is: if application supports :term:`websocket`\s or *data
streaming* it most likely has open connections at server
shutdown time.

The *library* has no knowledge how to close them gracefully but
developer can help by registering :attr:`Application.on_shutdown`
signal handler and call the signal on *web server* closing.

Developer should keep a list of opened connections
(:class:`Application` is a good candidate).

The following :term:`websocket` snippet shows an example for websocket
handler::

    app = web.Application()
    app['websockets'] = []

    async def websocket_handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        request.app['websockets'].append(ws)
        try:
            async for msg in ws:
                ...
        finally:
            request.app['websockets'].remove(ws)

        return ws

Signal handler may look like::

    async def on_shutdown(app):
        for ws in app['websockets']:
            await ws.close(code=WSCloseCode.GOING_AWAY,
                           message='Server shutdown')

    app.on_shutdown.append(on_shutdown)

Both :func:`run_app` and :meth:`AppRunner.cleanup` call shutdown
signal handlers.

.. _aiohttp-web-background-tasks:

Background tasks
-----------------

Sometimes there's a need to perform some asynchronous operations just
after application start-up.

Even more, in some sophisticated systems there could be a need to run some
background tasks in the event loop along with the application's request
handler. Such as listening to message queue or other network message/event
sources (e.g. ZeroMQ, Redis Pub/Sub, AMQP, etc.) to react to received messages
within the application.

For example the background task could listen to ZeroMQ on
:data:`zmq.SUB` socket, process and forward retrieved messages to
clients connected via WebSocket that are stored somewhere in the
application (e.g. in the :obj:`application['websockets']` list).

To run such short and long running background tasks aiohttp provides an
ability to register :attr:`Application.on_startup` signal handler(s) that
will run along with the application's request handler.

For example there's a need to run one quick task and two long running
tasks that will live till the application is alive. The appropriate
background tasks could be registered as an :attr:`Application.on_startup`
signal handlers as shown in the example below::


  async def listen_to_redis(app):
      try:
          sub = await aioredis.create_redis(('localhost', 6379), loop=app.loop)
          ch, *_ = await sub.subscribe('news')
          async for msg in ch.iter(encoding='utf-8'):
              # Forward message to all connected websockets:
              for ws in app['websockets']:
                  ws.send_str('{}: {}'.format(ch.name, msg))
      except asyncio.CancelledError:
          pass
      finally:
          await sub.unsubscribe(ch.name)
          await sub.quit()


  async def start_background_tasks(app):
      app['redis_listener'] = app.loop.create_task(listen_to_redis(app))


  async def cleanup_background_tasks(app):
      app['redis_listener'].cancel()
      await app['redis_listener']


  app = web.Application()
  app.on_startup.append(start_background_tasks)
  app.on_cleanup.append(cleanup_background_tasks)
  web.run_app(app)


The task :func:`listen_to_redis` will run forever.
To shut it down correctly :attr:`Application.on_cleanup` signal handler
may be used to send a cancellation to it.

Handling error pages
--------------------

Pages like *404 Not Found* and *500 Internal Error* could be handled
by custom middleware, see :ref:`aiohttp-tutorial-middlewares` for
details.

.. _aiohttp-web-forwarded-support:

Deploying behind a Proxy
------------------------

As discussed in :ref:`aiohttp-deployment` the preferable way is
deploying *aiohttp* web server behind a *Reverse Proxy Server* like
:term:`nginx` for production usage.

In this way properties like :attr:`~BaseRequest.scheme`
:attr:`~BaseRequest.host` and :attr:`~BaseRequest.remote` are
incorrect.

Real values should be given from proxy server, usually either
``Forwarded`` or old-fashion ``X-Forwarded-For``,
``X-Forwarded-Host``, ``X-Forwarded-Proto`` HTTP headers are used.

*aiohttp* does not take *forwarded* headers into account by default
because it produces *security issue*: HTTP client might add these
headers too, pushing non-trusted data values.

That's why *aiohttp server* should setup *forwarded* headers in custom
middleware in tight conjunction with *reverse proxy configuration*.

For changing :attr:`~BaseRequest.scheme` :attr:`~BaseRequest.host` and
:attr:`~BaseRequest.remote` the middleware might use
:meth:`~BaseRequest.clone`.

.. seealso::

   https://github.com/aio-libs/aiohttp-remotes provides secure helpers
   for modifying *scheme*, *host* and *remote* attributes according
   to ``Forwarded`` and ``X-Forwarded-*`` HTTP headers.

Swagger support
---------------

`aiohttp-swagger <https://github.com/cr0hn/aiohttp-swagger>`_ is a
library that allow to add Swagger documentation and embed the
Swagger-UI into your :mod:`aiohttp.web` project.

CORS support
------------

:mod:`aiohttp.web` itself does not support `Cross-Origin Resource
Sharing <https://en.wikipedia.org/wiki/Cross-origin_resource_sharing>`_, but
there is an aiohttp plugin for it:
`aiohttp_cors <https://github.com/aio-libs/aiohttp_cors>`_.


Debug Toolbar
-------------

`aiohttp-debugtoolbar`_ is a very useful library that provides a
debugging toolbar while you're developing an :mod:`aiohttp.web`
application.

Install it via ``pip``:

.. code-block:: shell

    $ pip install aiohttp_debugtoolbar


After that attach the :mod:`aiohttp_debugtoolbar` middleware to your
:class:`aiohttp.web.Application` and call :func:`aiohttp_debugtoolbar.setup`::

    import aiohttp_debugtoolbar
    from aiohttp_debugtoolbar import toolbar_middleware_factory

    app = web.Application(middlewares=[toolbar_middleware_factory])
    aiohttp_debugtoolbar.setup(app)

The toolbar is ready to use. Enjoy!!!

.. _aiohttp-debugtoolbar: https://github.com/aio-libs/aiohttp_debugtoolbar


Dev Tools
---------

`aiohttp-devtools`_ provides a couple of tools to simplify development of
:mod:`aiohttp.web` applications.


Install via ``pip``:

.. code-block:: shell

    $ pip install aiohttp-devtools

   * ``runserver`` provides a development server with auto-reload,
  live-reload, static file serving and aiohttp_debugtoolbar_
  integration.
   * ``start`` is a `cookiecutter command which does the donkey work
  of creating new :mod:`aiohttp.web` Applications.

Documentation and a complete tutorial of creating and running an app
locally are available at `aiohttp-devtools`_.

.. _aiohttp-devtools: https://github.com/aio-libs/aiohttp-devtools
