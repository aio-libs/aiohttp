.. _aiohttp-web-advanced:

Web Server Advanced
===================

.. currentmodule:: aiohttp.web


Unicode support
---------------

*aiohttp* does :term:`requoting` of incoming request path.

Unicode (non-ASCII) symbols are processed transparently on both *route
adding* and *resolving* (internally everything is converted to
:term:`percent-encoding` form by :term:`yarl` library).

But in case of custom regular expressions for
:ref:`aiohttp-web-variable-handler` please take care that URL is
*percent encoded*: if you pass Unicode patterns they don't match to
*requoted* path.

Peer disconnection
------------------

When a client peer is gone a subsequent reading or writing raises :exc:`OSError`
or more specific exception like :exc:`ConnectionResetError`.

The reason for disconnection is vary; it can be a network issue or explicit
socket closing on the peer side without reading the whole server response.

*aiohttp* handles disconnection properly but you can handle it explicitly, e.g.::

   async def handler(request):
       try:
           text = await request.text()
       except OSError:
           # disconnected

Passing a coroutine into run_app and Gunicorn
---------------------------------------------

:func:`run_app` accepts either application instance or a coroutine for
making an application. The coroutine based approach allows to perform
async IO before making an app::

   async def app_factory():
       await pre_init()
       app = web.Application()
       app.router.add_get(...)
       return app

   web.run_app(app_factory())

Gunicorn worker supports a factory as well. For Gunicorn the factory
should accept zero parameters::

   async def my_web_app():
       app = web.Application()
       app.router.add_get(...)
       return app

Start gunicorn:

.. code-block:: shell

   $ gunicorn my_app_module:my_web_app --bind localhost:8080 --worker-class aiohttp.GunicornWebWorker

.. versionadded:: 3.1

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
   app.add_routes([web.get('/', chooser.do_route)])

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
:meth:`RouteTableDef.static` or :func:`static` calls::

   app.add_routes([web.static('/prefix', path_to_static_folder)])

   routes.static('/prefix', path_to_static_folder)

When a directory is accessed within a static route then the server responses
to client with ``HTTP/403 Forbidden`` by default. Displaying folder index
instead could be enabled with ``show_index`` parameter set to ``True``::

   web.static('/prefix', path_to_static_folder, show_index=True)

When a symlink from the static directory is accessed, the server responses to
client with ``HTTP/404 Not Found`` by default. To allow the server to follow
symlinks, parameter ``follow_symlinks`` should be set to ``True``::

   web.static('/prefix', path_to_static_folder, follow_symlinks=True)

When you want to enable cache busting,
parameter ``append_version`` can be set to ``True``

Cache busting is the process of appending some form of file version hash
to the filename of resources like JavaScript and CSS files.
The performance advantage of doing this is that we can tell the browser
to cache these files indefinitely without worrying about the client not getting
the latest version when the file changes::

   web.static('/prefix', path_to_static_folder, append_version=True)

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
    async def handler(request):
        return {'name': 'Andrew', 'surname': 'Svetlov'}

If you prefer the `Mako`_ template engine, please take a look at the
`aiohttp_mako`_ library.

.. warning::

   :func:`aiohttp_jinja2.template` should be applied **before**
   :meth:`RouteTableDef.get` decorator and family, e.g. it must be
   the *first* (most *down* decorator in the chain)::


      @routes.get('/path')
      @aiohttp_jinja2.template('tmpl.jinja2')
      async def handler(request):
          return {'name': 'Andrew', 'surname': 'Svetlov'}


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
   possibility to call :meth:`WebSocketResponse.receive`
   from two tasks.

   See :ref:`FAQ section <aiohttp_faq_parallel_event_sources>` for
   instructions how to solve the problem.


.. _aiohttp-web-data-sharing:

Data Sharing aka No Singletons Please
-------------------------------------

:mod:`aiohttp.web` discourages the use of *global variables*, aka *singletons*.
Every variable should have its own context that is *not global*.

Global variables are generally considered bad practice due to the complexity
they add in keeping track of state changes to variables.

*aiohttp* does not use globals by design, which will reduce the number of bugs
and/or unexpected behaviors for its users. For example, an i18n translated string
being written for one request and then being served to another.

So, :class:`Application` and :class:`Request`
support a :class:`collections.abc.MutableMapping` interface (i.e. they are
dict-like objects), allowing them to be used as data stores.


.. _aiohttp-web-data-sharing-app-config:

Application's config
^^^^^^^^^^^^^^^^^^^^

For storing *global-like* variables, feel free to save them in an
:class:`Application` instance::

    app['my_private_key'] = data

and get it back in the :term:`web-handler`::

    async def handler(request):
        data = request.app['my_private_key']

Rather than using :class:`str` keys, we recommend using :class:`AppKey`.
This is required for type safety (e.g. when checking with mypy)::

    my_private_key = web.AppKey("my_private_key", str)
    app[my_private_key] = data

    async def handler(request: web.Request):
        data = request.app[my_private_key]
        # reveal_type(data) -> str

In case of :ref:`nested applications
<aiohttp-web-nested-applications>` the desired lookup strategy could
be the following:

1. Search the key in the current nested application.
2. If the key is not found continue searching in the parent application(s).

For this please use :attr:`Request.config_dict` read-only property::

    async def handler(request):
        data = request.config_dict[my_private_key]

The app object can be used in this way to reuse a database connection or anything
else needed throughout the application.

See this reference section for more detail: :ref:`aiohttp-web-app-and-router`.

Request's storage
^^^^^^^^^^^^^^^^^

Variables that are only needed for the lifetime of a :class:`Request`, can be
stored in a :class:`Request`::

    async def handler(request):
      request['my_private_key'] = "data"
      ...

This is mostly useful for :ref:`aiohttp-web-middlewares` and
:ref:`aiohttp-web-signals` handlers to store data for further processing by the
next handlers in the chain.

Response's storage
^^^^^^^^^^^^^^^^^^

:class:`StreamResponse` and :class:`Response` objects
also support :class:`collections.abc.MutableMapping` interface. This is useful
when you want to share data with signals and middlewares once all the work in
the handler is done::

    async def handler(request):
      [ do all the work ]
      response['my_metric'] = 123
      return response


Naming hint
^^^^^^^^^^^

To avoid clashing with other *aiohttp* users and third-party libraries, please
choose a unique key name for storing data.

If your code is published on PyPI, then the project name is most likely unique
and safe to use as the key.
Otherwise, something based on your company name/url would be satisfactory (i.e.
``org.company.app``).


.. _aiohttp-web-contextvars:


ContextVars support
-------------------

Asyncio has :mod:`Context Variables <contextvars>` as a context-local storage
(a generalization of thread-local concept that works with asyncio tasks also).


*aiohttp* server supports it in the following way:

* A server inherits the current task's context used when creating it.
  :func:`aiohttp.web.run_app()` runs a task for handling all underlying jobs running
  the app, but alternatively :ref:`aiohttp-web-app-runners` can be used.

* Application initialization / finalization events (:attr:`Application.cleanup_ctx`,
  :attr:`Application.on_startup` and :attr:`Application.on_shutdown`,
  :attr:`Application.on_cleanup`) are executed inside the same context.

  E.g. all context modifications made on application startup are visible on teardown.

* On every request handling *aiohttp* creates a context copy. :term:`web-handler` has
  all variables installed on initialization stage. But the context modification made by
  a handler or middleware is invisible to another HTTP request handling call.

An example of context vars usage::

    from contextvars import ContextVar

    from aiohttp import web

    VAR = ContextVar('VAR', default='default')


    async def coro():
        return VAR.get()


    async def handler(request):
        var = VAR.get()
        VAR.set('handler')
        ret = await coro()
        return web.Response(text='\n'.join([var,
                                            ret]))


    async def on_startup(app):
        print('on_startup', VAR.get())
        VAR.set('on_startup')


    async def on_cleanup(app):
        print('on_cleanup', VAR.get())
        VAR.set('on_cleanup')


    async def init():
        print('init', VAR.get())
        VAR.set('init')
        app = web.Application()
        app.router.add_get('/', handler)

        app.on_startup.append(on_startup)
        app.on_cleanup.append(on_cleanup)
        return app


    web.run_app(init())
    print('done', VAR.get())

.. versionadded:: 3.5


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

.. note::

   The example won't work with streamed responses or websockets

Every *middleware* should accept two parameters, a :class:`request
<Request>` instance and a *handler*, and return the response or raise
an exception. If the exception is not an instance of
:exc:`HTTPException` it is converted to ``500``
:exc:`HTTPInternalServerError` after processing the
middlewares chain.

.. warning::

   Second argument should be named *handler* exactly.

When creating an :class:`Application`, these *middlewares* are passed to
the keyword-only ``middlewares`` parameter::

   app = web.Application(middlewares=[middleware_1,
                                      middleware_2])

Internally, a single :ref:`request handler <aiohttp-web-handler>` is constructed
by applying the middleware chain to the original handler in reverse order,
and is called by the :class:`~aiohttp.web.RequestHandler` as a regular *handler*.

Since *middlewares* are themselves coroutines, they may perform extra
``await`` calls when creating a new handler, e.g. call database etc.

*Middlewares* usually call the handler, but they may choose to ignore it,
e.g. displaying *403 Forbidden page* or raising :exc:`HTTPForbidden` exception
if the user does not have permissions to access the underlying resource.
They may also render errors raised by the handler, perform some pre- or
post-processing like handling *CORS* and so on.

The following code demonstrates middlewares execution order::

   from aiohttp import web

   async def test(request):
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


Middleware Factory
^^^^^^^^^^^^^^^^^^

A *middleware factory* is a function that creates a middleware with passed arguments. For example, here's a trivial *middleware factory*::

    def middleware_factory(text):
        @middleware
        async def sample_middleware(request, handler):
            resp = await handler(request)
            resp.text = resp.text + text
            return resp
        return sample_middleware

Remember that contrary to regular middlewares you need the result of a middleware factory not the function itself. So when passing a middleware factory to an app you actually need to call it::

    app = web.Application(middlewares=[middleware_factory(' wink')])

.. _aiohttp-web-signals:

Signals
-------

Although :ref:`middlewares <aiohttp-web-middlewares>` can customize
:ref:`request handlers<aiohttp-web-handler>` before or after a :class:`Response`
has been prepared, they can't customize a :class:`Response` **while** it's
being prepared. For this :mod:`aiohttp.web` provides *signals*.

For example, a middleware can only change HTTP headers for *unprepared*
responses (see :meth:`StreamResponse.prepare`), but sometimes we
need a hook for changing HTTP headers for streamed responses and WebSockets.
This can be accomplished by subscribing to the
:attr:`Application.on_response_prepare` signal, which is called after default
headers have been computed and directly before headers are sent::

    async def on_prepare(request, response):
        response.headers['My-Header'] = 'value'

    app.on_response_prepare.append(on_prepare)


Additionally, the :attr:`Application.on_startup` and
:attr:`Application.on_cleanup` signals can be subscribed to for
application component setup and tear down accordingly.

The following example will properly initialize and dispose an asyncpg connection
engine::

    from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

    pg_engine = web.AppKey("pg_engine", AsyncEngine)

    async def create_pg(app):
        app[pg_engine] = await create_async_engine(
            "postgresql+asyncpg://postgre:@localhost:5432/postgre"
        )

    async def dispose_pg(app):
        await app[pg_engine].dispose()

    app.on_startup.append(create_pg)
    app.on_cleanup.append(dispose_pg)


Signal handlers should not return a value but may modify incoming mutable
parameters.

Signal handlers will be run sequentially, in order they were
added. All handlers must be asynchronous since *aiohttp* 3.0.

.. _aiohttp-web-cleanup-ctx:

Cleanup Context
---------------

Bare :attr:`Application.on_startup` / :attr:`Application.on_cleanup`
pair still has a pitfall: signals handlers are independent on each other.

E.g. we have ``[create_pg, create_redis]`` in *startup* signal and
``[dispose_pg, dispose_redis]`` in *cleanup*.

If, for example, ``create_pg(app)`` call fails ``create_redis(app)``
is not called. But on application cleanup both ``dispose_pg(app)`` and
``dispose_redis(app)`` are still called: *cleanup signal* has no
knowledge about startup/cleanup pairs and their execution state.


The solution is :attr:`Application.cleanup_ctx` usage::

    async def pg_engine(app: web.Application):
        app[pg_engine] = await create_async_engine(
            "postgresql+asyncpg://postgre:@localhost:5432/postgre"
        )
        yield
        await app[pg_engine].dispose()

    app.cleanup_ctx.append(pg_engine)

The attribute is a list of *asynchronous generators*, a code *before*
``yield`` is an initialization stage (called on *startup*), a code
*after* ``yield`` is executed on *cleanup*. The generator must have only
one ``yield``.

*aiohttp* guarantees that *cleanup code* is called if and only if
*startup code* was successfully finished.

Asynchronous generators are supported by Python 3.6+, on Python 3.5
please use `async_generator <https://pypi.org/project/async_generator/>`_
library.

.. versionadded:: 3.1

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
:meth:`Application.add_subapp`::

   admin = web.Application()
   # setup admin routes, signals and middlewares

   app.add_subapp('/admin/', admin)

Middlewares and signals from ``app`` and ``admin`` are chained.

It means that if URL is ``'/admin/something'`` middlewares from
``app`` are applied first and ``admin.middlewares`` are the next in
the call chain.

The same is going for
:attr:`Application.on_response_prepare` signal -- the
signal is delivered to both top level ``app`` and ``admin`` if
processing URL is routed to ``admin`` sub-application.

Common signals like :attr:`Application.on_startup`,
:attr:`Application.on_shutdown` and
:attr:`Application.on_cleanup` are delivered to all
registered sub-applications. The passed parameter is sub-application
instance, not top-level application.


Third level sub-applications can be nested into second level ones --
there are no limitation for nesting level.

Url reversing for sub-applications should generate urls with proper prefix.

But for getting URL sub-application's router should be used::

   admin = web.Application()
   admin.add_routes([web.get('/resource', handler, name='name')])

   app.add_subapp('/admin/', admin)

   url = admin.router['name'].url_for()

The generated ``url`` from example will have a value
``URL('/admin/resource')``.

If main application should do URL reversing for sub-application it could
use the following explicit technique::

   admin = web.Application()
   admin_key = web.AppKey('admin_key', web.Application)
   admin.add_routes([web.get('/resource', handler, name='name')])

   app.add_subapp('/admin/', admin)
   app[admin_key] = admin

   async def handler(request: web.Request):  # main application's handler
       admin = request.app[admin_key]
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
   app.add_routes([web.add_get('/', hello, expect_handler=check_auth)])

.. _aiohttp-web-custom-resource:

Custom resource implementation
------------------------------

To register custom resource use :meth:`~aiohttp.web.UrlDispatcher.register_resource`.
Resource instance must implement `AbstractResource` interface.

.. _aiohttp-web-app-runners:

Application runners
-------------------

:func:`run_app` provides a simple *blocking* API for running an
:class:`Application`.

For starting the application *asynchronously* or serving on multiple
HOST/PORT :class:`AppRunner` exists.

The simple startup code for serving HTTP site on ``'localhost'``, port
``8080`` looks like::

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, 'localhost', 8080)
    await site.start()

    while True:
        await asyncio.sleep(3600)  # sleep forever

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

    from aiohttp import web
    import weakref

    app = web.Application()
    websockets = web.AppKey("websockets", weakref.WeakSet)
    app[websockets] = weakref.WeakSet()

    async def websocket_handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        request.app[websockets].add(ws)
        try:
            async for msg in ws:
                ...
        finally:
            request.app[websockets].discard(ws)

        return ws

Signal handler may look like::

    from aiohttp import WSCloseCode

    async def on_shutdown(app):
        for ws in set(app[websockets]):
            await ws.close(code=WSCloseCode.GOING_AWAY,
                           message='Server shutdown')

    app.on_shutdown.append(on_shutdown)

Both :func:`run_app` and :meth:`AppRunner.cleanup` call shutdown
signal handlers.

.. _aiohttp-web-ceil-absolute-timeout:

Ceil of absolute timeout value
------------------------------

*aiohttp* **ceils** internal timeout values if the value is equal or
greater than 5 seconds. The timeout expires at the next integer second
greater than ``current_time + timeout``.

More details about ceiling absolute timeout values is available here
:ref:`aiohttp-client-timeouts`.

The default threshold can be configured at :class:`aiohttp.web.Application`
level using the ``handler_args`` parameter.

.. code-block:: python3

    app = web.Application(handler_args={"timeout_ceil_threshold": 1})

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
``zmq.SUB`` socket, process and forward retrieved messages to
clients connected via WebSocket that are stored somewhere in the
application (e.g. in the ``application['websockets']`` list).

To run such short and long running background tasks aiohttp provides an
ability to register :attr:`Application.on_startup` signal handler(s) that
will run along with the application's request handler.

For example there's a need to run one quick task and two long running
tasks that will live till the application is alive. The appropriate
background tasks could be registered as an :attr:`Application.on_startup`
signal handler or :attr:`Application.cleanup_ctx` as shown in the example
below::


  async def listen_to_redis(app):
      try:
          sub = await aioredis.create_redis(('localhost', 6379))
          ch, *_ = await sub.subscribe('news')
          async for msg in ch.iter(encoding='utf-8'):
              # Forward message to all connected websockets:
              for ws in app[websockets]:
                  ws.send_str('{}: {}'.format(ch.name, msg))
      except asyncio.CancelledError:
          pass
      finally:
          await sub.unsubscribe(ch.name)
          await sub.quit()


  async def background_tasks(app):
      app[redis_listener] = asyncio.create_task(listen_to_redis(app))

      yield

      app[redis_listener].cancel()
      await app[redis_listener]


  app = web.Application()
  redis_listener = web.AppKey("redis_listener", asyncio.Task[None])
  app.cleanup_ctx.append(background_tasks)
  web.run_app(app)


The task ``listen_to_redis`` will run forever.
To shut it down correctly :attr:`Application.on_cleanup` signal handler
may be used to send a cancellation to it.

.. _aiohttp-web-complex-applications:

Complex Applications
^^^^^^^^^^^^^^^^^^^^

Sometimes aiohttp is not the sole part of an application and additional
tasks/processes may need to be run alongside the aiohttp :class:`Application`.

Generally, the best way to achieve this is to use :func:`aiohttp.web.run_app`
as the entry point for the program. Other tasks can then be run via
:attr:`Application.startup` and :attr:`Application.on_cleanup`. By having the
:class:`Application` control the lifecycle of the entire program, the code
will be more robust and ensure that the tasks are started and stopped along
with the application.

For example, running a long-lived task alongside the :class:`Application`
can be done with a :ref:`aiohttp-web-cleanup-ctx` function like::


  async def run_other_task(_app):
      task = asyncio.create_task(other_long_task())

      yield

      task.cancel()
      with suppress(asyncio.CancelledError):
          await task  # Ensure any exceptions etc. are raised.

  app.cleanup_ctx.append(run_other_task)


Or a separate process can be run with something like::


  async def run_process(_app):
      proc = await asyncio.create_subprocess_exec(path)

      yield

      if proc.returncode is None:
          proc.terminate()
      await proc.wait()

  app.cleanup_ctx.append(run_process)


Handling error pages
--------------------

Pages like *404 Not Found* and *500 Internal Error* could be handled
by custom middleware, see :ref:`polls demo <aiohttp-demos-polls-middlewares>`
for example.

.. _aiohttp-web-forwarded-support:

Deploying behind a Proxy
------------------------

As discussed in :ref:`aiohttp-deployment` the preferable way is
deploying *aiohttp* web server behind a *Reverse Proxy Server* like
:term:`nginx` for production usage.

In this way properties like :attr:`BaseRequest.scheme`
:attr:`BaseRequest.host` and :attr:`BaseRequest.remote` are
incorrect.

Real values should be given from proxy server, usually either
``Forwarded`` or old-fashion ``X-Forwarded-For``,
``X-Forwarded-Host``, ``X-Forwarded-Proto`` HTTP headers are used.

*aiohttp* does not take *forwarded* headers into account by default
because it produces *security issue*: HTTP client might add these
headers too, pushing non-trusted data values.

That's why *aiohttp server* should setup *forwarded* headers in custom
middleware in tight conjunction with *reverse proxy configuration*.

For changing :attr:`BaseRequest.scheme` :attr:`BaseRequest.host`
:attr:`BaseRequest.remote` and :attr:`BaseRequest.client_max_size`
the middleware might use :meth:`BaseRequest.clone`.

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

Install it with ``pip``:

.. code-block:: shell

    $ pip install aiohttp_debugtoolbar


Just call :func:`aiohttp_debugtoolbar.setup`::

    import aiohttp_debugtoolbar
    from aiohttp_debugtoolbar import toolbar_middleware_factory

    app = web.Application()
    aiohttp_debugtoolbar.setup(app)

The toolbar is ready to use. Enjoy!!!

.. _aiohttp-debugtoolbar: https://github.com/aio-libs/aiohttp_debugtoolbar


Dev Tools
---------

`aiohttp-devtools`_ provides a couple of tools to simplify development of
:mod:`aiohttp.web` applications.


Install with ``pip``:

.. code-block:: shell

    $ pip install aiohttp-devtools

* ``runserver`` provides a development server with auto-reload,
  live-reload, static file serving.
* ``start`` is a `cookiecutter command which does the donkey work
  of creating new :mod:`aiohttp.web` Applications.

Documentation and a complete tutorial of creating and running an app
locally are available at `aiohttp-devtools`_.

.. _aiohttp-devtools: https://github.com/aio-libs/aiohttp-devtools
