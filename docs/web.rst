.. _aiohttp-web:

HTTP Server Usage
=================

.. currentmodule:: aiohttp.web

.. versionchanged:: 0.12
   :mod:`aiohttp.web` was deeply refactored making it backwards incompatible.


Run a Simple Web Server
-----------------------

In order to implement a web server, first create a
:ref:`request handler <aiohttp-web-handler>`.

A request handler is a :ref:`coroutine <coroutine>` or regular function that
accepts a :class:`Request` instance as its only parameter and returns a
:class:`Response` instance::

   import asyncio
   from aiohttp import web

   async def hello(request):
       return web.Response(body=b"Hello, world")

Next, create an :class:`Application` instance and register the
request handler with the application's :class:`router <UrlDispatcher>` on a
particular *HTTP method* and *path*::

   app = web.Application()
   app.router.add_route('GET', '/', hello)

After that, create a server and run the *asyncio loop* as usual::

   loop = asyncio.get_event_loop()
   handler = app.make_handler()
   f = loop.create_server(handler, '0.0.0.0', 8080)
   srv = loop.run_until_complete(f)
   print('serving on', srv.sockets[0].getsockname())
   try:
       loop.run_forever()
   except KeyboardInterrupt:
       pass
   finally:
       srv.close()
       loop.run_until_complete(srv.wait_closed())
       loop.run_until_complete(handler.finish_connections(1.0))
       loop.run_until_complete(app.finish())
   loop.close()

That's it. Now, head over to ``http://localhost:8080/`` to see the results.


.. _aiohttp-web-handler:

Handler
-------

A request handler can be any :term:`callable` that accepts a :class:`Request`
instance as its only argument and returns a :class:`StreamResponse` derived
(e.g. :class:`Response`) instance::

   def handler(request):
       return web.Response()

A handler **may** also be a :ref:`coroutine<coroutine>`, in which case
:mod:`aiohttp.web` will ``await`` the handler::

   async def handler(request):
       return web.Response()

Handlers are setup to handle requests by registering them with the
:attr:`Application.router` on a particular route (*HTTP method* and *path*
pair)::

   app.router.add_route('GET', '/', handler)
   app.router.add_route('POST', '/post', post_handler)
   app.router.add_route('PUT', '/put', put_handler)

:meth:`~UrlDispatcher.add_route` also supports the wildcard *HTTP method*,
allowing a handler to serve incoming requests on a *path* having **any**
*HTTP method*::

  app.router.add_route('*', '/path', all_handler)

The *HTTP method* can be queried later in the request handler using the
:attr:`Request.method` property.

.. versionadded:: 0.15.2
   Support for wildcard *HTTP method* routes.


.. _aiohttp-web-variable-handler:

Variable Routes
^^^^^^^^^^^^^^^

Handlers can also be attached to routes with *variable paths*. For instance,
a route with the path ``'/a/{name}/c'`` would match all incoming requests with
paths such as ``'/a/b/c'``, ``'/a/1/c'``, and ``'/a/etc/c'``.

A variable *part* is specified in the form ``{identifier}``, where the
``identifier`` can be used later in a
:ref:`request handler <aiohttp-web-handler>` to access the matched value for
that *part*. This is done by looking up the ``identifier`` in the
:attr:`Request.match_info` mapping::

   async def variable_handler(request):
       return web.Response(
           text="Hello, {}".format(request.match_info['name']))

   app.router.add_route('GET', '/{name}', variable_handler)

By default, each *part* matches the regular expression ``[^{}/]+``.

You can also specify a custom regex in the form ``{identifier:regex}``::

   app.router.add_route('GET', r'/{name:\d+}', variable_handler)

.. versionadded:: 0.13
   Support for custom regexs in variable routes.


.. _aiohttp-web-named-routes:

Reverse URL Constructing using Named Routes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Routes can also be given a *name*::

   app.router.add_route('GET', '/root', handler, name='root')

Which can then be used to access and build a *URL* for that route later (e.g.
in a :ref:`request handler <aiohttp-web-handler>`)::

   >>> request.app.router['root'].url(query={"a": "b", "c": "d"})
   '/root?a=b&c=d'

A more interesting example is building *URLs* for :ref:`variable
routes <aiohttp-web-variable-handler>`::

   app.router.add_route('GET', r'/{user}/info',
                        variable_handler, name='user-info')


In this case you can also pass in the *parts* of the route::

   >>> request.app.router['user-info'].url(
   ...     parts={'user': 'john_doe'},
   ...     query="?a=b")
   '/john_doe/info?a=b'


Organizing Handlers in Classes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

As discussed above, :ref:`handlers <aiohttp-web-handler>` can be first-class
functions or coroutines::

   async def hello(request):
       return web.Response(body=b"Hello, world")

   app.router.add_route('GET', '/', hello)

But sometimes it's convenient to group logically similar handlers into a Python
*class*.

Since :mod:`aiohttp.web` does not dictate any implementation details,
application developers can organize handlers in classes if they so wish::

   class Handler:

       def __init__(self):
           pass

       def handle_intro(self, request):
           return web.Response(body=b"Hello, world")

       async def handle_greeting(self, request):
           name = request.match_info.get('name', "Anonymous")
           txt = "Hello, {}".format(name)
           return web.Response(text=txt)

   handler = Handler()
   app.router.add_route('GET', '/intro', handler.handle_intro)
   app.router.add_route('GET', '/greet/{name}', handler.handle_greeting)


.. _aiohttp-web-class-based-views:

Class Based Views
^^^^^^^^^^^^^^^^^

:mod:`aiohttp.web` has support for django-style class based views.

You can derive from :class:`View` and define methods for handling http
requests::

   class MyView(web.View):
       async def get(self):
           return await get_resp(self.request)

       async def post(self):
           return await post_resp(self.request)

Handlers should be coroutines accepting self only and returning
response object as regular :term:`web-handler`. Request object can be
retrieved by :attr:`View.request` property.

After implementing the view (``MyView`` from example above) should be
registered in application's router::

   app.router.add_route('*', '/path/to', MyView)

Example will process GET and POST requests for */path/to* but raise
*405 Method not allowed* exception for unimplemented HTTP methods.

Route Views
^^^^^^^^^^^

*All* registered routes in a router can be viewed using the
:meth:`UrlDispatcher.routes` method::

   for route in app.router.routes():
       print(route)

Similarly, a *subset* of the routes that were registered with a *name* can be
viewed using the :meth:`UrlDispatcher.named_routes` method::

   for name, route in app.router.named_routes().items():
       print(name, route)



.. versionadded:: 0.18
   :meth:`UrlDispatcher.routes`

.. versionadded:: 0.19
   :meth:`UrlDispatcher.named_routes`


Custom Routing Criteria
-----------------------

Sometimes you need to register :ref:`handlers <aiohttp-web-handler>` on
more complex criteria than simply a *HTTP method* and *path* pair.

Although :class:`UrlDispatcher` does not support any extra criteria, routing
based on custom conditions can be accomplished by implementing a second layer
of routing in your application.

The following example shows custom routing based on the *HTTP Accept* header:

.. code-block:: python

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
   app.router.add_route('GET', '/', chooser.do_route)

   chooser.reg_acceptor('application/json', handle_json)
   chooser.reg_acceptor('application/xml', handle_xml)


Template Rendering
------------------

:mod:`aiohttp.web` does not support template rendering out-of-the-box.

However, there is a third-party library, :mod:`aiohttp_jinja2`, which is
supported by the *aiohttp* authors.

Using it is rather simple. First, setup a *jinja2 environment* with a call
to :func:`aiohttp_jinja2.setup`::

    app = web.Application(loop=self.loop)
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


User Sessions
-------------

Often you need a container for storing user data across requests. The concept
is usually called a *session*.

:mod:`aiohttp.web` has no built-in concept of a *session*, however, there is a
third-party library, :mod:`aiohttp_session`, that adds *session* support::

    import asyncio
    import time
    from aiohttp import web
    from aiohttp_session import get_session, session_middleware
    from aiohttp_session.cookie_storage import EncryptedCookieStorage

    async def handler(request):
        session = await get_session(request)
        session['last_visit'] = time.time()
        return web.Response(body=b'OK')

    async def init(loop):
        app = web.Application(middlewares=[session_middleware(
            EncryptedCookieStorage(b'Sixteen byte key'))])
        app.router.add_route('GET', '/', handler)
        srv = await loop.create_server(
            app.make_handler(), '0.0.0.0', 8080)
        return srv

    loop = asyncio.get_event_loop()
    loop.run_until_complete(init(loop))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass


.. _aiohttp-web-expect-header:

*Expect* Header
---------------

.. versionadded:: 0.15

By default, :mod:`aiohttp.web` simply responds with an ``HTTP/1.1 100 Continue``
status code whenever a requests contains an *Expect* header; however, it is
possible to specify a custom *Expect* handler on a per route basis.

This handler gets called **after** receiving the request headers, but **before**
calling application :ref:`middlewares <aiohttp-web-middlewares>`, or route
:ref:`handlers <aiohttp-web-handler>`.

The *Expect* handler *may* return *None*, in which case the request processing
continues as usual. If the handler returns an instance of
class :class:`StreamResponse`, the *request handler* uses it as the response.

If all checks pass, the custom handler *must* write a *HTTP/1.1 100 Continue*
status code before returning.

The following example shows how to setup a custom handler for the *Expect*
header:

.. code-block:: python

   async def check_auth(request):
       if request.version != aiohttp.HttpVersion11:
           return

       if request.headers.get('AUTHORIZATION') is None:
           return web.HTTPForbidden()

       request.transport.write(b"HTTP/1.1 100 Continue\r\n\r\n")

   async def hello(request):
       return web.Response(body=b"Hello, world")

   app = web.Application()
   app.router.add_route('GET', '/', hello, expect_handler=check_auth)


.. _aiohttp-web-file-upload:

File Uploads
------------

:mod:`aiohttp.web` has built-in support for handling files uploaded from the
browser.

First, make sure that the HTML ``<form>`` element has its *enctype* attribute
set to ``enctype="multipart/form-data"``. As an example, here is a form that
accepts a MP3 file:

.. code-block:: html

   <form action="/store/mp3" method="post" accept-charset="utf-8"
         enctype="multipart/form-data">

       <label for="mp3">Mp3</label>
       <input id="mp3" name="mp3" type="file" value="" />

       <input type="submit" value="submit" />
   </form>

Then, in the :ref:`request handler <aiohttp-web-handler>` you can access the
file input field as a :class:`FileField` instance. :class:`FileField` is simply
a container for the file as well as some of its metadata:

.. code-block:: python

    async def store_mp3_handler(request):

        data = await request.post()

        mp3 = data['mp3']

        # .filename contains the name of the file in string format.
        filename = mp3.filename

        # .file contains the actual file data that needs to be stored somewhere.
        mp3_file = data['mp3'].file

        content = mp3_file.read()

        return web.Response(body=content,
                            headers=MultiDict(
                                {'CONTENT-DISPOSITION': mp3_file})


.. _aiohttp-web-websockets:

WebSockets
----------

.. versionadded:: 0.14

:mod:`aiohttp.web` supports *WebSockets* out-of-the-box.

To setup a *WebSocket*, create a :class:`WebSocketResponse` in a
:ref:`request handler <aiohttp-web-handler>` and then use it to communicate
with the peer:

.. code-block:: python

    async def websocket_handler(request):

        ws = web.WebSocketResponse()
        await ws.prepare(request)

        async for msg in ws:
            if msg.tp == aiohttp.MsgType.text:
                if msg.data == 'close':
                    await ws.close()
                else:
                    ws.send_str(msg.data + '/answer')
            elif msg.tp == aiohttp.MsgType.error:
                print('ws connection closed with exception %s' %
                      ws.exception())

        print('websocket connection closed')

        return ws

Reading from the *WebSocket* (``await ws.receive()``) **must only** be
done inside the request handler coroutine; however, writing
(``ws.send_str(...)``) to the *WebSocket* may be delegated to other coroutines.

.. note::

   While :mod:`aiohttp.web` itself only supports *WebSockets* without
   downgrading to *LONG-POLLING*, etc., our team supports SockJS_, an
   aiohttp-based library for implementing SockJS-compatible server
   code.

.. _SockJS: https://github.com/aio-libs/sockjs


.. _aiohttp-web-exceptions:

Exceptions
----------

:mod:`aiohttp.web` defines a set of exceptions for every *HTTP status code*.

Each exception is a subclass of :class:`~HTTPException` and relates to a single
HTTP status code.

The exceptions are also a subclass of :class:`Response`, allowing you to either
``raise`` or ``return`` them in a
:ref:`request handler <aiohttp-web-handler>` for the same effect.

The following snippets are the same::

    async def handler(request):
        return aiohttp.web.HTTPFound('/redirect')

and::

    async def handler(request):
        raise aiohttp.web.HTTPFound('/redirect')


Each exception class has a status code according to :rfc:`2068`:
codes with 100-300 are not really errors; 400s are client errors,
and 500s are server errors.

HTTP Exception hierarchy chart::

   Exception
     HTTPException
       HTTPSuccessful
         * 200 - HTTPOk
         * 201 - HTTPCreated
         * 202 - HTTPAccepted
         * 203 - HTTPNonAuthoritativeInformation
         * 204 - HTTPNoContent
         * 205 - HTTPResetContent
         * 206 - HTTPPartialContent
       HTTPRedirection
         * 300 - HTTPMultipleChoices
         * 301 - HTTPMovedPermanently
         * 302 - HTTPFound
         * 303 - HTTPSeeOther
         * 304 - HTTPNotModified
         * 305 - HTTPUseProxy
         * 307 - HTTPTemporaryRedirect
         * 308 - HTTPPermanentRedirect
       HTTPError
         HTTPClientError
           * 400 - HTTPBadRequest
           * 401 - HTTPUnauthorized
           * 402 - HTTPPaymentRequired
           * 403 - HTTPForbidden
           * 404 - HTTPNotFound
           * 405 - HTTPMethodNotAllowed
           * 406 - HTTPNotAcceptable
           * 407 - HTTPProxyAuthenticationRequired
           * 408 - HTTPRequestTimeout
           * 409 - HTTPConflict
           * 410 - HTTPGone
           * 411 - HTTPLengthRequired
           * 412 - HTTPPreconditionFailed
           * 413 - HTTPRequestEntityTooLarge
           * 414 - HTTPRequestURITooLong
           * 415 - HTTPUnsupportedMediaType
           * 416 - HTTPRequestRangeNotSatisfiable
           * 417 - HTTPExpectationFailed
           * 421 - HTTPMisdirectedRequest
           * 426 - HTTPUpgradeRequired
           * 428 - HTTPPreconditionRequired
           * 429 - HTTPTooManyRequests
           * 431 - HTTPRequestHeaderFieldsTooLarge
         HTTPServerError
           * 500 - HTTPInternalServerError
           * 501 - HTTPNotImplemented
           * 502 - HTTPBadGateway
           * 503 - HTTPServiceUnavailable
           * 504 - HTTPGatewayTimeout
           * 505 - HTTPVersionNotSupported
           * 506 - HTTPVariantAlsoNegotiates
           * 510 - HTTPNotExtended
           * 511 - HTTPNetworkAuthenticationRequired

All HTTP exceptions have the same constructor signature::

    HTTPNotFound(*, headers=None, reason=None,
                 body=None, text=None, content_type=None)

If not directly specified, *headers* will be added to the *default
response headers*.

Classes :class:`HTTPMultipleChoices`, :class:`HTTPMovedPermanently`,
:class:`HTTPFound`, :class:`HTTPSeeOther`, :class:`HTTPUseProxy`,
:class:`HTTPTemporaryRedirect` have the following constructor signature::

    HTTPFound(location, *, headers=None, reason=None,
              body=None, text=None, content_type=None)

where *location* is value for *Location HTTP header*.

:class:`HTTPMethodNotAllowed` is constructed by providing the incoming
unsupported method and list of allowed methods::

    HTTPMethodNotAllowed(method, allowed_methods, *,
                         headers=None, reason=None,
                         body=None, text=None, content_type=None)


.. _aiohttp-web-data-sharing:

Data Sharing
------------

:mod:`aiohttp.web` discourages the use of *global variables*, aka *singletons*.
Every variable should have it's own context that is *not global*.

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

To avoid clashing with other *aiohttp* users and third-party libraries, please
choose a unique key name for storing data.

If your code is published on PyPI, then the project name is most likely unique
and safe to use as the key.
Otherwise, something based on your company name/url would be satisfactory (i.e
``org.company.app``).


.. _aiohttp-web-middlewares:

Middlewares
-----------

.. versionadded:: 0.13

:mod:`aiohttp.web` provides a powerful mechanism for customizing
:ref:`request handlers<aiohttp-web-handler>` via *middlewares*.

*Middlewares* are setup by providing a sequence of *middleware factories* to
the keyword-only ``middlewares`` parameter when creating an
:class:`Application`::

   app = web.Application(middlewares=[middleware_factory_1,
                                      middleware_factory_2])

A *middleware factory* is simply a coroutine that implements the logic of a
*middleware*. For example, here's a trivial *middleware factory*::

    async def middleware_factory(app, handler):
        async def middleware_handler(request):
            return await handler(request)
        return middleware_handler

Every *middleware factory* should accept two parameters, an
:class:`app <Application>` instance and a *handler*, and return a new handler.

The *handler* passed in to a *middleware factory* is the handler returned by
the **next** *middleware factory*. The last *middleware factory* always receives
the :ref:`request handler <aiohttp-web-handler>` selected by the router itself
(by :meth:`UrlDispatcher.resolve`).

*Middleware factories* should return a new handler that has the same signature
as a :ref:`request handler <aiohttp-web-handler>`. That is, it should accept a
single :class:`Response` instance and return a :class:`Response`, or raise an
exception.

Internally, a single :ref:`request handler <aiohttp-web-handler>` is constructed
by applying the middleware chain to the original handler in reverse order,
and is called by the :class:`RequestHandler` as a regular *handler*.

Since *middleware factories* are themselves coroutines, they may perform extra
``await`` calls when creating a new handler, e.g. call database etc.

*Middlewares* usually call the inner handler, but they may choose to ignore it,
e.g. displaying *403 Forbidden page* or raising :exc:`HTTPForbidden` exception
if user has no permissions to access the underlying resource.
They may also render errors raised by the handler, perform some pre- or
post-processing like handling *CORS* and so on.

.. versionchanged:: 0.14
   Middlewares accept route exceptions (:exc:`HTTPNotFound` and
   :exc:`HTTPMethodNotAllowed`).


.. _aiohttp-web-signals:

Signals
-------

.. versionadded:: 0.18

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


Signal handlers should not return a value but may modify incoming mutable
parameters.


.. warning::

   Signals API has provisional status, meaning it may be changed in future
   releases.

   Signal subscription and sending will most likely be the same, but signal
   object creation is subject to change. As long as you are not creating new
   signals, but simply reusing existing ones, you will not be affected.


Flow control
------------

:mod:`aiohttp.web` has sophisticated flow control for underlying TCP
sockets write buffer.

The problem is: by default TCP sockets use `Nagle's algorithm
<https://en.wikipedia.org/wiki/Nagle%27s_algorithm>`_ for output
buffer which is not optimal for streaming data protocols like HTTP.

Web server response may have one of the following states:

1. **CORK** (:attr:`~StreamResponse.tcp_cork` is ``True``).
   Don't send out partial TCP/IP frames.  All queued partial frames
   are sent when the option is cleared again. Optimal for sending big
   portion of data since data will be sent using minimum
   frames count.

   If OS doesn't support **CORK** mode (neither ``socket.TCP_CORK``
   nor ``socket.TCP_NOPUSH`` exists) the mode is equal to *Nagle's
   enabled* one. The most widespread OS without **CORK** support is
   *Windows*.

2. **NODELAY** (:attr:`~StreamResponse.tcp_nodelay` is
   ``True``).  Disable the Nagle algorithm.  This means that small
   data pieces are always sent as soon as possible, even if there is
   only a small amount of data. Optimal for transmitting short messages.

3. Nagle's algorithm enabled (both
   :attr:`~StreamResponse.tcp_cork` and
   :attr:`~StreamResponse.tcp_nodelay` are ``False``).
   Data is buffered until there is a sufficient amount to send out.
   Avoid using this mode for sending HTTP data until you have no doubts.

By default streaming data (:class:`StreamResponse`) and websockets
(:class:`WebSocketResponse`) use **NODELAY** mode, regular responses
(:class:`Response` and http exceptions derived from it) as well as
static file handlers work in **CORK** mode.

To manual mode switch :meth:`~StreamResponse.set_tcp_cork` and
:meth:`~StreamResponse.set_tcp_nodelay` methods can be used.  It may
be helpful for better streaming control for example.


CORS support
------------

:mod:`aiohttp.web` itself does not support `Cross-Origin Resource
Sharing <https://en.wikipedia.org/wiki/Cross-origin_resource_sharing>`_, but
there is a aiohttp plugin for it:
`aiohttp_cors <https://github.com/aio-libs/aiohttp_cors>`_.


Debug Toolbar
-------------

aiohttp_debugtoolbar_ is a very useful library that provides a debugging toolbar
while you're developing an :mod:`aiohttp.web` application.

Install it via ``pip``::

    $ pip install aiohttp_debugtoolbar


After that attach the :mod:`aiohttp_debugtoolbar` middleware to your
:class:`aiohttp.web.Application` and call :func:`aiohttp_debugtoolbar.setup`::

    import aiohttp_debugtoolbar
    from aiohttp_debugtoolbar import toolbar_middleware_factory

    app = web.Application(loop=loop,
                          middlewares=[toolbar_middleware_factory])
    aiohttp_debugtoolbar.setup(app)

The toolbar is ready to use. Enjoy!!!

.. _aiohttp_debugtoolbar: https://github.com/aio-libs/aiohttp_debugtoolbar


.. disqus::
