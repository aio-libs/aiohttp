.. _aiohttp-web:

HTTP Server Usage
=================

.. highlight:: python

.. currentmodule:: aiohttp.web

.. versionchanged:: 0.12

   The module was deeply refactored which makes it backward incompatible.

Run a simple web server
-----------------------

In order to implement a web server, first create a :ref:`request
handler<aiohttp-web-handler>`.

Handler is a :ref:`coroutine<coroutine>` or a regular function that
accepts only *request* parameters of type :class:`Request`
and returns :class:`Response` instance::

   import asyncio
   from aiohttp import web

   @asyncio.coroutine
   def hello(request):
       return web.Response(body=b"Hello, world")

Next, you have to create a :class:`Application` instance and register
:ref:`handler<aiohttp-web-handler>` in the application's router pointing *HTTP
method*, *path* and *handler*::

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
       loop.run_until_complete(handler.finish_connections(1.0))
       srv.close()
       loop.run_until_complete(srv.wait_closed())
       loop.run_until_complete(app.finish())
   loop.close()

That's it.

.. _aiohttp-web-handler:

Handler
-------

Handler is an any :term:`callable` that accepts a single
:class:`Request` argument and returns a :class:`StreamResponse`
derived (e.g. :class:`Response`) instance.

Handler **may** be a :ref:`coroutine<coroutine>`, :mod:`aiohttp.web` will
**unyield** returned result by applying ``yield from`` to the handler.

Handlers are connected to the :class:`Application` via routes::

   handler = Handler()
   app.router.add_route('GET', '/', handler)

.. _aiohttp-web-variable-handler:

Variable routes
^^^^^^^^^^^^^^^

You can also use *variable routes*. If route contains strings like
``'/a/{name}/c'`` that means the route matches to the path like
``'/a/b/c'`` or ``'/a/1/c'``.

Parsed *path part* will be available in the *request handler* as
``request.match_info['name']``::

   @asyncio.coroutine
   def variable_handler(request):
       return web.Response(
           text="Hello, {}".format(request.match_info['name']))

   app.router.add_route('GET', '/{name}', variable_handler)


You can also specify regex for variable route in the form ``{name:regex}``::

   app.router.add_route('GET', r'/{name:\d+}', variable_handler)


By default regex is ``[^{}/]+``.


.. versionadded:: 0.13

   Support for custom regexs in variable routes.


.. _aiohttp-web-named-routes:

Named routes and url reverse constructing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Routes may have a *name*::

   app.router.add_route('GET', '/root', handler, name='root')

In web-handler you may build *URL* for that route::

   >>> request.app.router['root'].url(query="?a=b&c=d")
   '/root?a=b&c=d'

More interesting example is building *URL* for :ref:`variable
router<aiohttp-web-variable-handler>`::

   app.router.add_route('GET', r'/{user}/info',
                        variable_handler, name='handler')


In this case you can pass route parameters also::

   >>> request.app.router['handler'].url(
   ...     params={'user': 'john_doe'},
   ...     query="?a=b")
   '/john_doe/info?a=b'


Using plain coroutines and classes for web-handlers
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Handlers *may* be first-class functions, e.g.::

   @asyncio.coroutine
   def hello(request):
       return web.Response(body=b"Hello, world")

   app.router.add_route('GET', '/', hello)

But sometimes you would like to group logically coupled handlers into a
python class.

:mod:`aiohttp.web` doesn't dictate any implementation details,
so application developer can use classes if he wants::

   class Handler:

       def __init__(self):
           pass

       def handle_intro(self, request):
           return web.Response(body=b"Hello, world")

       @asyncio.coroutine
       def handle_greeting(self, request):
           name = request.match_info.get('name', "Anonymous")
           txt = "Hello, {}".format(name)
           return web.Response(text=txt)

   handler = Handler()
   app.router.add_route('GET', '/intro', handler.handle_intro)
   app.router.add_route('GET', '/greet/{name}', handler.handle_greeting)


.. versionadded:: 0.15.2

   :meth:`UrlDispatcher.add_route` supports wildcard as *HTTP method*::

       app.router.add_route('*', '/path', handler)

   That means the handler for ``'/path'`` is applied for every HTTP method.


Custom conditions for routes lookup
-----------------------------------

Sometimes you need to distinguish *web-handlers* on more complex
criteria than *HTTP method* and *path*.

While :class:`UrlDispatcher` doesn't accept extra criterias there is an
easy way to do the task by implementing the second routing layer by
hand.

The next example shows custom processing based on *HTTP Accept* header:

.. code-block:: python

   class AcceptChooser:

       def __init__(self):
           self._accepts = {}

       @asyncio.coroutine
       def do_route(self, request):
           for accept in request.headers.getall('ACCEPT', []):
                acceptor = self._accepts.get(accept):
                if acceptor is not None:
                    return (yield from acceptor(request))
           raise HTTPNotAcceptable()

       def reg_acceptor(self, accept, handler):
           self._accepts[accept] = handler


   @asyncio.coroutine
   def handle_json(request):
       # do json handling

   @asyncio.coroutine
   def handle_xml(request):
       # do xml handling

   chooser = AcceptChooser()
   app.router.add_route('GET', '/', chooser.do_route)

   chooser.reg_acceptor('application/json', handle_json)
   chooser.reg_acceptor('application/xml', handle_xml)


Template rendering
------------------

:mod:`aiohttp.web` has no support for template rendering out-of-the-box.

But there is third-party library :mod:`aiohttp_jinja2` which is
supported by *aiohttp* authors.

The usage is simple: create dictionary with data and pass it into
template renderer.

Before template rendering you have to setup *jinja2 environment* first
(:func:`aiohttp_jinja2.setup` call)::

    app = web.Application(loop=self.loop)
    aiohttp_jinja2.setup(app,
        loader=jinja2.FileSystemLoader('/path/to/templates/folder'))


After that you may use template engine in your *web-handlers*. The
most convinient way is to use :func:`aiohttp_jinja2.template`
decorator::

    @aiohttp_jinja2.template('tmpl.jinja2')
    def handler(request):
        return {'name': 'Andrew', 'surname': 'Svetlov'}

If you prefer `Mako template engine <http://www.makotemplates.org/>`_
please take a look on
`aiohttp_mako <https://github.com/aio-libs/aiohttp_mako>`_ library.


User sessions
-------------

Often you need a container for storing per-user data. The concept is
usually called *session*.

:mod:`aiohttp.web` has no *sessions* but there is third-party
:mod:`aiohttp_session` library for that::

    import asyncio
    import time
    from aiohttp import web
    from aiohttp_session import get_session, session_middleware
    from aiohttp_session.cookie_storage import EncryptedCookieStorage

    @asyncio.coroutine
    def handler(request):
        session = yield from get_session(request)
        session['last_visit'] = time.time()
        return web.Response(body=b'OK')

    @asyncio.coroutine
    def init(loop):
        app = web.Application(middlewares=[session_middleware(
            EncryptedCookieStorage(b'Sixteen byte key'))])
        app.router.add_route('GET', '/', handler)
        srv = yield from loop.create_server(
            app.make_handler(), '0.0.0.0', 8080)
        return srv

    loop = asyncio.get_event_loop()
    loop.run_until_complete(init(loop))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass


.. _aiohttp-web-expect-header:

*Expect* header support
-----------------------

.. versionadded:: 0.15

:mod:`aiohttp.web` supports *Expect* header. By default
it responds with an *HTTP/1.1 100 Continue* status code.
It is possible to specify custom *Expect* header handler on per route basis.
This handler gets called after receiving all headers and before
processing application middlewares :ref:`aiohttp-web-middlewares` and route
handler. Handler can return *None*, in that case the request processing
continues as usual. If handler returns an instance of
class :class:`StreamResponse`, *request handler* uses it as response.
Custom handler *must* write *HTTP/1.1 100 Continue* status if all checks pass.

This example shows custom handler for *Except* header:

.. code-block:: python

   @asyncio.coroutine
   def check_auth(request):
       if request.version != aiohttp.HttpVersion11:
           return

       if request.headers.get('AUTHORIZATION') is None:
           return web.HTTPForbidden()

       request.transport.write(b"HTTP/1.1 100 Continue\r\n\r\n")

   @asyncio.coroutine
   def hello(request):
       return web.Response(body=b"Hello, world")

   app = web.Application()
   app.router.add_route('GET', '/', hello, except_handler=check_auth)


.. _aiohttp-web-file-upload:

File Uploads
------------

There are two steps necessary for handling file uploads. The first is
to make sure that you have a form that has been setup correctly to accept
files. This means adding the *enctype* attribute to your form element with
the value of *multipart/form-data*. A very simple example would be a
form that accepts a mp3 file. Notice, we have set up the form as
previously explained and also added the *input* element of the *file*
type:

.. code-block:: html

   <form action="/store_mp3" method="post" accept-charset="utf-8"
         enctype="multipart/form-data">

       <label for="mp3">Mp3</label>
       <input id="mp3" name="mp3" type="file" value="" />

       <input type="submit" value="submit" />
   </form>

The second step is handling the file upload in your :ref:`request
handler<aiohttp-web-handler>` (here assumed to answer on
*/store_mp3*). The uploaded file is added to the request object as a
:class:`FileField` object accessible through the :meth:`Request.post`
coroutine. The two properties we are interested in are
:attr:`~FileField.file` and :attr:`~FileField.filename` and we will
use those to read a file's name and a content:

.. code-block:: python

    @asyncio.coroutine
    def store_mp3_view(request):

        data = yield from request.post()

        # filename contains the name of the file in string format.
        filename = data['mp3'].filename

        # input_file contains the actual file data which needs to be
        # stored somewhere.

        input_file = data['mp3'].file

        content = input_file.read()

        return web.Response(body=content,
                            headers=MultiDict(
                                {'CONTENT-DISPOSITION': input_file})


.. _aiohttp-web-websockets:

WebSockets
----------

.. versionadded:: 0.14

:mod:`aiohttp.web` works with websockets out-of-the-box.

You have to create :class:`WebSocketResponse` in
:ref:`web-handler<aiohttp-web-handler>` and communicate with peer
using response's methods:

.. code-block:: python

    @asyncio.coroutine
    def websocket_handler(request):

        ws = web.WebSocketResponse()
        ws.start(request)

        while True:
            msg = yield from ws.receive()

            if msg.tp == aiohttp.MsgType.text:
                if msg.data == 'close':
                    yield from ws.close()
                else:
                    ws.send_str(msg.data + '/answer')
            elif msg.tp == aiohttp.MsgType.close:
                print('websocket connection closed')
            elif msg.tp == aiohttp.MsgType.error:
                print('ws connection closed with exception %s',
                      ws.exception())

        return ws

You **must** use the only websocket task for both reading (e.g ``yield
from ws.receive()``) and writing but may have multiple writer tasks
which can only send data asynchronously (by ``yield from
ws.send_str('data')`` for example).


.. _aiohttp-web-exceptions:

Exceptions
----------

:mod:`aiohttp.web` defines exceptions for list of *HTTP status codes*.

Each class relates to a single HTTP status code.  Each class is a
subclass of the :class:`~HTTPException`.

Those exceptions are derived from :class:`Response` too, so you can
either return exception object from :ref:`aiohttp-web-handler` or raise it.

The following snippets are the same::

    @asyncio.coroutine
    def handler(request):
        return aiohttp.web.HTTPFound('/redirect')

and::

    @asyncio.coroutine
    def handler(request):
        raise aiohttp.web.HTTPFound('/redirect')


Each exception class has a status code according to :rfc:`2068`:
codes with 100-300 are not really errors; 400s are client errors,
and 500s are server errors.

Http Exception hierarchy chart::

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
         HTTPServerError
           * 500 - HTTPInternalServerError
           * 501 - HTTPNotImplemented
           * 502 - HTTPBadGateway
           * 503 - HTTPServiceUnavailable
           * 504 - HTTPGatewayTimeout
           * 505 - HTTPVersionNotSupported

All http exceptions have the same constructor::

    HTTPNotFound(*, headers=None, reason=None,
                 body=None, text=None, content_type=None)

if other not directly specified. *headers* will be added to *default
response headers*.

Classes :class:`HTTPMultipleChoices`, :class:`HTTPMovedPermanently`,
:class:`HTTPFound`, :class:`HTTPSeeOther`, :class:`HTTPUseProxy`,
:class:`HTTPTemporaryRedirect` has constructor signature like::

    HTTPFound(location, *, headers=None, reason=None,
              body=None, text=None, content_type=None)

where *location* is value for *Location HTTP header*.

:class:`HTTPMethodNotAllowed` constructed with pointing trial method
and list of allowed methods::

    HTTPMethodNotAllowed(method, allowed_methods, *,
                         headers=None, reason=None,
                         body=None, text=None, content_type=None)

.. _aiohttp-web-middlewares:

Middlewares
-----------

.. versionadded:: 0.13

:class:`Application` accepts optional *middlewares* keyword-only
parameter, which should be a sequence of *middleware factories*, e.g::

   app = web.Application(middlewares=[middleware_factory_1,
                                      middleware_factory_2])

The most trivial *middleware factory* example::

    @asyncio.coroutine
    def middleware_factory(app, handler):
        @asyncio.coroutine
        def middleware(request):
            return (yield from handler(request))
        return middleware

Every factory is a coroutine that accepts two parameters: *app*
(:class:`Application` instance) and *handler* (next handler in
middleware chain.

The last handler is :ref:`web-handler<aiohttp-web-handler>` selected
by routing itself (:meth:`~UrlDispatcher.resolve` call).

Middleware should return a new coroutine by wrapping *handler*
parameter. Signature of returned handler should be the same as for
:ref:`web-handler<aiohttp-web-handler>`: accept single *request*
parameter, return *response* or raise exception.

The factory is a coroutine, thus it can do extra ``yield from`` calls
on making new handler, e.g. call database etc.

After constructing outermost handler by applying middleware chain to
:ref:`web-handler<aiohttp-web-handler>` in reversed order
:class:`RequestHandler` executes the outermost handler as regular
*web-handler*.

Middleware usually calls an inner handler, but may do something
other, like displaying *403 Forbidden page* or raising
:exc:`HTTPForbidden` exception if user has no permissions to access underlying
resource.  Also middleware may render errors raised by handler, do
some pre- and post- processing like handling *CORS* and so on.

.. versionchanged:: 0.14

   Middleware accepts route exceptions (:exc:`HTTPNotFound` and
   :exc:`HTTPMethodNotAllowed`).


Debug toolbar
-------------

`aiohttp_debugtoolbar
<https://github.com/aio-libs/aiohttp_debugtoolbar>`_ is very useful
library that provides debug toolbar while you're developing
:mod:`aiohttp.web` application.

Install it via ``pip`` tool::

    $ pip install aiohttp_debugtoolbar


After that attach middleware to your :class:`aiohttp.web.Application`
and call ``aiohttp_debugtoolbar.setup``::

    import aiohttp_debugtoolbar
    from aiohttp_debugtoolbar import toolbar_middleware_factory

    app = web.Application(loop=loop,
                          middlewares=[toolbar_middleware_factory])
    aiohttp_debugtoolbar.setup(app)

Debug toolbar is ready to use. Enjoy!!!
