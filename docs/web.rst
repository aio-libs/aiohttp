.. _aiohttp-web:

HTTP Server Usage
=================

.. highlight:: python

.. currentmodule:: aiohttp.web

.. versionchanged:: 0.12

   The module was deeply refactored in backward incompatible manner.

Run a simple web server
-----------------------

For implementing a web server, first create a :ref:`request
handler<aiohttp-web-handler>`.

Handler is a :ref:`coroutine<coroutine>` or a regular function that
accepts only *request* parameter of type :class:`Request`
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
   f = loop.create_server(app.make_handler(), '0.0.0.0', 8080)
   srv = loop.run_until_complete(f)
   print('serving on', srv.sockets[0].getsockname())
   try:
       loop.run_forever()
   except KeyboardInterrupt:
       pass

That's it.

.. _aiohttp-web-handler:

Handler
-------

Handler is an any *callable* that accepts a single :class:`Request`
argument and returns a :class:`StreamResponse` derived
(e.g. :class:`Response`) instance.

Handler **may** be a :ref:`coroutine<coroutine>`, :mod:`aiohttp.web` will
**unyield** returned result by applying ``yield from`` to the handler.

Handlers are connected to the :class:`Application` via routes::

   handler = Handler()
   app.router.add_route('GET', '/', handler)

.. _aiohttp-web-variable-handler:

You can also use *variable routes*. If route contains string like
``'/a/{name}/c'`` that means the route matches to the path like
``'/a/b/c'`` or ``'/a/1/c'``.

Parsed *path part* will be available in the *request handler* as
``request.match_info['name']``::

   @asyncio.coroutine
   def variable_handler(request):
       return web.Response(
           text="Hello, {}".format(request.match_info['name']))

   app.router.add_route('GET', '/{name}', variable_handler)


Also you can specify regex for variable route in form ``{name:regex}``::

   app.router.add_route('GET', r'/{name:\d+}', variable_handler)


By default regex is ``[^{}/]+``.


.. versionadded:: 0.13

   Support for custom regexs in variable routes.


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


Custom conditions for routes lookup
-----------------------------------

Sometimes you need to distinguish *web-handlers* on more complex
criteria than *HTTP method* and *path*.

While :class:`UrlDispatcher` doesn't accept extra criterias there is
easy way to do the task by implementing the second routing layer by
hands.

The example shows custom processing based on *HTTP Accept* header:

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



.. _aiohttp-web-file-upload:

File Uploads
------------

There are two steps necessary for handling file uploads. The first is
to make sure that you have a form that has been setup correctly to accept
files. This means adding *enctype* attribute to your form element with
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
using response's methods::

    @asyncio.coroutine
    def websocket_handler(request):

        ws = web.WebSocketResponse()
        ws.start(request)

        while True:
            try:
                data = yield from ws.receive_str()
                if data == 'close':
                    ws.close()
                else:
                    ws.send_str(data + '/answer')
            except web.WebSocketDisconnectedError as exc:
                print(exc.code, exc.message)
                return ws

You can have the only websocket reader task (which can call ``yield
from ws.receive_str()``) and multiple writer tasks which can only send
data asynchronously (by ``yield from ws.send_str('data')`` for example).


.. _aiohttp-web-exceptions:

Exceptions
----------

:mod:`aiohttp.web` defines exceptions for list of *HTTP status codes*.

Each class relates to a single HTTP status code.  Each class is a
subclass of the :class:`~HTTPException`.

Those exceptions are derived from :class:`Response` too, so you can
either return exception object from :ref:`aiohttp-web-handler` or raise it.

The following snippets are equal::

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

Middleware should return new coroutine by wrapping *handler*
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
