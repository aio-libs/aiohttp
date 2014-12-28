.. _aiohttp-web:

.. highlight:: python

High-level HTTP Server
======================

.. module:: aiohttp.web

.. versionchanged:: 0.12

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

Handler **can** be a :ref:`coroutine<coroutine>`, :mod:`aiohttp.web` will
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


Also you can specify regexp for variable route in form ``{name:regexp}``::

   app.router.add_route('GET', r'/{name:\d+}', variable_handler)


By default regexp is ``[^{}/]+``.


Handlers can be first-class functions, e.g.::

   @asyncio.coroutine
   def hello(request):
       return web.Response(body=b"Hello, world")

   app.router.add_route('GET', '/', hello)

Sometimes you would like to group logically coupled handlers into a
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


.. _aiohttp-web-file-upload:

File Uploads
------------

There are two steps necessary for handling file uploads. The first is
to make sure that you have a form that has been setup correctly to accept
files. This means adding *enctype* attribute to your form element with
the value of *multipart/form-data*. A very simple example would be a
form that accepts a mp3 file. Notice, we have set up the form as
previously explained and also added the *input* element of the *file*
type::

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
use those to read a file's name and a content::

    import os
    import uuid
    from aiohttp.web import Response

    def store_mp3_view(request):

        data = yield from request.post()

        # ``filename`` contains the name of the file in string format.
        filename = data['mp3'].filename

        # ``input_file`` contains the actual file data which needs to be
        # stored somewhere.

        input_file = data['mp3'].file

        content = input_file.read()

        return Response(body=content,
                        headers=MultiDict({'CONTENT-DISPOSITION': input_file})


.. _aiohttp-web-request:


Request
-------

The Request object contains all the information about an incoming HTTP request.

Every :ref:`handler<aiohttp-web-handler>` accepts a request instance as the
first positional parameter.

.. note::

   You should never create the :class:`Request` instance manually --
   :mod:`aiohttp.web` does it for you.

.. class:: Request

   .. attribute:: method

      *HTTP method*, Read-only property.

      The value is upper-cased :class:`str` like ``"GET"``,
      ``"POST"``, ``"PUT"`` etc.

   .. attribute:: version

      *HTTP version* of request, Read-only property.

      Returns :class:`aiohttp.protocol.HttpVersion` instance.

   .. attribute:: host

      *HOST* header of request, Read-only property.

      Returns :class:`str` or ``None`` if HTTP request has no *HOST* header.

   .. attribute:: path_qs

      The URL including PATH_INFO and the query string. e.g, ``/app/blog?id=10``

      Read-only :class:`str` property.

   .. attribute:: path

      The URL including *PATH INFO* without the host or scheme. e.g.,
      ``/app/blog``

      Read-only :class:`str` property.

   .. attribute:: query_string

      The query string in the URL, e.g., ``id=10``

      Read-only :class:`str` property.

   .. attribute:: GET

      A multidict with all the variables in the query string.

      Read-only :class:`~aiohttp.multidict.MultiDict` lazy property.

   .. attribute:: POST

      A multidict with all the variables in the POST parameters.
      POST property available only after :meth:`Request.post` coroutine call.

      Read-only :class:`~aiohttp.multidict.MultiDict`.

      :raises RuntimeError: if :meth:`Request.post` was not called \
                            before accessing the property.

   .. attribute:: headers

      A case-insensitive multidict with all headers.

      Read-only :class:`~aiohttp.multidict.CaseInsensitiveMultiDict`
      lazy property.

   .. attribute:: keep_alive

      ``True`` if keep-alive connection enabled by HTTP client and
      protocol version supports it, otherwise ``False``.

      Read-only :class:`bool` property.

   .. attribute:: match_info

      Read-only property with :class:`~aiohttp.abc.AbstractMatchInfo`
      instance for result of route resolving.

      .. note::

         Exact type of property depends on used router.  If
         ``app.router`` is :class:`UrlDispatcher` the property contains
         :class:`UrlMappingMatchInfo` instance.

   .. attribute:: app

      An :class:`Application` instance used to call :ref:`request handler
      <aiohttp-web-handler>`, Read-only property.

   .. attribute:: transport

      An :ref:`transport<asyncio-transport>` used to process request,
      Read-only property.

      The property can be used, for example, for getting IP address of
      client's peer::

         peername = request.transport.get_extra_info('peername')
         if peername is not None:
             host, port = peername

   .. attribute:: cookies

      A multidict of all request's cookies.

      Read-only :class:`~aiohttp.multidict.MultiDict` lazy property.

   .. attribute:: payload

      A :class:`~aiohttp.streams.FlowControlStreamReader` instance,
      input stream for reading request's *BODY*.

      Read-only property.

   .. attribute:: content_type

      Read-only property with *content* part of *Content-Type* header.

      Returns :class:`str` like ``'text/html'``

      .. note::

         Returns value is ``'application/octet-stream'`` if no
         Content-Type header present in HTTP headers according to
         :rfc:`2616`

   .. attribute:: charset

      Read-only property that specifies the *encoding* for the request's BODY.

      The value is parsed from the *Content-Type* HTTP header.

      Returns :class:`str` like ``'utf-8'`` or ``None`` if
      *Content-Type* has no charset information.

   .. attribute:: content_length

      Read-only property that returns length of the request's BODY.

      The value is parsed from the *Content-Length* HTTP header.

      Returns :class:`int` or ``None`` if *Content-Length* is absent.

   .. method:: read()

      Read request body, returns :class:`bytes` object with body content.

      The method is a :ref:`coroutine <coroutine>`.

      .. warning::

         The method doesn't store read data internally, subsequent
         :meth:`~Request.read` call will return empty bytes ``b''``.

   .. method:: text()

      Read request body, decode it using :attr:`charset` encoding or
      ``UTF-8`` if no encoding was specified in *MIME-type*.

      Returns :class:`str` with body content.

      The method is a :ref:`coroutine <coroutine>`.

      .. warning::

         The method doesn't store read data internally, subsequent
         :meth:`~Request.text` call will return empty string ``''``.

   .. method:: json(*, loader=json.loads)

      Read request body decoded as *json*.

      The method is just a boilerplate :ref:`coroutine <coroutine>`
      implemented as::

         @asyncio.coroutine
         def json(self, *, loader=json.loads):
             body = yield from self.text()
             return loader(body)

      :param callable loader: any callable that accepts :class:`str`
                              and returns :class:`dict` with parsed
                              JSON (:func:`json.loads` by default).

      .. warning::

         The method doesn't store read data internally, subsequent
         :meth:`~Request.json` call will raise an exception.

   .. method:: post()

      A :ref:`coroutine <coroutine>` that reads POST parameters from
      request body.

      Returns :class:`~aiohttp.multidict.MultiDict` instance filled
      with parsed data.

      If :attr:`method` is not *POST*, *PUT* or *PATCH* or
      :attr:`content_type` is not empty or
      *application/x-www-form-urlencoded* or *multipart/form-data*
      returns empty multidict.

      .. warning::

         The method **does** store read data internally, subsequent
         :meth:`~Request.post` call will return the same value.

   .. method:: release()

      Release request.

      Eat unread part of HTTP BODY if present.

      The method is a :ref:`coroutine <coroutine>`.

      .. note::

          User code may never call :meth:`~Request.release`, all
          required work will be processed by :mod:`aiohttp.web`
          internal machinery.


.. _aiohttp-web-response:


Response classes
-----------------

For now, :mod:`aiohttp.web` has two classes for the *HTTP response*:
:class:`StreamResponse` and :class:`Response`.

Usually you need to use the second one. :class:`StreamResponse` is
intended for streaming data, while :class:`Response` contains *HTTP
BODY* as an attribute and sends own content as single piece with the
correct *Content-Length HTTP header*.

For sake of design decisions :class:`Response` is derived from
:class:`StreamResponse` parent class.

The response supports *keep-alive* handling out-of-the-box if
*request* supports it.

You can disable *keep-alive* by :meth:`~StreamResponse.force_close` though.

The common case for sending an answer from
:ref:`web-handler<aiohttp-web-handler>` is returning a
:class:`Response` instance::

   def handler(request):
       return Response("All right!")


StreamResponse
^^^^^^^^^^^^^^

.. class:: StreamResponse(*, status=200, reason=None)

   The base class for the *HTTP response* handling.

   Contains methods for setting *HTTP response headers*, *cookies*,
   *response status code*, writing *HTTP response BODY* and so on.

   The most important thing you should know about *response* --- it
   is *Finite State Machine*.

   That means you can do any manipulations with *headers*,
   *cookies* and *status code* only before :meth:`start`
   called.

   Once you call :meth:`start` any change of
   the *HTTP header* part will raise :exc:`RuntimeError` exception.

   Any :meth:`write` call after :meth:`write_eof` is also forbidden.

   :param int status: HTTP status code, ``200`` by default.

   :param str reason: HTTP reason. If param is ``None`` reason will be
                      calculated basing on *status*
                      parameter. Otherwise pass :class:`str` with
                      arbitrary *status* explanation..

   .. attribute:: status

      Read-only property for *HTTP response status code*, :class:`int`.

      ``200`` (OK) by default.

   .. attribute:: reason

      Read-only property for *HTTP response reason*, :class:`str`.

   .. method:: set_status(status, reason=None)

      Set :attr:`status` and :attr:`reason`.

      *reason* value is auto calculated if not specified (``None``).

   .. attribute:: keep_alive

      Read-only property, copy of :attr:`Request.keep_alive` by default.

      Can be switched to ``False`` by :meth:`force_close` call.

   .. method:: force_close

      Disable :attr:`keep_alive` for connection. There are no ways to
      enable it back.

   .. attribute:: headers

      :class:`~aiohttp.multidict.CaseInsensitiveMultiDict` instance
      for *outgoing* *HTTP headers*.

   .. attribute:: cookies

      An instance of :class:`http.cookies.SimpleCookie` for *outgoing* cookies.

      .. warning::

         Direct setting up *Set-Cookie* header may be overwritten by
         explicit calls to cookie manipulation.

         We are encourage using of :attr:`cookies` and
         :meth:`set_cookie`, :meth:`del_cookie` for cookie
         manipulations.

   .. method:: set_cookie(name, value, *, expires=None, \
                   domain=None, max_age=None, path=None, \
                   secure=None, httponly=None, version=None)

      Convenient way for setting :attr:`cookies`, allows to specify
      some additional properties like *max_age* in a single call.

      :param str name: cookie name

      :param str value: cookie value (will be converted to
                        :class:`str` if value has another type).

      :param expries: expiration date (optional)

      :param str domain: cookie domain (optional)

      :param int max_age: defines the lifetime of the cookie, in
                          seconds.  The delta-seconds value is a
                          decimal non- negative integer.  After
                          delta-seconds seconds elapse, the client
                          should discard the cookie.  A value of zero
                          means the cookie should be discarded
                          immediately.  (optional)

      :param str path: specifies the subset of URLs to
                       which this cookie applies. (optional)

      :param bool secure: attribute (with no value) directs
                          the user agent to use only (unspecified)
                          secure means to contact the origin server
                          whenever it sends back this cookie.
                          The user agent (possibly under the user's
                          control) may determine what level of
                          security it considers appropriate for
                          "secure" cookies.  The *secure* should be
                          considered security advice from the server
                          to the user agent, indicating that it is in
                          the session's interest to protect the cookie
                          contents. (optional)

      :param bool httponly: ``True`` if the cookie HTTP only (optional)

      :param int version: a decimal integer, identifies to which
                          version of the state management
                          specification the cookie
                          conforms. (Optional, *version=1* by default)

   .. method:: del_cookie(name, *, domain=None, path=None)

      Deletes cookie.

      :param str name: cookie name

      :param str domain: optional cookie domain

      :param str path: optional cookie path

   .. attribute:: content_length

      *Content-Length* for outgoing response.

   .. attribute:: content_type

      *Content* part of *Content-Type* for outgoing response.

   .. attribute:: charset

      *Charset* aka *encoding* part of *Content-Type* for outgoing response.

      The value converted to lower-case on attribute assigning.

   .. method:: start(request)

      :param aiohttp.web.Request request: HTTP request object, that the
                                          response answers.

      Send *HTTP header*. You should not change any header data after
      calling this method.

   .. method:: write(data)

      Send byte-ish data as the part of *response BODY*.

      :meth:`start` must be called before.

      Raises :exc:`TypeError` if data is not :class:`bytes`,
      :class:`bytearray` or :class:`memoryview` instance.

      Raises :exc:`RuntimeError` if :meth:`start` has not been called.

      Raises :exc:`RuntimeError` if :meth:`write_eof` has been called.

   .. method:: write_eof()

      A :ref:`coroutine<coroutine>` *may* be called as a mark of the
      *HTTP response* processing finish.

      *Internal machinery* will call this method at the end of
      the request processing if needed.

      After :meth:`write_eof` call any manipulations with the *response*
      object are forbidden.


Response
^^^^^^^^

.. class:: Response(*, status=200, headers=None, content_type=None, \
                    body=None, text=None)

   The most usable response class, inherited from :class:`StreamResponse`.

   Accepts *body* argument for setting the *HTTP response BODY*.

   The actual :attr:`body` sending happens in overridden
   :meth:`~StreamResponse.write_eof`.

   :param bytes body: response's BODY

   :param int status: HTTP status code, 200 OK by default.

   :param collections.abc.Mapping headers: HTTP headers that should be added to
                           response's ones.

   :param str text: response's BODY

   :param str content_type: response's content type

   .. attribute:: body

      Read-write attribute for storing response's content aka BODY,
      :class:`bytes`.

      Setting :attr:`body` also recalculates
      :attr:`~StreamResponse.content_length` value.

      Resetting :attr:`body` (assigning ``None``) sets
      :attr:`~StreamResponse.content_length` to ``None`` too, dropping
      *Content-Length* HTTP header.

   .. attribute:: text

      Read-write attribute for storing response's content, represented as str,
      :class:`str`.

      Setting :attr:`str` also recalculates
      :attr:`~StreamResponse.content_length` value and
      :attr:`~StreamResponse.body` value

      Resetting :attr:`body` (assigning ``None``) sets
      :attr:`~StreamResponse.content_length` to ``None`` too, dropping
      *Content-Length* HTTP header.


.. _aiohttp-web-app-and-router:

Application and Router
----------------------


Application
^^^^^^^^^^^

Application is a synonym for web-server.

To get fully working example, you have to make *application*, register
supported urls in *router* and create a *server socket* with
:class:`aiohttp.RequestHandlerFactory` as a *protocol factory*. *RequestHandlerFactory*
could be constructed with :meth:`make_handler`.

*Application* contains a *router* instance and a list of callbacks that
will be called during application finishing.

*Application* is a :class:`dict`, so you can use it as registry for
arbitrary properties for later access from
:ref:`handler<aiohttp-web-handler>` via :attr:`Request.app` property::

   app = Application(loop=loop)
   app['database'] = yield from aiopg.create_engine(**db_config)

   @asyncio.coroutine
   def handler(request):
       with (yield from request.app['database']) as conn:
           conn.execute("DELETE * FROM table")


.. class:: Application(*, loop=None, router=None, logger=<default>, \
                       middlewares=(), **kwargs)

   The class inherits :class:`dict`.

   :param loop: :ref:`event loop<asyncio-event-loop>` used
                for processing HTTP requests.

                If param is ``None`` :func:`asyncio.get_event_loop`
                used for getting default event loop, but we strongly
                recommend to use explicit loops everywhere.

   :param router: :class:`aiohttp.abc.AbstractRouter` instance, the system
                  creates :class:`UrlDispatcher` by default if
                  *router* is ``None``.

   :param logger: :class:`logging.Logger` instance for storing application logs.

                  By default the value is ``logging.getLogger("aiohttp.web")``

   :param middlewares: sequence of middleware factories, see
                       :ref:`aiohttp-web-middlewares` for details.

   :param kwargs: optional params for initializing self dict.

   .. attribute:: router

      Read-only property that returns *router instance*.

   .. attribute:: logger

      Read-only property that returns *router instance*.

   .. attribute:: loop

      :class:`logging.Logger` instance for storing application logs.

   .. method:: make_handler(**kwargs)

      Creates HTTP protocol factory for handling requests.

      :param kwargs: additional parameters for :class:`RequestHandlerFactory`
                     constructor.

      You should pass result of the method as *protocol_factory* to
      :meth:`~BaseEventLoop.create_server`, e.g.::

         loop = asyncio.get_event_loop()

         app = Application(loop=loop)

         # setup route table
         # app.router.add_route(...)

         yield from loop.create_server(app.make_handler(), '0.0.0.0', 8080)

   .. method:: finish()

      A :ref:`coroutine<coroutine>` that should be called after
      server stopping.

      This method executes functions registered by
      :meth:`register_on_finish` in LIFO order.

      If callback raises an exception, the error will be stored by
      :meth:`~asyncio.BaseEventLoop.call_exception_handler` with keys:
      *message*, *exception*, *application*.

   .. method:: register_on_finish(self, func, *args, **kwargs):

      Register *func* as a function to be executed at termination.
      Any optional arguments that are to be passed to *func* must be
      passed as arguments to :meth:`register_on_finish`.  It is possible to
      register the same function and arguments more than once.

      During the call of :meth:`finish` all functions registered are called in
      last in, first out order.

      *func* may be either regular function or :ref:`coroutine<coroutine>`,
      :meth:`finish` will un-yield (`yield from`) the later.

   .. note::

      Application object has :attr:`route` attribute but has no
      ``add_router`` method. The reason is: we want to support
      different route implementations (even maybe not url-matching
      based but traversal ones).

      For sake of that fact we have very trivial ABC for
      :class:`AbstractRouter`: it should have only
      :meth:`AbstractRouter.resolve` coroutine.

      No methods for adding routes or route reversing (getting URL by
      route name). All those are router implementation details (but,
      sure, you need to deal with that methods after choosing the
      router for your application).


RequestHandlerFactory
^^^^^^^^^^^^^^^^^^^^^

RequestHandlerFactory is responsible for creating HTTP protocol objects that
can handle http connections.

   .. attribute:: connections

      List of all currently oppened connections.

   .. method:: finish_connections(timeout)

      A :ref:`coroutine<coroutine>` that should be called to close all opened
      connections.


Router
^^^^^^

For dispatching URLs to :ref:`handlers<aiohttp-web-handler>`
:mod:`aiohttp.web` uses *routers*.

Router is any object that implements :class:`AbstractRouter` interface.

:mod:`aiohttp.web` provides an implementation called :class:`UrlDispatcher`.

:class:`Application` uses :class:`UrlDispatcher` as :meth:`router` by default.

.. class:: UrlDispatcher()

   Straightforward url-mathing router, implements
   :class:`collections.abc.Mapping` for access to *named routes*.

   Before running :class:`Application` you should fill *route
   table* first by calling :meth:`add_route` and :meth:`add_static`.

   :ref:`Handler<aiohttp-web-handler>` lookup is performed by iterating on
   added *routes* in FIFO order. The first matching *route* will be used
   to call corresponding *handler*.

   If on route creation you specify *name* parameter the result is
   *named route*.

   *Named route* can be retrieved by ``app.router[name]`` call, checked for
   existence by ``name in app.router`` etc.

   .. seealso:: :ref:`Route classes <aiohttp-web-route>`

   .. method:: add_route(method, path, handler, *, name=None)

      Append :ref:`handler<aiohttp-web-handler>` to the end of route table.

      *path* may be either *constant* string like ``'/a/b/c'`` or
       *variable rule* like ``'/a/{var}'`` (see
       :ref:`handling variable pathes<aiohttp-web-variable-handler>`)

      Pay attention please: *handler* is converted to coroutine internally when
      it is a regular function.

      :param str path: route path

      :param callable handler: route handler

      :param str name: optional route name.

      :returns: new :class:`PlainRoute` or :class:`DynamicRoute` instance.

   .. method:: add_static(prefix, path, *, name=None)

      Adds router for returning static files.

      Useful for handling static content like images, javascript and css files.

      .. warning::

         Use :meth:`add_static` for development only. In production,
         static content should be processed by web servers like *nginx*
         or *apache*.

      :param str prefix: URL path prefix for handled static files

      :param str path: path to the folder in file system that contains
                       handled static files.

      :param str name: optional route name.

      :returns: new :class:`StaticRoute` instance.

   .. method:: resolve(requst)

      A :ref:`coroutine<coroutine>` that returns
      :class:`AbstractMatchInfo` for *request* or raises http
      exception like :exc:`HTTPNotFound` if there is no registered
      route for *request*.

      Used by internal machinery, end user unlikely need to call the method.

.. _aiohttp-web-route:

Route
^^^^^

.. versionadded:: 0.11

Default router :class:`UrlDispatcher` operates with *routes*.

User should not instantiate route classes by hand but can give *named
route instance* by ``router[name]`` if he have added route by
:meth:`UrlDispatcher.add_route` or :meth:`UrlDispatcher.add_static`
calls with non-empty *name* parameter.

The main usage of *named routes* is constructing URL by route name for
passing it into *template engine* for example::

   url = app.router['route_name'].url(query={'a': 1, 'b': 2})

There are three conctrete route classes:* :class:`DynamicRoute` for
urls with :ref:`variable pathes<aiohttp-web-variable-handler>` spec.


* :class:`PlainRoute` for urls without :ref:`variable
  pathes<aiohttp-web-variable-handler>`

* :class:`DynamicRoute` for urls with :ref:`variable
  pathes<aiohttp-web-variable-handler>` spec.

* :class:`StaticRoute` for static file handlers.

.. class:: Route

   Base class for routes served by :class:`UrlDispatcher`.

   .. attribute:: method

   HTTP method handled by the route, e.g. *GET*, *POST* etc.

   .. attribute:: handler

   :ref:`handler<aiohttp-web-handler>` that processes the route.

   .. attribute:: name

   Name of the route.

   .. method:: match(path)

   Abstract method, accepts *URL path* and returns :class:`dict` with
   parsed *path parts* for :class:`UrlMappingMatchInfo` or ``None`` if
   the route cannot handle given *path*.

   The method exists for internal usage, end user unlikely need to call it.

   .. method:: url(*, query=None, **kwargs)

   Abstract method for constructing url handled by the route.

   *query* is a mapping or list of *(name, value)* pairs for
   specifying *query* part of url (parameter is processed by
   :func:`~urllib.parse.urlencode`).

   Other available parameters depends on concrete route class and
   described in descendant classes.

.. class:: PlainRoute

   The route class for handling plain *URL path*, e.g. ``"/a/b/c"``

   .. method:: url(*, parts, query=None)

   Construct url, doesn't accepts extra parameters::

      >>> route.url(query={'d': 1, 'e': 2})
      '/a/b/c/?d=1&e=2'``

.. class:: DynamicRoute

   The route class for handling :ref:`variable
   path<aiohttp-web-variable-handler>`, e.g. ``"/a/{name1}/{name2}"``

   .. method:: url(*, parts, query=None)

   Construct url with given *dynamic parts*::

       >>> route.url(parts={'name1': 'b', 'name2': 'c'}, query={'d': 1, 'e': 2})
       '/a/b/c/?d=1&e=2'


.. class:: StaticRoute

   The route class for handling static files, created by
   :meth:`UrlDispatcher.add_static` call.

   .. method:: url(*, filename, query=None)

   Construct url for given *filename*::

      >>> route.url(filename='img/logo.png', query={'param': 1})
      '/path/to/static/img/logo.png?param=1'

MatchInfo
^^^^^^^^^

After route matching web application calls found handler if any.

Matching result can be accessible from handler as
:attr:`Request.match_info` attribute.

In general the result may be any object derived from
:class:`AbstractMatchInfo` (:class:`UrlMappingMatchInfo` for default
:class:`UrlDispatcher` router).

.. class:: UrlMappingMatchInfo

   Inherited from :class:`dict` and :class:`AbstractMatchInfo`. Dict
   items are given from :meth:`Route.match` call return value.

   .. attribute:: route

   :class:`Route` instance for url matching.



Utilities
---------

.. class:: FileField

   A :func:`~collections.namedtuple` that is returned as multidict value
   by :meth:`Request.POST` if field is uploaded file.

   .. attribute:: name

      Field name

   .. attribute:: filename

      File name as specified by uploading (client) side.

   .. attribute:: file

      An :class:`io.IOBase` instance with content of uploaded file.

   .. attribute:: content_type

      *MIME type* of uploaded file, ``'text/plain'`` by default.

   .. seealso:: :ref:`aiohttp-web-file-upload`

.. _aiohttp-web-exceptions:

Exceptions
-----------

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

:class:`Application` accepts *middlewares* keyword-only parameter,
which should be sequence of *middleware factories*.

The most trivial *middleware factory* example::

    @asyncio.coroutine
    def middleware_factory(app, handler):
        @asyncio.coroutine
        def middleware(request):
            return (yield from handler(request))
        return middleware

Every factory is a coroutine that accepts two parameters: *app*
(:class:`Application` instance) and *handler* (next handler in
middleware chain. The last handler is
:ref:`web-handler<aiohttp-web-handler>` selected by routing itself
(:meth:`~UrlDispatcher.resolve` call). Middleware should return new
coroutine by wrapping *handler* parameter. Signature of returned
handler should be the same as for
:ref:`web-handler<aiohttp-web-handler>`: accept single *request*
parameter, return *response* or raise exception. Factory is coroutine,
thus it can do extra ``yield from`` calls on making new handler.

After constructing outermost handler by applying middleware chain to
:ref:`web-handler<aiohttp-web-handler>` in reversed order
:class:`RequestHandler` executes that outermost handler as regular
*web-handler*.

Middleware usually calls inner handler, but may do something
other, like displaying *403 Forbidden page* or raising
:exc:`HTTPForbidden` exception if user has no permissions to access underlying
resource.  Also middleware may render errors raised by handler, do
some pre- and post- processing like handling *CORS* and so on.

.. warning::

   Middlewares are executed **after** routing, so it cannot process
   route exceptions.
