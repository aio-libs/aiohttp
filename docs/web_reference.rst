.. _aiohttp-web-reference:

HTTP Server Reference
=====================

.. highlight:: python

.. module:: aiohttp.web

.. versionchanged:: 0.12

   The module was deeply refactored in backward incompatible manner.

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

   .. attribute:: scheme

      A string representing the scheme of the request.

      The scheme is ``'https'`` if transport for request handling is
      *SSL* or ``secure_proxy_ssl_header`` is matching.

      ``'http'`` otherwise.

      Read-only :class:`str` property.

   .. attribute:: method

      *HTTP method*, read-only property.

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

      Read-only :class:`~aiohttp.multidict.MultiDictProxy` lazy property.

   .. attribute:: POST

      A multidict with all the variables in the POST parameters.
      POST property available only after :meth:`Request.post` coroutine call.

      Read-only :class:`~aiohttp.multidict.MultiDictProxy`.

      :raises RuntimeError: if :meth:`Request.post` was not called \
                            before accessing the property.

   .. attribute:: headers

      A case-insensitive multidict proxy with all headers.

      Read-only :class:`~aiohttp.multidict.CIMultiDictProxy` property.

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

      Read-only :class:`~aiohttp.multidict.MultiDictProxy` lazy property.

   .. attribute:: content

      A :class:`~aiohttp.streams.FlowControlStreamReader` instance,
      input stream for reading request's *BODY*.

      Read-only property.

      .. versionadded:: 0.15

   .. attribute:: has_body

      Return ``True`` if request has *HTTP BODY*, ``False`` otherwise.

      Read-only :class:`bool` property.

      .. versionadded:: 0.16

   .. attribute:: payload

      A :class:`~aiohttp.streams.FlowControlStreamReader` instance,
      input stream for reading request's *BODY*.

      Read-only property.

      .. deprecated:: 0.15

         Use :attr:`~Request.content` instead.

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

   .. coroutinemethod:: read()

      Read request body, returns :class:`bytes` object with body content.

      .. note::

         The method **does** store read data internally, subsequent
         :meth:`~Request.read` call will return the same value.

   .. coroutinemethod:: text()

      Read request body, decode it using :attr:`charset` encoding or
      ``UTF-8`` if no encoding was specified in *MIME-type*.

      Returns :class:`str` with body content.

      .. note::

         The method **does** store read data internally, subsequent
         :meth:`~Request.text` call will return the same value.

   .. coroutinemethod:: json(*, loader=json.loads)

      Read request body decoded as *json*.

      The method is just a boilerplate :ref:`coroutine <coroutine>`
      implemented as::

         @asyncio.coroutine
         def json(self, *, loader=json.loads):
             body = yield from self.text()
             return loader(body)

      :param callable loader: any :term:`callable` that accepts
                              :class:`str` and returns :class:`dict`
                              with parsed JSON (:func:`json.loads` by
                              default).

      .. note::

         The method **does** store read data internally, subsequent
         :meth:`~Request.json` call will return the same value.

   .. coroutinemethod:: post()

      A :ref:`coroutine <coroutine>` that reads POST parameters from
      request body.

      Returns :class:`~aiohttp.multidict.MultiDictProxy` instance filled
      with parsed data.

      If :attr:`method` is not *POST*, *PUT* or *PATCH* or
      :attr:`content_type` is not empty or
      *application/x-www-form-urlencoded* or *multipart/form-data*
      returns empty multidict.

      .. note::

         The method **does** store read data internally, subsequent
         :meth:`~Request.post` call will return the same value.

   .. coroutinemethod:: release()

      Release request.

      Eat unread part of HTTP BODY if present.

      .. note::

          User code may never call :meth:`~Request.release`, all
          required work will be processed by :mod:`aiohttp.web`
          internal machinery.


.. _aiohttp-web-response:


Response classes
----------------

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

   .. attribute:: started

      Read-only :class:`bool` property, ``True`` if :meth:`start` has
      been called, ``False`` otherwise.

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

   .. attribute:: compression

      Read-only :class:`bool` property, ``True`` if compression is enabled.

      ``False`` by default.

      .. versionadded:: 0.14

      .. seealso:: :meth:`enable_compression`

   .. method:: enable_compression(force=False)

      Enable compression.

      When *force* is ``False`` (default) compression is used only
      when *deflate* is in *Accept-Encoding* request's header.

      *Accept-Encoding* is not checked if *force* is ``True``.

      .. versionadded:: 0.14

      .. seealso:: :attr:`compression`

   .. attribute:: chunked

      Read-only property, indicates if chunked encoding is on.

      Can be enabled by :meth:`enable_chunked_encoding` call.

      .. versionadded:: 0.14

      .. seealso:: :attr:`enable_chunked_encoding`

   .. method:: enable_chunked_encoding

      Enables :attr:`chunked` encoding for response. There are no ways to
      disable it back. With enabled :attr:`chunked` encoding each `write()`
      operation encoded in separate chunk.

      .. versionadded:: 0.14

      .. seealso:: :attr:`chunked`

   .. attribute:: headers

      :class:`~aiohttp.multidict.CIMultiDict` instance
      for *outgoing* *HTTP headers*.

   .. attribute:: cookies

      An instance of :class:`http.cookies.SimpleCookie` for *outgoing* cookies.

      .. warning::

         Direct setting up *Set-Cookie* header may be overwritten by
         explicit calls to cookie manipulation.

         We are encourage using of :attr:`cookies` and
         :meth:`set_cookie`, :meth:`del_cookie` for cookie
         manipulations.

   .. method:: set_cookie(name, value, *, path='/', expires=None, \
                   domain=None, max_age=None, \
                   secure=None, httponly=None, version=None)

      Convenient way for setting :attr:`cookies`, allows to specify
      some additional properties like *max_age* in a single call.

      :param str name: cookie name

      :param str value: cookie value (will be converted to
                        :class:`str` if value has another type).

      :param expires: expiration date (optional)

      :param str domain: cookie domain (optional)

      :param int max_age: defines the lifetime of the cookie, in
                          seconds.  The delta-seconds value is a
                          decimal non- negative integer.  After
                          delta-seconds seconds elapse, the client
                          should discard the cookie.  A value of zero
                          means the cookie should be discarded
                          immediately.  (optional)

      :param str path: specifies the subset of URLs to
                       which this cookie applies. (optional, ``'/'`` by default)

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

      .. versionchanged:: 0.14.3

         Default value for *path* changed from ``None`` to ``'/'``.

   .. method:: del_cookie(name, *, path='/', domain=None)

      Deletes cookie.

      :param str name: cookie name

      :param str domain: optional cookie domain

      :param str path: optional cookie path, ``'/'`` by default

      .. versionchanged:: 0.14.3

         Default value for *path* changed from ``None`` to ``'/'``.

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

   .. coroutinemethod:: drain()

      A :ref:`coroutine<coroutine>` to let the write buffer of the
      underlying transport a chance to be flushed.

      The intended use is to write::

          resp.write(data)
          yield from resp.drain()

      Yielding from :meth:`drain` gives the opportunity for the loop
      to schedule the write operation and flush the buffer. It should
      especially be used when a possibly large amount of data is
      written to the transport, and the coroutine does not yield-from
      between calls to :meth:`write`.

      .. versionadded:: 0.14

   .. coroutinemethod:: write_eof()

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


WebSocketResponse
^^^^^^^^^^^^^^^^^

.. class:: WebSocketResponse(*, timeout=10.0, autoclose=True, \
                             autoping=True, protocols=())

   Class for handling server-side websockets.

   After starting (by :meth:`start` call) the response you
   cannot use :meth:`~StreamResponse.write` method but should to
   communicate with websocket client by :meth:`send_str`,
   :meth:`receive` and others.

   .. method:: start(request)

      Starts websocket. After the call you can use websocket methods.

      :param aiohttp.web.Request request: HTTP request object, that the
                                          response answers.


      :raises HTTPException: if websocket handshake has failed.

   .. method:: can_start(request)

      Performs checks for *request* data to figure out if websocket
      can be started on the request.

      If :meth:`can_start` call is success then :meth:`start` will success too.

      :param aiohttp.web.Request request: HTTP request object, that the
                                          response answers.

      :return: ``(ok, protocol)`` pair, *ok* is ``True`` on success,
               *protocol* is websocket subprotocol which is passed by
               client and accepted by server (one of *protocols*
               sequence from :class:`WebSocketResponse` ctor). *protocol* may be
               ``None`` if client and server subprotocols are nit overlapping.

      .. note:: The method newer raises exception.

   .. attribute:: closed

      Read-only property, ``True`` if connection has been closed or in process
      of closing.
      :const:`~aiohttp.websocket.MSG_CLOSE` message has been received from peer.

   .. attribute:: close_code

      Read-only property, close code from peer. It is set to ``None`` on
      opened connection.

   .. attribute:: protocol

      Websocket *subprotocol* chosen after :meth:`start` call.

      May be ``None`` if server and client protocols are
      not overlapping.

   .. method:: exception()

      Returns last occured exception or None.

   .. method:: ping(message=b'')

      Send :const:`~aiohttp.websocket.MSG_PING` to peer.

      :param message: optional payload of *ping* message,
                      :class:`str` (converted to *UTF-8* encoded bytes)
                      or :class:`bytes`.

      :raise RuntimeError: if connections is not started or closing.

   .. method:: pong(message=b'')

      Send *unsolicited* :const:`~aiohttp.websocket.MSG_PONG` to peer.

      :param message: optional payload of *pong* message,
                      :class:`str` (converted to *UTF-8* encoded bytes)
                      or :class:`bytes`.

      :raise RuntimeError: if connections is not started or closing.

   .. method:: send_str(data)

      Send *data* to peer as :const:`~aiohttp.websocket.MSG_TEXT` message.

      :param str data: data to send.

      :raise RuntimeError: if connection is not started or closing

      :raise TypeError: if data is not :class:`str`

   .. method:: send_bytes(data)

      Send *data* to peer as :const:`~aiohttp.websocket.MSG_BINARY` message.

      :param data: data to send.

      :raise RuntimeError: if connection is not started or closing

      :raise TypeError: if data is not :class:`bytes`,
                        :class:`bytearray` or :class:`memoryview`.

   .. coroutinemethod:: close(*, code=1000, message=b'')

      A :ref:`coroutine<coroutine>` that initiates closing
      handshake by sending :const:`~aiohttp.websocket.MSG_CLOSE` message.

      :param int code: closing code

      :param message: optional payload of *pong* message,
                      :class:`str` (converted to *UTF-8* encoded bytes)
                      or :class:`bytes`.

      :raise RuntimeError: if connection is not started or closing

   .. coroutinemethod:: receive()

      A :ref:`coroutine<coroutine>` that waits upcoming *data*
      message from peer and returns it.

      The coroutine implicitly handles
      :const:`~aiohttp.websocket.MSG_PING`,
      :const:`~aiohttp.websocket.MSG_PONG` and
      :const:`~aiohttp.websocket.MSG_CLOSE` without returning the
      message.

      It process *ping-pong game* and performs *closing handshake* internally.

      After websocket closing raises
      :exc:`~aiohttp.errors.WSClientDisconnectedError` with
      connection closing data.

      :return: :class:`~aiohttp.websocket.Message`

      :raise RuntimeError: if connection is not started

      :raise: :exc:`~aiohttp.errors.WSClientDisconnectedError` on closing.

   .. coroutinemethod:: receive_str()

      A :ref:`coroutine<coroutine>` that calls :meth:`receive_mgs` but
      also asserts the message type is
      :const:`~aiohttp.websocket.MSG_TEXT`.

      :return str: peer's message content.

      :raise TypeError: if message is :const:`~aiohttp.websocket.MSG_BINARY`.

   .. coroutinemethod:: receive_bytes()

      A :ref:`coroutine<coroutine>` that calls :meth:`receive_mgs` but
      also asserts the message type is
      :const:`~aiohttp.websocket.MSG_BINARY`.

      :return bytes: peer's message content.

      :raise TypeError: if message is :const:`~aiohttp.websocket.MSG_TEXT`.


.. versionadded:: 0.14

.. seealso:: :ref:`WebSockets handling<aiohttp-web-websockets>`

.. _aiohttp-web-app-and-router:

Application and Router
----------------------


Application
^^^^^^^^^^^

Application is a synonym for web-server.

To get fully working example, you have to make *application*, register
supported urls in *router* and create a *server socket* with
:class:`aiohttp.RequestHandlerFactory` as a *protocol
factory*. *RequestHandlerFactory* could be constructed with
:meth:`make_handler`.

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

                       .. versionadded:: 0.13

   .. attribute:: router

      Read-only property that returns *router instance*.

   .. attribute:: logger

      :class:`logging.Logger` instance for storing application logs.

   .. attribute:: loop

      :ref:`event loop<asyncio-event-loop>` used for processing HTTP requests.

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

         yield from loop.create_server(app.make_handler(),
                                       '0.0.0.0', 8080)

   .. coroutinemethod:: finish()

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

   Straightforward url-matching router, implements
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

   .. method:: add_route(method, path, handler, *, \
                         name=None, expect_handler=None)

      Append :ref:`handler<aiohttp-web-handler>` to the end of route table.

      *path* may be either *constant* string like ``'/a/b/c'`` or
       *variable rule* like ``'/a/{var}'`` (see
       :ref:`handling variable pathes<aiohttp-web-variable-handler>`)

      Pay attention please: *handler* is converted to coroutine internally when
      it is a regular function.

      :param str method: HTTP method for route. Should be one of
                         ``'GET'``, ``'POST'``, ``'PUT'``,
                         ``'DELETE'``, ``'PATCH'``, ``'HEAD'``,
                         ``'OPTIONS'`` or ``'*'`` for any method.

                         The parameter is case-insensitive, e.g. you
                         can push ``'get'`` as well as ``'GET'``.

      :param str path: route path

      :param callable handler: route handler

      :param str name: optional route name.

      :param coroutine expect_handler: optional *expect* header handler.

      :returns: new :class:`PlainRoute` or :class:`DynamicRoute` instance.

   .. method:: add_static(prefix, path, *, name=None, expect_handler=None, \
                          chunk_size=256*1024)

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

      :param coroutine expect_handler: optional *expect* header handler.

      :param int chunk_size: size of single chunk for file
                             downloading, 64Kb by default.

                             Increasing *chunk_size* parameter to,
                             say, 1Mb may increase file downloading
                             speed but consumes more memory.

                             .. versionadded:: 0.16

   :returns: new :class:`StaticRoute` instance.

   .. coroutinemethod:: resolve(requst)

      A :ref:`coroutine<coroutine>` that returns
      :class:`AbstractMatchInfo` for *request*.

      The method never raises exception, but returns
      :class:`AbstractMatchInfo` instance with:

      1. :attr:`~AbstractMatchInfo.route` asigned to
         :class:`SystemRoute` instance
      2. :attr:`~AbstractMatchInfo.handler` which raises
         :exc:`HTTPNotFound` or :exc:`HTTPMethodNotAllowed` on handler's
         execution if there is no registered route for *request*.

         *Middlewares* can process that exceptions to render
         pretty-looking error page for example.

      Used by internal machinery, end user unlikely need to call the method.

      .. versionchanged:: 0.14

         The method don't raise :exc:`HTTPNotFound` and
         :exc:`HTTPMethodNotAllowed` anymore.


.. _aiohttp-web-route:

Route
^^^^^

Default router :class:`UrlDispatcher` operates with *routes*.

User should not instantiate route classes by hand but can give *named
route instance* by ``router[name]`` if he have added route by
:meth:`UrlDispatcher.add_route` or :meth:`UrlDispatcher.add_static`
calls with non-empty *name* parameter.

The main usage of *named routes* is constructing URL by route name for
passing it into *template engine* for example::

   url = app.router['route_name'].url(query={'a': 1, 'b': 2})

There are three concrete route classes:* :class:`DynamicRoute` for
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

       >>> route.url(parts={'name1': 'b', 'name2': 'c'},
                     query={'d': 1, 'e': 2})
       '/a/b/c/?d=1&e=2'


.. class:: StaticRoute

   The route class for handling static files, created by
   :meth:`UrlDispatcher.add_static` call.

   .. method:: url(*, filename, query=None)

   Construct url for given *filename*::

      >>> route.url(filename='img/logo.png', query={'param': 1})
      '/path/to/static/img/logo.png?param=1'


.. class:: SystemRoute

   The route class for internal purposes.

   Now it has used for handling *404: Not Found* and *405: Method Not Allowed*.

   .. method:: url()

   Always raises :exc:`RuntimeError`, :class:`SystemRoute` should not
   be used in url construction expressions.


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
