.. _aiohttp-web-reference:

Server Reference
================

.. module:: aiohttp.web

.. currentmodule:: aiohttp.web

.. _aiohttp-web-request:


Request and Base Request
------------------------

The Request object contains all the information about an incoming HTTP request.

:class:`BaseRequest` is used for :ref:`Low-Level
Servers<aiohttp-web-lowlevel>` (which have no applications, routers, signals
and middlewares) and :class:`Request` has an *application* and *match
info* attributes.

A :class:`BaseRequest`/:class:`Request` are :obj:`dict`-like objects,
allowing them to be used for :ref:`sharing
data<aiohttp-web-data-sharing>` among :ref:`aiohttp-web-middlewares`
and :ref:`aiohttp-web-signals` handlers.

.. class:: BaseRequest

   .. attribute:: version

      *HTTP version* of request, Read-only property.

      Returns :class:`aiohttp.protocol.HttpVersion` instance.

   .. attribute:: method

      *HTTP method*, read-only property.

      The value is upper-cased :class:`str` like ``"GET"``,
      ``"POST"``, ``"PUT"`` etc.

   .. attribute:: url

      A :class:`~yarl.URL` instance with absolute URL to resource
      (*scheme*, *host* and *port* are included).

      .. note::

         In case of malformed request (e.g. without ``"HOST"`` HTTP
         header) the absolute url may be unavailable.

   .. attribute:: rel_url

      A :class:`~yarl.URL` instance with relative URL to resource
      (contains *path*, *query* and *fragment* parts only, *scheme*,
      *host* and *port* are excluded).

      The property is equal to ``.url.relative()`` but is always present.

      .. seealso::

         A note from :attr:`url`.

   .. attribute:: scheme

      A string representing the scheme of the request.

      The scheme is ``'https'`` if transport for request handling is *SSL*, if
      ``secure_proxy_ssl_header`` is matching (deprecated), if the ``proto``
      portion of a ``Forward`` header is present and contains ``https``, or if
      an ``X-Forwarded-Proto`` header is present and contains ``https``.

      ``'http'`` otherwise.

      Read-only :class:`str` property.

      .. seealso:: :meth:`Application.make_handler`

      .. deprecated:: 1.1

         Use :attr:`url` (``request.url.scheme``) instead.

   .. attribute:: secure

      Shorthand for ``request.url.scheme == 'https'``

      Read-only :class:`bool` property.

      .. seealso:: :attr:`scheme`

   .. attribute:: forwarded

      A tuple containing all parsed Forwarded header(s).

      Makes an effort to parse Forwarded headers as specified by :rfc:`7239`:

      - It adds one (immutable) dictionary per Forwarded ``field-value``, i.e.
        per proxy. The element corresponds to the data in the Forwarded
        ``field-value`` added by the first proxy encountered by the client.
        Each subsequent item corresponds to those added by later proxies.
      - It checks that every value has valid syntax in general as specified
        in :rfc:`7239#section-4`: either a ``token`` or a ``quoted-string``.
      - It un-escapes ``quoted-pairs``.
      - It does NOT validate 'by' and 'for' contents as specified in
        :rfc:`7239#section-6`.
      - It does NOT validate ``host`` contents (Host ABNF).
      - It does NOT validate ``proto`` contents for valid URI scheme names.

      Returns a tuple containing one or more ``MappingProxy`` objects

      .. seealso:: :attr:`scheme`

      .. seealso:: :attr:`host`

   .. attribute:: host

      Host name of the request.

      Host name is resolved through the following headers, in this order:

      - *Forwarded*
      - *X-Forwarded-Host*
      - *Host*

      Returns  :class:`str`, or ``None`` if no host name is found in the
      headers.

   .. attribute:: path_qs

      The URL including PATH_INFO and the query string. e.g.,
      ``/app/blog?id=10``

      Read-only :class:`str` property.

   .. attribute:: path

      The URL including *PATH INFO* without the host or scheme. e.g.,
      ``/app/blog``. The path is URL-unquoted. For raw path info see
      :attr:`raw_path`.

      Read-only :class:`str` property.

   .. attribute:: raw_path

      The URL including raw *PATH INFO* without the host or scheme.
      Warning, the path may be quoted and may contains non valid URL characters, e.g.
      ``/my%2Fpath%7Cwith%21some%25strange%24characters``.

      For unquoted version please take a look on :attr:`path`.

      Read-only :class:`str` property.

   .. attribute:: query

      A multidict with all the variables in the query string.

      Read-only :class:`~multidict.MultiDictProxy` lazy property.

   .. attribute:: query_string

      The query string in the URL, e.g., ``id=10``

      Read-only :class:`str` property.

   .. attribute:: headers

      A case-insensitive multidict proxy with all headers.

      Read-only :class:`~multidict.CIMultiDictProxy` property.

   .. attribute:: raw_headers

      HTTP headers of response as unconverted bytes, a sequence of
      ``(key, value)`` pairs.

   .. attribute:: keep_alive

      ``True`` if keep-alive connection enabled by HTTP client and
      protocol version supports it, otherwise ``False``.

      Read-only :class:`bool` property.

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

      Read-only :class:`~multidict.MultiDictProxy` lazy property.

   .. attribute:: content

      A :class:`~aiohttp.StreamReader` instance,
      input stream for reading request's *BODY*.

      Read-only property.

   .. attribute:: has_body

      Return ``True`` if request has *HTTP BODY*, ``False`` otherwise.

      Read-only :class:`bool` property.

      .. versionadded:: 0.16

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

   .. attribute:: http_range

      Read-only property that returns information about *Range* HTTP header.

      Returns a :class:`slice` where ``.start`` is *left inclusive
      bound*, ``.stop`` is *right exclusive bound* and ``.step`` is
      ``1``.

      The property might be used in two manners:

      1. Attribute-access style (example assumes that both left and
         right borders are set, the real logic for case of open bounds
         is more complex)::

            rng = request.http_range
            with open(filename, 'rb') as f:
                f.seek(rng.start)
                return f.read(rng.stop-rng.start)

      2. Slice-style::

            return buffer[request.http_range]

      .. versionadded:: 1.2

   .. attribute:: if_modified_since

      Read-only property that returns the date specified in the
      *If-Modified-Since* header.

      Returns :class:`datetime.datetime` or ``None`` if
      *If-Modified-Since* header is absent or is not a valid
      HTTP date.

   .. method:: clone(*, method=..., rel_url=..., headers=...)

      Clone itself with replacement some attributes.

      Creates and returns a new instance of Request object. If no parameters
      are given, an exact copy is returned. If a parameter is not passed, it
      will reuse the one from the current request object.

      :param str method: http method

      :param rel_url: url to use, :class:`str` or :class:`~yarl.URL`

      :param headers: :class:`~multidict.CIMultidict` or compatible
                      headers container.

      :return: a cloned :class:`Request` instance.

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

   .. coroutinemethod:: json(*, loads=json.loads)

      Read request body decoded as *json*.

      The method is just a boilerplate :ref:`coroutine <coroutine>`
      implemented as::

         async def json(self, *, loads=json.loads):
             body = await self.text()
             return loads(body)

      :param callable loads: any :term:`callable` that accepts
                              :class:`str` and returns :class:`dict`
                              with parsed JSON (:func:`json.loads` by
                              default).

      .. note::

         The method **does** store read data internally, subsequent
         :meth:`~Request.json` call will return the same value.


   .. coroutinemethod:: multipart(*, reader=aiohttp.multipart.MultipartReader)

      Returns :class:`aiohttp.multipart.MultipartReader` which processes
      incoming *multipart* request.

      The method is just a boilerplate :ref:`coroutine <coroutine>`
      implemented as::

         async def multipart(self, *, reader=aiohttp.multipart.MultipartReader):
             return reader(self.headers, self._payload)

      This method is a coroutine for consistency with the else reader methods.

      .. warning::

         The method **does not** store read data internally. That means once
         you exhausts multipart reader, you cannot get the request payload one
         more time.

      .. seealso:: :ref:`aiohttp-multipart`

   .. coroutinemethod:: post()

      A :ref:`coroutine <coroutine>` that reads POST parameters from
      request body.

      Returns :class:`~multidict.MultiDictProxy` instance filled
      with parsed data.

      If :attr:`method` is not *POST*, *PUT*, *PATCH*, *TRACE* or *DELETE* or
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


.. class:: Request

   An request used for receiving request's information by *web handler*.

   Every :ref:`handler<aiohttp-web-handler>` accepts a request
   instance as the first positional parameter.

   The class in derived from :class:`BaseRequest`, shares all parent's
   attributes and methods but has a couple of additional properties:

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

   .. note::

      You should never create the :class:`Request` instance manually
      -- :mod:`aiohttp.web` does it for you. But
      :meth:`~BaseRequest.clone` may be used for cloning *modified*
      request copy with changed *path*, *method* etc.



.. _aiohttp-web-response:


Response classes
----------------

For now, :mod:`aiohttp.web` has three classes for the *HTTP response*:
:class:`StreamResponse`, :class:`Response` and :class:`FileResponse`.

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

   That means you can do any manipulations with *headers*, *cookies*
   and *status code* only before :meth:`prepare` coroutine is called.

   Once you call :meth:`prepare` any change of
   the *HTTP header* part will raise :exc:`RuntimeError` exception.

   Any :meth:`write` call after :meth:`write_eof` is also forbidden.

   :param int status: HTTP status code, ``200`` by default.

   :param str reason: HTTP reason. If param is ``None`` reason will be
                      calculated basing on *status*
                      parameter. Otherwise pass :class:`str` with
                      arbitrary *status* explanation..

   .. attribute:: prepared

      Read-only :class:`bool` property, ``True`` if :meth:`prepare` has
      been called, ``False`` otherwise.

      .. versionadded:: 0.18

   .. attribute:: task

      A task that serves HTTP request handling.

      May be useful for graceful shutdown of long-running requests
      (streaming, long polling or web-socket).

      .. versionadded:: 1.2

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

      .. seealso:: :meth:`enable_compression`

   .. method:: enable_compression(force=None)

      Enable compression.

      When *force* is unset compression encoding is selected based on
      the request's *Accept-Encoding* header.

      *Accept-Encoding* is not checked if *force* is set to a
      :class:`ContentCoding`.

      .. seealso:: :attr:`compression`

   .. attribute:: chunked

      Read-only property, indicates if chunked encoding is on.

      Can be enabled by :meth:`enable_chunked_encoding` call.

      .. seealso:: :attr:`enable_chunked_encoding`

   .. method:: enable_chunked_encoding

      Enables :attr:`chunked` encoding for response. There are no ways to
      disable it back. With enabled :attr:`chunked` encoding each `write()`
      operation encoded in separate chunk.

      .. warning:: chunked encoding can be enabled for ``HTTP/1.1`` only.

                   Setting up both :attr:`content_length` and chunked
                   encoding is mutually exclusive.

      .. seealso:: :attr:`chunked`

   .. attribute:: headers

      :class:`~aiohttp.CIMultiiDct` instance
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

      .. warning::

         In HTTP version 1.1, ``expires`` was deprecated and replaced with
         the easier-to-use ``max-age``, but Internet Explorer (IE6, IE7,
         and IE8) **does not** support ``max-age``.

   .. method:: del_cookie(name, *, path='/', domain=None)

      Deletes cookie.

      :param str name: cookie name

      :param str domain: optional cookie domain

      :param str path: optional cookie path, ``'/'`` by default

      .. versionchanged:: 1.0

         Fixed cookie expiration support for
         Internet Explorer (version less than 11).

   .. attribute:: content_length

      *Content-Length* for outgoing response.

   .. attribute:: content_type

      *Content* part of *Content-Type* for outgoing response.

   .. attribute:: charset

      *Charset* aka *encoding* part of *Content-Type* for outgoing response.

      The value converted to lower-case on attribute assigning.

   .. attribute:: last_modified

      *Last-Modified* header for outgoing response.

      This property accepts raw :class:`str` values,
      :class:`datetime.datetime` objects, Unix timestamps specified
      as an :class:`int` or a :class:`float` object, and the
      value ``None`` to unset the header.

   .. attribute:: tcp_cork

      :const:`~socket.TCP_CORK` (linux) or :const:`~socket.TCP_NOPUSH`
      (FreeBSD and MacOSX) is applied to underlying transport if the
      property is ``True``.

      Use :meth:`set_tcp_cork` to assign new value to the property.

      Default value is ``False``.

   .. method:: set_tcp_cork(value)

      Set :attr:`tcp_cork` property to *value*.

      Clear :attr:`tcp_nodelay` if *value* is ``True``.

   .. attribute:: tcp_nodelay

      :const:`~socket.TCP_NODELAY` is applied to underlying transport
      if the property is ``True``.

      Use :meth:`set_tcp_nodelay` to assign new value to the property.

      Default value is ``True``.

   .. method:: set_tcp_nodelay(value)

      Set :attr:`tcp_nodelay` property to *value*.

      Clear :attr:`tcp_cork` if *value* is ``True``.

   .. coroutinemethod:: prepare(request)

      :param aiohttp.web.Request request: HTTP request object, that the
                                          response answers.

      Send *HTTP header*. You should not change any header data after
      calling this method.

      The coroutine calls :attr:`~aiohttp.web.Application.on_response_prepare`
      signal handlers.

      .. versionadded:: 0.18

   .. method:: write(data)

      Send byte-ish data as the part of *response BODY*.

      :meth:`prepare` must be called before.

      Raises :exc:`TypeError` if data is not :class:`bytes`,
      :class:`bytearray` or :class:`memoryview` instance.

      Raises :exc:`RuntimeError` if :meth:`prepare` has not been called.

      Raises :exc:`RuntimeError` if :meth:`write_eof` has been called.

   .. coroutinemethod:: drain()

      A :ref:`coroutine<coroutine>` to let the write buffer of the
      underlying transport a chance to be flushed.

      The intended use is to write::

          resp.write(data)
          await resp.drain()

      Yielding from :meth:`drain` gives the opportunity for the loop
      to schedule the write operation and flush the buffer. It should
      especially be used when a possibly large amount of data is
      written to the transport, and the coroutine does not yield-from
      between calls to :meth:`write`.

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
                    charset=None, body=None, text=None)

   The most usable response class, inherited from :class:`StreamResponse`.

   Accepts *body* argument for setting the *HTTP response BODY*.

   The actual :attr:`body` sending happens in overridden
   :meth:`~StreamResponse.write_eof`.

   :param bytes body: response's BODY

   :param int status: HTTP status code, 200 OK by default.

   :param collections.abc.Mapping headers: HTTP headers that should be added to
                           response's ones.

   :param str text: response's BODY

   :param str content_type: response's content type. ``'text/plain'``
                       if *text* is passed also,
                       ``'application/octet-stream'`` otherwise.

   :param str charset: response's charset. ``'utf-8'`` if *text* is
                       passed also, ``None`` otherwise.


   .. attribute:: body

      Read-write attribute for storing response's content aka BODY,
      :class:`bytes`.

      Setting :attr:`body` also recalculates
      :attr:`~StreamResponse.content_length` value.

      Resetting :attr:`body` (assigning ``None``) sets
      :attr:`~StreamResponse.content_length` to ``None`` too, dropping
      *Content-Length* HTTP header.

   .. attribute:: text

      Read-write attribute for storing response's content, represented as
      string, :class:`str`.

      Setting :attr:`text` also recalculates
      :attr:`~StreamResponse.content_length` value and
      :attr:`~StreamResponse.body` value

      Resetting :attr:`text` (assigning ``None``) sets
      :attr:`~StreamResponse.content_length` to ``None`` too, dropping
      *Content-Length* HTTP header.


WebSocketResponse
^^^^^^^^^^^^^^^^^

.. class:: WebSocketResponse(*, timeout=10.0, receive_timeout=None, autoclose=True, \
                             autoping=True, heartbeat=None, protocols=())

   Class for handling server-side websockets, inherited from
   :class:`StreamResponse`.

   After starting (by :meth:`prepare` call) the response you
   cannot use :meth:`~StreamResponse.write` method but should to
   communicate with websocket client by :meth:`send_str`,
   :meth:`receive` and others.

   .. versionadded:: 1.3.0

   To enable back-pressure from slow websocket clients treat methods
   `ping()`, `pong()`, `send_str()`, `send_bytes()`, `send_json()` as coroutines.
   By default write buffer size is set to 64k.

   :param bool autoping: Automatically send
                         :const:`~aiohttp.WSMsgType.PONG` on
                         :const:`~aiohttp.WSMsgType.PING`
                         message from client, and handle
                         :const:`~aiohttp.WSMsgType.PONG`
                         responses from client.
                         Note that server does not send
                         :const:`~aiohttp.WSMsgType.PING`
                         requests, you need to do this explicitly
                         using :meth:`ping` method.

   .. versionadded:: 1.3.0

   :param float heartbeat: Send `ping` message every `heartbeat` seconds
                           and wait `pong` response, close connection if `pong` response
                           is not received.

   :param float receive_timeout: Timeout value for `receive` operations.
                                 Default value is None (no timeout for receive operation)

   .. versionadded:: 0.19

      The class supports ``async for`` statement for iterating over
      incoming messages::

         ws = web.WebSocketResponse()
         await ws.prepare(request)

         async for msg in ws:
             print(msg.data)


   .. coroutinemethod:: prepare(request)

      Starts websocket. After the call you can use websocket methods.

      :param aiohttp.web.Request request: HTTP request object, that the
                                          response answers.


      :raises HTTPException: if websocket handshake has failed.

      .. versionadded:: 0.18

   .. method:: can_prepare(request)

      Performs checks for *request* data to figure out if websocket
      can be started on the request.

      If :meth:`can_prepare` call is success then :meth:`prepare` will
      success too.

      :param aiohttp.web.Request request: HTTP request object, that the
                                          response answers.

      :return: :class:`WebSocketReady` instance.

               :attr:`WebSocketReady.ok` is
               ``True`` on success, :attr:`WebSocketReady.protocol` is
               websocket subprotocol which is passed by client and
               accepted by server (one of *protocols* sequence from
               :class:`WebSocketResponse` ctor).
               :attr:`WebSocketReady.protocol` may be ``None`` if
               client and server subprotocols are not overlapping.

      .. note:: The method never raises exception.

   .. attribute:: closed

      Read-only property, ``True`` if connection has been closed or in process
      of closing.
      :const:`~aiohttp.WSMsgType.CLOSE` message has been received from peer.

   .. attribute:: close_code

      Read-only property, close code from peer. It is set to ``None`` on
      opened connection.

   .. attribute:: protocol

      Websocket *subprotocol* chosen after :meth:`start` call.

      May be ``None`` if server and client protocols are
      not overlapping.

   .. method:: exception()

      Returns last occurred exception or None.

   .. method:: ping(message=b'')

      Send :const:`~aiohttp.WSMsgType.PING` to peer.

      :param message: optional payload of *ping* message,
                      :class:`str` (converted to *UTF-8* encoded bytes)
                      or :class:`bytes`.

      :raise RuntimeError: if connections is not started or closing.

   .. method:: pong(message=b'')

      Send *unsolicited* :const:`~aiohttp.WSMsgType.PONG` to peer.

      :param message: optional payload of *pong* message,
                      :class:`str` (converted to *UTF-8* encoded bytes)
                      or :class:`bytes`.

      :raise RuntimeError: if connections is not started or closing.

   .. coroutinemethod:: send_str(data)

      Send *data* to peer as :const:`~aiohttp.WSMsgType.TEXT` message.

      :param str data: data to send.

      :raise RuntimeError: if connection is not started or closing

      :raise TypeError: if data is not :class:`str`

   .. coroutinemethod:: send_bytes(data)

      Send *data* to peer as :const:`~aiohttp.WSMsgType.BINARY` message.

      :param data: data to send.

      :raise RuntimeError: if connection is not started or closing

      :raise TypeError: if data is not :class:`bytes`,
                        :class:`bytearray` or :class:`memoryview`.

   .. coroutinemethod:: send_json(data, *, dumps=json.loads)

      Send *data* to peer as JSON string.

      :param data: data to send.

      :param callable dumps: any :term:`callable` that accepts an object and
                             returns a JSON string
                             (:func:`json.dumps` by default).

      :raise RuntimeError: if connection is not started or closing

      :raise ValueError: if data is not serializable object

      :raise TypeError: if value returned by ``dumps`` param is not :class:`str`

   .. coroutinemethod:: close(*, code=1000, message=b'')

      A :ref:`coroutine<coroutine>` that initiates closing
      handshake by sending :const:`~aiohttp.WSMsgType.CLOSE` message.

      It is save to call `close()` from different task.

      :param int code: closing code

      :param message: optional payload of *pong* message,
                      :class:`str` (converted to *UTF-8* encoded bytes)
                      or :class:`bytes`.

      :raise RuntimeError: if connection is not started

   .. coroutinemethod:: receive(timeout=None)

      A :ref:`coroutine<coroutine>` that waits upcoming *data*
      message from peer and returns it.

      The coroutine implicitly handles
      :const:`~aiohttp.WSMsgType.PING`,
      :const:`~aiohttp.WSMsgType.PONG` and
      :const:`~aiohttp.WSMsgType.CLOSE` without returning the
      message.

      It process *ping-pong game* and performs *closing handshake* internally.

      .. note::

         Can only be called by the request handling task.

      :param timeout: timeout for `receive` operation.
                      timeout value overrides response`s receive_timeout attribute.

      :return: :class:`~aiohttp.WSMessage`

      :raise RuntimeError: if connection is not started

   .. coroutinemethod:: receive_str(*, timeout=None)

      A :ref:`coroutine<coroutine>` that calls :meth:`receive` but
      also asserts the message type is :const:`~aiohttp.WSMsgType.TEXT`.

      .. note::

         Can only be called by the request handling task.

      :param timeout: timeout for `receive` operation.
                      timeout value overrides response`s receive_timeout attribute.

      :return str: peer's message content.

      :raise TypeError: if message is :const:`~aiohttp.WSMsgType.BINARY`.

   .. coroutinemethod:: receive_bytes(*, timeout=None)

      A :ref:`coroutine<coroutine>` that calls :meth:`receive` but
      also asserts the message type is
      :const:`~aiohttp.WSMsgType.BINARY`.

      .. note::

         Can only be called by the request handling task.

      :param timeout: timeout for `receive` operation.
                      timeout value overrides response`s receive_timeout attribute.

      :return bytes: peer's message content.

      :raise TypeError: if message is :const:`~aiohttp.WSMsgType.TEXT`.

   .. coroutinemethod:: receive_json(*, loads=json.loads, timeout=None)

      A :ref:`coroutine<coroutine>` that calls :meth:`receive_str` and loads the
      JSON string to a Python dict.

      .. note::

         Can only be called by the request handling task.

      :param callable loads: any :term:`callable` that accepts
                              :class:`str` and returns :class:`dict`
                              with parsed JSON (:func:`json.loads` by
                              default).

   :param timeout: timeout for `receive` operation.
                      timeout value overrides response`s receive_timeout attribute.

      :return dict: loaded JSON content

      :raise TypeError: if message is :const:`~aiohttp.WSMsgType.BINARY`.
      :raise ValueError: if message is not valid JSON.

      .. versionadded:: 0.22


.. seealso:: :ref:`WebSockets handling<aiohttp-web-websockets>`


WebSocketReady
^^^^^^^^^^^^^^

.. class:: WebSocketReady

   A named tuple for returning result from
   :meth:`WebSocketResponse.can_prepare`.

   Has :class:`bool` check implemented, e.g.::

       if not await ws.can_prepare(...):
           cannot_start_websocket()

   .. attribute:: ok

      ``True`` if websocket connection can be established, ``False``
      otherwise.


   .. attribute:: protocol

      :class:`str` represented selected websocket sub-protocol.

   .. seealso:: :meth:`WebSocketResponse.can_prepare`


json_response
-------------

.. function:: json_response([data], *, text=None, body=None, \
                            status=200, reason=None, headers=None, \
                            content_type='application/json', \
                            dumps=json.dumps)

Return :class:`Response` with predefined ``'application/json'``
content type and *data* encoded by ``dumps`` parameter
(:func:`json.dumps` by default).


.. _aiohttp-web-app-and-router:

Application and Router
----------------------


Application
^^^^^^^^^^^

Application is a synonym for web-server.

To get fully working example, you have to make *application*, register
supported urls in *router* and create a *server socket* with
:class:`~aiohttp.web.Server` as a *protocol
factory*. *Server* could be constructed with
:meth:`Application.make_handler`.

*Application* contains a *router* instance and a list of callbacks that
will be called during application finishing.

:class:`Application` is a :obj:`dict`-like object, so you can use it for
:ref:`sharing data<aiohttp-web-data-sharing>` globally by storing arbitrary
properties for later access from a :ref:`handler<aiohttp-web-handler>` via the
:attr:`Request.app` property::

   app = Application()
   app['database'] = await aiopg.create_engine(**db_config)

   async def handler(request):
       with (await request.app['database']) as conn:
           conn.execute("DELETE * FROM table")

Although :class:`Application` is a :obj:`dict`-like object, it can't be
duplicated like one using :meth:`Application.copy`.

.. class:: Application(*, router=None, logger=<default>, \
                       middlewares=(), debug=False, **kwargs)

   The class inherits :class:`dict`.

   :param router: :class:`aiohttp.abc.AbstractRouter` instance, the system
                  creates :class:`UrlDispatcher` by default if
                  *router* is ``None``.

   :param logger: :class:`logging.Logger` instance for storing application logs.

                  By default the value is ``logging.getLogger("aiohttp.web")``

   :param middlewares: :class:`list` of middleware factories, see
                       :ref:`aiohttp-web-middlewares` for details.

   :param debug: Switches debug mode.

   :param loop: loop parameter is deprecated. loop is get set during freeze stage.

   .. attribute:: router

      Read-only property that returns *router instance*.

   .. attribute:: logger

      :class:`logging.Logger` instance for storing application logs.

   .. attribute:: loop

      :ref:`event loop<asyncio-event-loop>` used for processing HTTP requests.


   .. attribute:: debug

      Boolean value indicating whether the debug mode is turned on or off.

   .. attribute:: on_response_prepare

      A :class:`~aiohttp.signals.Signal` that is fired at the beginning
      of :meth:`StreamResponse.prepare` with parameters *request* and
      *response*. It can be used, for example, to add custom headers to each
      response before sending.

      Signal handlers should have the following signature::

          async def on_prepare(request, response):
              pass

   .. attribute:: on_startup

      A :class:`~aiohttp.signals.Signal` that is fired on application start-up.

      Subscribers may use the signal to run background tasks in the event
      loop along with the application's request handler just after the
      application start-up.

      Signal handlers should have the following signature::

          async def on_startup(app):
              pass

      .. seealso:: :ref:`aiohttp-web-background-tasks`.

   .. attribute:: on_shutdown

      A :class:`~aiohttp.signals.Signal` that is fired on application shutdown.

      Subscribers may use the signal for gracefully closing long running
      connections, e.g. websockets and data streaming.

      Signal handlers should have the following signature::

          async def on_shutdown(app):
              pass

      It's up to end user to figure out which :term:`web-handler`\s
      are still alive and how to finish them properly.

      We suggest keeping a list of long running handlers in
      :class:`Application` dictionary.

      .. seealso:: :ref:`aiohttp-web-graceful-shutdown` and :attr:`on_cleanup`.

   .. attribute:: on_cleanup

      A :class:`~aiohttp.signals.Signal` that is fired on application cleanup.

      Subscribers may use the signal for gracefully closing
      connections to database server etc.

      Signal handlers should have the following signature::

          async def on_cleanup(app):
              pass

      .. seealso:: :ref:`aiohttp-web-graceful-shutdown` and :attr:`on_shutdown`.

   .. method:: make_handler(loop=None, **kwargs)

    Creates HTTP protocol factory for handling requests.

    :param loop: :ref:`event loop<asyncio-event-loop>` used
                 for processing HTTP requests.

                 If param is ``None`` :func:`asyncio.get_event_loop`
                 used for getting default event loop.

    :param tuple secure_proxy_ssl_header: Default: ``None``.

      .. deprecated:: 2.1

        See ``request.url.scheme`` for built-in resolution of the current
        scheme using the standard and de-facto standard headers.

    :param bool tcp_keepalive: Enable TCP Keep-Alive. Default: ``True``.
    :param int keepalive_timeout: Number of seconds before closing Keep-Alive
      connection. Default: ``75`` seconds (NGINX's default value).
    :param slow_request_timeout: Slow request timeout. Default: ``0``.
    :param logger: Custom logger object. Default:
      :data:`aiohttp.log.server_logger`.
    :param access_log: Custom logging object. Default:
      :data:`aiohttp.log.access_logger`.
    :param str access_log_format: Access log format string. Default:
      :attr:`helpers.AccessLogger.LOG_FORMAT`.
    :param bool debug: Switches debug mode. Default: ``False``.

      .. deprecated:: 1.0

        The usage of ``debug`` parameter in :meth:`Application.make_handler`
        is deprecated in favor of :attr:`Application.debug`.
        The :class:`Application`'s debug mode setting should be used
        as a single point to setup a debug mode.

    :param int max_line_size: Optional maximum header line size. Default:
      ``8190``.
    :param int max_headers: Optional maximum header size. Default: ``32768``.
    :param int max_field_size: Optional maximum header field size. Default:
      ``8190``.

    :param float lingering_time: maximum time during which the server
       reads and ignore additional data coming from the client when
       lingering close is on.  Use ``0`` for disabling lingering on
       server channel closing.

    :param float lingering_timeout: maximum waiting time for more
        client data to arrive when lingering close is in effect

    You should pass result of the method as *protocol_factory* to
    :meth:`~asyncio.AbstractEventLoop.create_server`, e.g.::

       loop = asyncio.get_event_loop()

       app = Application(loop=loop)

       # setup route table
       # app.router.add_route(...)

       await loop.create_server(app.make_handler(),
                                '0.0.0.0', 8080)

   .. coroutinemethod:: startup()

      A :ref:`coroutine<coroutine>` that will be called along with the
      application's request handler.

      The purpose of the method is calling :attr:`on_startup` signal
      handlers.

   .. coroutinemethod:: shutdown()

      A :ref:`coroutine<coroutine>` that should be called on
      server stopping but before :meth:`cleanup()`.

      The purpose of the method is calling :attr:`on_shutdown` signal
      handlers.

   .. coroutinemethod:: cleanup()

      A :ref:`coroutine<coroutine>` that should be called on
      server stopping but after :meth:`shutdown`.

      The purpose of the method is calling :attr:`on_cleanup` signal
      handlers.

   .. note::

      Application object has :attr:`router` attribute but has no
      ``add_route()`` method. The reason is: we want to support
      different router implementations (even maybe not url-matching
      based but traversal ones).

      For sake of that fact we have very trivial ABC for
      :class:`AbstractRouter`: it should have only
      :meth:`AbstractRouter.resolve` coroutine.

      No methods for adding routes or route reversing (getting URL by
      route name). All those are router implementation details (but,
      sure, you need to deal with that methods after choosing the
      router for your application).


Server
^^^^^^

A protocol factory compatible with
:meth:`~asyncio.AbstreactEventLoop.create_server`.

      .. class:: Server

   The class is responsible for creating HTTP protocol
   objects that can handle HTTP connections.

   .. attribute:: Server.connections

      List of all currently opened connections.

   .. attribute:: requests_count

      Amount of processed requests.

      .. versionadded:: 1.0

   .. coroutinemethod:: Server.shutdown(timeout)

      A :ref:`coroutine<coroutine>` that should be called to close all opened
      connections.

   .. coroutinemethod:: Server.finish_connections(timeout)

      .. deprecated:: 1.2

         A deprecated alias for :meth:`shutdown`.

   .. versionchanged:: 1.2

      ``Server`` was called ``RequestHandlerFactory`` before ``aiohttp==1.2``.

      The rename has no deprecation period but it's safe: no user
      should instantiate the class by hands.


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

   .. method:: add_resource(path, *, name=None)

      Append a :term:`resource` to the end of route table.

      *path* may be either *constant* string like ``'/a/b/c'`` or
      *variable rule* like ``'/a/{var}'`` (see
      :ref:`handling variable paths <aiohttp-web-variable-handler>`)

      :param str path: resource path spec.

      :param str name: optional resource name.

      :return: created resource instance (:class:`PlainResource` or
               :class:`DynamicResource`).

   .. method:: add_route(method, path, handler, *, \
                         name=None, expect_handler=None)

      Append :ref:`handler<aiohttp-web-handler>` to the end of route table.

      *path* may be either *constant* string like ``'/a/b/c'`` or
       *variable rule* like ``'/a/{var}'`` (see
       :ref:`handling variable paths <aiohttp-web-variable-handler>`)

      Pay attention please: *handler* is converted to coroutine internally when
      it is a regular function.

      :param str method: HTTP method for route. Should be one of
                         ``'GET'``, ``'POST'``, ``'PUT'``,
                         ``'DELETE'``, ``'PATCH'``, ``'HEAD'``,
                         ``'OPTIONS'`` or ``'*'`` for any method.

                         The parameter is case-insensitive, e.g. you
                         can push ``'get'`` as well as ``'GET'``.

      :param str path: route path. Should be started with slash (``'/'``).

      :param callable handler: route handler.

      :param str name: optional route name.

      :param coroutine expect_handler: optional *expect* header handler.

      :returns: new :class:`PlainRoute` or :class:`DynamicRoute` instance.

   .. method:: add_get(path, handler, *, name=None, allow_head=True, **kwargs)

      Shortcut for adding a GET handler. Calls the :meth:`add_route` with \
      ``method`` equals to ``'GET'``.

      If *allow_head* is ``True`` (default) the route for method HEAD
      is added with the same handler as for GET.

      If *name* is provided the name for HEAD route is suffixed with
      ``'-head'``. For example ``router.add_get(path, handler,
      name='route')`` call adds two routes: first for GET with name
      ``'route'`` and second for HEAD with name ``'route-head'``.

      .. versionadded:: 1.0

      .. versionchanged:: 2.0

         *allow_head* parameter added.

   .. method:: add_post(path, handler, **kwargs)

      Shortcut for adding a POST handler. Calls the :meth:`add_route` with \


      ``method`` equals to ``'POST'``.

      .. versionadded:: 1.0

   .. method:: add_head(path, handler, **kwargs)

      Shortcut for adding a HEAD handler. Calls the :meth:`add_route` with \
      ``method`` equals to ``'HEAD'``.

      .. versionadded:: 1.0

   .. method:: add_put(path, handler, **kwargs)

      Shortcut for adding a PUT handler. Calls the :meth:`add_route` with \
      ``method`` equals to ``'PUT'``.

      .. versionadded:: 1.0

   .. method:: add_patch(path, handler, **kwargs)

      Shortcut for adding a PATCH handler. Calls the :meth:`add_route` with \
      ``method`` equals to ``'PATCH'``.

      .. versionadded:: 1.0

   .. method:: add_delete(path, handler, **kwargs)

      Shortcut for adding a DELETE handler. Calls the :meth:`add_route` with \
      ``method`` equals to ``'DELETE'``.

      .. versionadded:: 1.0

   .. method:: add_static(prefix, path, *, name=None, expect_handler=None, \
                          chunk_size=256*1024, \
                          response_factory=StreamResponse, \
                          show_index=False, \
                          follow_symlinks=False)

      Adds a router and a handler for returning static files.

      Useful for serving static content like images, javascript and css files.

      On platforms that support it, the handler will transfer files more
      efficiently using the ``sendfile`` system call.

      In some situations it might be necessary to avoid using the ``sendfile``
      system call even if the platform supports it. This can be accomplished by
      by setting environment variable ``AIOHTTP_NOSENDFILE=1``.

      If a gzip version of the static content exists at file path + ``.gz``, it
      will be used for the response.

      .. warning::

         Use :meth:`add_static` for development only. In production,
         static content should be processed by web servers like *nginx*
         or *apache*.

      .. versionchanged:: 0.18.0
         Transfer files using the ``sendfile`` system call on supported
         platforms.

      .. versionchanged:: 0.19.0
         Disable ``sendfile`` by setting environment variable
         ``AIOHTTP_NOSENDFILE=1``

      .. versionchanged:: 1.2.0
         Send gzip version if file path + ``.gz`` exists.

      :param str prefix: URL path prefix for handled static files

      :param path: path to the folder in file system that contains
                   handled static files, :class:`str` or :class:`pathlib.Path`.

      :param str name: optional route name.

      :param coroutine expect_handler: optional *expect* header handler.

      :param int chunk_size: size of single chunk for file
                             downloading, 256Kb by default.

                             Increasing *chunk_size* parameter to,
                             say, 1Mb may increase file downloading
                             speed but consumes more memory.

                             .. versionadded:: 0.16

      :param callable response_factory: factory to use to generate a new
                                        response, defaults to
                                        :class:`StreamResponse` and should
                                        expose a compatible API.

                                        .. versionadded:: 0.17

      :param bool show_index: flag for allowing to show indexes of a directory,
                              by default it's not allowed and HTTP/403 will
                              be returned on directory access.

      :param bool follow_symlinks: flag for allowing to follow symlinks from
                              a directory, by default it's not allowed and
                              HTTP/404 will be returned on access.

      :returns: new :class:`StaticRoute` instance.

   .. method:: add_subapp(prefix, subapp)

      Register nested sub-application under given path *prefix*.

      In resolving process if request's path starts with *prefix* then
      further resolving is passed to *subapp*.

      :param str prefix: path's prefix for the resource.

      :param Application subapp: nested application attached under *prefix*.

      :returns: a :class:`PrefixedSubAppResource` instance.

      .. versionadded:: 1.1

   .. coroutinemethod:: resolve(request)

      A :ref:`coroutine<coroutine>` that returns
      :class:`AbstractMatchInfo` for *request*.

      The method never raises exception, but returns
      :class:`AbstractMatchInfo` instance with:

      1. :attr:`~AbstractMatchInfo.http_exception` assigned to
         :exc:`HTTPException` instance.
      2. :attr:`~AbstractMatchInfo.handler` which raises
         :exc:`HTTPNotFound` or :exc:`HTTPMethodNotAllowed` on handler's
         execution if there is no registered route for *request*.

         *Middlewares* can process that exceptions to render
         pretty-looking error page for example.

      Used by internal machinery, end user unlikely need to call the method.

      .. note:: The method uses :attr:`Request.raw_path` for pattern
         matching against registered routes.

   .. method:: resources()

      The method returns a *view* for *all* registered resources.

      The view is an object that allows to:

      1. Get size of the router table::

           len(app.router.resources())

      2. Iterate over registered resources::

           for resource in app.router.resources():
               print(resource)

      3. Make a check if the resources is registered in the router table::

           route in app.router.resources()

      .. versionadded:: 0.21.1

   .. method:: routes()

      The method returns a *view* for *all* registered routes.

      .. versionadded:: 0.18

   .. method:: named_resources()

      Returns a :obj:`dict`-like :class:`types.MappingProxyType` *view* over
      *all* named **resources**.

      The view maps every named resource's **name** to the
      :class:`BaseResource` instance. It supports the usual
      :obj:`dict`-like operations, except for any mutable operations
      (i.e. it's **read-only**)::

          len(app.router.named_resources())

          for name, resource in app.router.named_resources().items():
              print(name, resource)

          "name" in app.router.named_resources()

          app.router.named_resources()["name"]

      .. versionadded:: 0.21

   .. method:: named_routes()

      An alias for :meth:`named_resources` starting from aiohttp 0.21.

      .. versionadded:: 0.19

      .. versionchanged:: 0.21

         The method is an alias for :meth:`named_resources`, so it
         iterates over resources instead of routes.

      .. deprecated:: 0.21

         Please use named **resources** instead of named **routes**.

         Several routes which belongs to the same resource shares the
         resource name.


.. _aiohttp-web-resource:

Resource
^^^^^^^^

Default router :class:`UrlDispatcher` operates with :term:`resource`\s.

Resource is an item in *routing table* which has a *path*, an optional
unique *name* and at least one :term:`route`.

:term:`web-handler` lookup is performed in the following way:

1. Router iterates over *resources* one-by-one.
2. If *resource* matches to requested URL the resource iterates over
   own *routes*.
3. If route matches to requested HTTP method (or ``'*'`` wildcard) the
   route's handler is used as found :term:`web-handler`. The lookup is
   finished.
4. Otherwise router tries next resource from the *routing table*.
5. If the end of *routing table* is reached and no *resource* /
   *route* pair found the *router* returns special :class:`AbstractMatchInfo`
   instance with :attr:`AbstractMatchInfo.http_exception` is not ``None``
   but :exc:`HTTPException` with  either *HTTP 404 Not Found* or
   *HTTP 405 Method Not Allowed* status code.
   Registered :attr:`AbstractMatchInfo.handler` raises this exception on call.

User should never instantiate resource classes but give it by
:meth:`UrlDispatcher.add_resource` call.

After that he may add a :term:`route` by calling :meth:`Resource.add_route`.

:meth:`UrlDispatcher.add_route` is just shortcut for::

   router.add_resource(path).add_route(method, handler)

Resource with a *name* is called *named resource*.
The main purpose of *named resource* is constructing URL by route name for
passing it into *template engine* for example::

   url = app.router['resource_name'].url_for().with_query({'a': 1, 'b': 2})

Resource classes hierarchy::

   AbstractResource
     Resource
       PlainResource
       DynamicResource
       StaticResource


.. class:: AbstractResource

   A base class for all resources.

   Inherited from :class:`collections.abc.Sized` and
   :class:`collections.abc.Iterable`.

   ``len(resource)`` returns amount of :term:`route`\s belongs to the resource,
   ``for route in resource`` allows to iterate over these routes.

   .. attribute:: name

      Read-only *name* of resource or ``None``.

   .. coroutinemethod:: resolve(method, path)

      Resolve resource by finding appropriate :term:`web-handler` for
      ``(method, path)`` combination.

      :param str method: requested HTTP method.
      :param str path: *path* part of request.

      :return: (*match_info*, *allowed_methods*) pair.

               *allowed_methods* is a :class:`set` or HTTP methods accepted by
               resource.

               *match_info* is either :class:`UrlMappingMatchInfo` if
               request is resolved or ``None`` if no :term:`route` is
               found.

   .. method:: get_info()

      A resource description, e.g. ``{'path': '/path/to'}`` or
      ``{'formatter': '/path/{to}', 'pattern':
      re.compile(r'^/path/(?P<to>[a-zA-Z][_a-zA-Z0-9]+)$``

   .. method:: url_for(*args, **kwargs)

      Construct an URL for route with additional params.

      *args* and **kwargs** depend on a parameters list accepted by
      inherited resource class.

      :return: :class:`~yarl.URL` -- resulting URL instance.

      .. versionadded:: 1.1

   .. method:: url(**kwargs)

      Construct an URL for route with additional params.

      **kwargs** depends on a list accepted by inherited resource
      class parameters.

      :return: :class:`str` -- resulting URL string.

      .. deprecated:: 1.1

         Use :meth:`url_for` instead.


.. class:: Resource

   A base class for new-style resources, inherits :class:`AbstractResource`.


   .. method:: add_route(method, handler, *, expect_handler=None)

      Add a :term:`web-handler` to resource.

      :param str method: HTTP method for route. Should be one of
                         ``'GET'``, ``'POST'``, ``'PUT'``,
                         ``'DELETE'``, ``'PATCH'``, ``'HEAD'``,
                         ``'OPTIONS'`` or ``'*'`` for any method.

                         The parameter is case-insensitive, e.g. you
                         can push ``'get'`` as well as ``'GET'``.

                         The method should be unique for resource.

      :param callable handler: route handler.

      :param coroutine expect_handler: optional *expect* header handler.

      :returns: new :class:`ResourceRoute` instance.


.. class:: PlainResource

   A resource, inherited from :class:`Resource`.

   The class corresponds to resources with plain-text matching,
   ``'/path/to'`` for example.


   .. method:: url_for()

      Returns a :class:`~yarl.URL` for the resource.

      .. versionadded:: 1.1


.. class:: DynamicResource

   A resource, inherited from :class:`Resource`.

   The class corresponds to resources with
   :ref:`variable <aiohttp-web-variable-handler>` matching,
   e.g. ``'/path/{to}/{param}'`` etc.


   .. method:: url_for(**params)

      Returns a :class:`~yarl.URL` for the resource.

      :param params: -- a variable substitutions for dynamic resource.

         E.g. for ``'/path/{to}/{param}'`` pattern the method should
         be called as ``resource.url_for(to='val1', param='val2')``


      .. versionadded:: 1.1

.. class:: StaticResource

   A resource, inherited from :class:`Resource`.

   The class corresponds to resources for :ref:`static file serving
   <aiohttp-web-static-file-handling>`.

   .. method:: url_for(filename)

      Returns a :class:`~yarl.URL` for file path under resource prefix.

      :param filename: -- a file name substitution for static file handler.

         Accepts both :class:`str` and :class:`pathlib.Path`.

         E.g. an URL for ``'/prefix/dir/file.txt'`` should
         be generated as ``resource.url_for(filename='dir/file.txt')``

      .. versionadded:: 1.1

.. class:: PrefixedSubAppResource

   A resource for serving nested applications. The class instance is
   returned by :class:`~aiohttp.web.Application.add_subapp` call.

   .. versionadded:: 1.1

   .. method:: url_for(**kwargs)

      The call is not allowed, it raises :exc:`RuntimeError`.


.. _aiohttp-web-route:

Route
^^^^^

Route has *HTTP method* (wildcard ``'*'`` is an option),
:term:`web-handler` and optional *expect handler*.

Every route belong to some resource.

Route classes hierarchy::

   AbstractRoute
     ResourceRoute
     SystemRoute

:class:`ResourceRoute` is the route used for resources,
:class:`SystemRoute` serves URL resolving errors like *404 Not Found*
and *405 Method Not Allowed*.

.. class:: AbstractRoute

   Base class for routes served by :class:`UrlDispatcher`.

   .. attribute:: method

      HTTP method handled by the route, e.g. *GET*, *POST* etc.

   .. attribute:: handler

      :ref:`handler<aiohttp-web-handler>` that processes the route.

   .. attribute:: name

      Name of the route, always equals to name of resource which owns the route.

   .. attribute:: resource

      Resource instance which holds the route, ``None`` for
      :class:`SystemRoute`.

   .. method:: url_for(*args, **kwargs)

      Abstract method for constructing url handled by the route.

      Actually it's a shortcut for ``route.resource.url_for(...)``.

   .. coroutinemethod:: handle_expect_header(request)

      ``100-continue`` handler.

.. class:: ResourceRoute

   The route class for handling different HTTP methods for :class:`Resource`.


.. class:: SystemRoute

   The route class for handling URL resolution errors like like *404 Not Found*
   and *405 Method Not Allowed*.

   .. attribute:: status

      HTTP status code

   .. attribute:: reason

      HTTP status reason



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
   items are filled by matching info and is :term:`resource`\-specific.

   .. attribute:: expect_handler

      A coroutine for handling ``100-continue``.

   .. attribute:: handler

      A coroutine for handling request.

   .. attribute:: route

      :class:`Route` instance for url matching.


View
^^^^

.. class:: View(request)

   Inherited from :class:`AbstractView`.

   Base class for class based views. Implementations should derive from
   :class:`View` and override methods for handling HTTP verbs like
   ``get()`` or ``post()``::

       class MyView(View):

           async def get(self):
               resp = await get_response(self.request)
               return resp

           async def post(self):
               resp = await post_response(self.request)
               return resp

       app.router.add_route('*', '/view', MyView)

   The view raises *405 Method Not allowed*
   (:class:`HTTPMethodNowAllowed`) if requested web verb is not
   supported.

   :param request: instance of :class:`Request` that has initiated a view
                   processing.


   .. attribute:: request

      Request sent to view's constructor, read-only property.


   Overridable coroutine methods: ``connect()``, ``delete()``,
   ``get()``, ``head()``, ``options()``, ``patch()``, ``post()``,
   ``put()``, ``trace()``.

.. seealso:: :ref:`aiohttp-web-class-based-views`


Utilities
---------

.. class:: FileField

   A :class:`~collections.namedtuple` instance that is returned as
   multidict value by :meth:`Request.POST` if field is uploaded file.

   .. attribute:: name

      Field name

   .. attribute:: filename

      File name as specified by uploading (client) side.

   .. attribute:: file

      An :class:`io.IOBase` instance with content of uploaded file.

   .. attribute:: content_type

      *MIME type* of uploaded file, ``'text/plain'`` by default.

   .. seealso:: :ref:`aiohttp-web-file-upload`


.. function:: run_app(app, *, host=None, port=None, path=None, \
                      sock=None, shutdown_timeout=60.0, \
                      ssl_context=None, print=print, backlog=128, \
                      access_log_format=None, \
                      access_log=aiohttp.log.access_logger, \
                      handle_signals=True, loop=None)

   A utility function for running an application, serving it until
   keyboard interrupt and performing a
   :ref:`aiohttp-web-graceful-shutdown`.

   Suitable as handy tool for scaffolding aiohttp based projects.
   Perhaps production config will use more sophisticated runner but it
   good enough at least at very beginning stage.

   The function uses *app.loop* as event loop to run.

   The server will listen on any host or Unix domain socket path you supply.
   If no hosts or paths are supplied, or only a port is supplied, a TCP server
   listening on 0.0.0.0 (all hosts) will be launched.

   Distributing HTTP traffic to multiple hosts or paths on the same
   application process provides no performance benefit as the requests are
   handled on the same event loop. See :doc:`deployment` for ways of
   distributing work for increased performance.

   :param app: :class:`Application` instance to run

   :param str host: TCP/IP host or a sequence of hosts for HTTP server.
                    Default is ``'0.0.0.0'`` if *port* has been specified
                    or if *path* is not supplied.

   :param int port: TCP/IP port for HTTP server. Default is ``8080`` for plain
                    text HTTP and ``8443`` for HTTP via SSL (when
                    *ssl_context* parameter is specified).

   :param str path: file system path for HTTP server Unix domain socket.
                    A sequence of file system paths can be used to bind
                    multiple domain sockets. Listening on Unix domain
                    sockets is not supported by all operating systems.

   :param socket sock: a preexisting socket object to accept connections on.
                       A sequence of socket objects can be passed.

   :param int shutdown_timeout: a delay to wait for graceful server
                                shutdown before disconnecting all
                                open client sockets hard way.

                                A system with properly
                                :ref:`aiohttp-web-graceful-shutdown`
                                implemented never waits for this
                                timeout but closes a server in a few
                                milliseconds.

   :param ssl_context: :class:`ssl.SSLContext` for HTTPS server,
                       ``None`` for HTTP connection.

   :param print: a callable compatible with :func:`print`. May be used
                 to override STDOUT output or suppress it.

   :param int backlog: the number of unaccepted connections that the
                       system will allow before refusing new
                       connections (``128`` by default).

   :param access_log: :class:`logging.Logger` instance used for saving
                      access logs. Use ``None`` for disabling logs for
                      sake of speedup.

   :param access_log_format: access log format, see
                             :ref:`aiohttp-logging-access-log-format-spec`
                             for details.

   :param bool handle_signals: override signal TERM handling to gracefully
                               exit the application.

   :param loop: an *event loop* used for running the application
                (``None`` by default).

                If the loop is not explicitly specified the function
                closes it by :meth:`~asyncio.AbstractEventLoop.close` call but
                **does nothing** for **non-default** loop.


Constants
---------

.. class:: ContentCoding

   An :class:`enum.Enum` class of available Content Codings.

   .. attribute:: deflate

      *DEFLATE compression*

   .. attribute:: gzip

      *GZIP compression*

.. attribute:: identity

      *no compression*


Middlewares
-----------

Normalize path middleware
^^^^^^^^^^^^^^^^^^^^^^^^^

.. function:: normalize_path_middleware(*, append_slash=True, merge_slashes=True)

  Middleware that normalizes the path of a request. By normalizing
  it means:

      - Add a trailing slash to the path.
      - Double slashes are replaced by one.

  The middleware returns as soon as it finds a path that resolves
  correctly. The order if all enabled is 1) merge_slashes, 2) append_slash
  and 3) both merge_slashes and append_slash. If the path resolves with
  at least one of those conditions, it will redirect to the new path.

  If append_slash is True append slash when needed. If a resource is
  defined with trailing slash and the request comes without it, it will
  append it automatically.

  If merge_slashes is True, merge multiple consecutive slashes in the
  path into one.


.. disqus::
  :title: aiohttp server reference
