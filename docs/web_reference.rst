.. _aiohttp-web-reference:

Server Reference
================

.. currentmodule:: aiohttp.web

.. _aiohttp-web-request:


Request and Base Request
------------------------

The Request object contains all the information about an incoming HTTP request.

:class:`BaseRequest` is used for :ref:`Low-Level
Servers<aiohttp-web-lowlevel>` (which have no applications, routers,
signals and middlewares). :class:`Request` has an :attr:`Request.app`
and :attr:`Request.match_info` attributes.

A :class:`BaseRequest` / :class:`Request` are :obj:`dict` like objects,
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

      The scheme is ``'https'`` if transport for request handling is
      *SSL*, ``'http'`` otherwise.

      The value could be overridden by :meth:`~BaseRequest.clone`.

      Read-only :class:`str` property.

      .. versionchanged:: 2.3

         *Forwarded* and *X-Forwarded-Proto* are not used anymore.

         Call ``.clone(scheme=new_scheme)`` for setting up the value
         explicitly.

      .. seealso:: :ref:`aiohttp-web-forwarded-support`

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

      Host name of the request, resolved in this order:

      - Overridden value by :meth:`~BaseRequest.clone` call.
      - *Host* HTTP header
      - :func:`socket.getfqdn`

      Read-only :class:`str` property.

      .. versionchanged:: 2.3

         *Forwarded* and *X-Forwarded-Host* are not used anymore.

         Call ``.clone(host=new_host)`` for setting up the value
         explicitly.

      .. seealso:: :ref:`aiohttp-web-forwarded-support`

   .. attribute:: remote

      Originating IP address of a client initiated HTTP request.

      The IP is resolved through the following headers, in this order:

      - Overridden value by :meth:`~BaseRequest.clone` call.
      - Peer name of opened socket.

      Read-only :class:`str` property.

      Call ``.clone(remote=new_remote)`` for setting up the value
      explicitly.

      .. versionadded:: 2.3

      .. seealso:: :ref:`aiohttp-web-forwarded-support`

   .. attribute:: client_max_size

      The maximum size of the request body.

      The value could be overridden by :meth:`~BaseRequest.clone`.

      Read-only :class:`int` property.

   .. attribute:: path_qs

      The URL including PATH_INFO and the query string. e.g.,
      ``/app/blog?id=10``

      Read-only :class:`str` property.

   .. attribute:: path

      The URL including *PATH INFO* without the host or scheme. e.g.,
      ``/app/blog``. The path is URL-decoded. For raw path info see
      :attr:`raw_path`.

      Read-only :class:`str` property.

   .. attribute:: raw_path

      The URL including raw *PATH INFO* without the host or scheme.
      Warning, the path may be URL-encoded and may contain invalid URL
      characters, e.g.
      ``/my%2Fpath%7Cwith%21some%25strange%24characters``.

      For URL-decoded version please take a look on :attr:`path`.

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

      A :ref:`transport<asyncio-transport>` used to process request.
      Read-only property.

      The property can be used, for example, for getting IP address of
      client's peer::

         peername = request.transport.get_extra_info('peername')
         if peername is not None:
             host, port = peername

   .. attribute:: loop

      An event loop instance used by HTTP request handling.

      Read-only :class:`asyncio.AbstractEventLoop` property.

      .. deprecated:: 3.5

   .. attribute:: cookies

      A read-only dictionary-like object containing the request's cookies.

      Read-only :class:`~types.MappingProxyType` property.

   .. attribute:: content

      A :class:`~aiohttp.StreamReader` instance,
      input stream for reading request's *BODY*.

      Read-only property.

   .. attribute:: body_exists

      Return ``True`` if request has *HTTP BODY*, ``False`` otherwise.

      Read-only :class:`bool` property.

      .. versionadded:: 2.3

   .. attribute:: can_read_body

      Return ``True`` if request's *HTTP BODY* can be read, ``False`` otherwise.

      Read-only :class:`bool` property.

      .. versionadded:: 2.3

   .. attribute:: has_body

      Return ``True`` if request's *HTTP BODY* can be read, ``False`` otherwise.

      Read-only :class:`bool` property.

      .. deprecated:: 2.3

         Use :meth:`can_read_body` instead.

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

   .. attribute:: if_modified_since

      Read-only property that returns the date specified in the
      *If-Modified-Since* header.

      Returns :class:`datetime.datetime` or ``None`` if
      *If-Modified-Since* header is absent or is not a valid
      HTTP date.

   .. attribute:: if_unmodified_since

      Read-only property that returns the date specified in the
      *If-Unmodified-Since* header.

      Returns :class:`datetime.datetime` or ``None`` if
      *If-Unmodified-Since* header is absent or is not a valid
      HTTP date.

      .. versionadded:: 3.1

   .. attribute:: if_match

      Read-only property that returns :class:`~aiohttp.ETag` objects specified
      in the *If-Match* header.

      Returns :class:`tuple` of :class:`~aiohttp.ETag` or ``None`` if
      *If-Match* header is absent.

      .. versionadded:: 3.8

   .. attribute:: if_none_match

      Read-only property that returns :class:`~aiohttp.ETag` objects specified
      *If-None-Match* header.

      Returns :class:`tuple` of :class:`~aiohttp.ETag` or ``None`` if
      *If-None-Match* header is absent.

      .. versionadded:: 3.8

   .. attribute:: if_range

      Read-only property that returns the date specified in the
      *If-Range* header.

      Returns :class:`datetime.datetime` or ``None`` if
      *If-Range* header is absent or is not a valid
      HTTP date.

      .. versionadded:: 3.1

   .. method:: clone(*, method=..., rel_url=..., headers=...)

      Clone itself with replacement some attributes.

      Creates and returns a new instance of Request object. If no parameters
      are given, an exact copy is returned. If a parameter is not passed, it
      will reuse the one from the current request object.

      :param str method: http method

      :param rel_url: url to use, :class:`str` or :class:`~yarl.URL`

      :param headers: :class:`~multidict.CIMultiDict` or compatible
                      headers container.

      :return: a cloned :class:`Request` instance.

   .. method:: get_extra_info(name, default=None)

      Reads extra information from the protocol's transport.
      If no value associated with ``name`` is found, ``default`` is returned.

      See :meth:`asyncio.BaseTransport.get_extra_info`

      :param str name: The key to look up in the transport extra information.

      :param default: Default value to be used when no value for ``name`` is
                      found (default is ``None``).

      .. versionadded:: 3.7

   .. method:: read()
      :async:

      Read request body, returns :class:`bytes` object with body content.

      .. note::

         The method **does** store read data internally, subsequent
         :meth:`~aiohttp.web.BaseRequest.read` call will return the same value.

   .. method:: text()
      :async:

      Read request body, decode it using :attr:`charset` encoding or
      ``UTF-8`` if no encoding was specified in *MIME-type*.

      Returns :class:`str` with body content.

      .. note::

         The method **does** store read data internally, subsequent
         :meth:`~aiohttp.web.BaseRequest.text` call will return the same value.

   .. method:: json(*, loads=json.loads)
      :async:

      Read request body decoded as *json*.

      The method is just a boilerplate :ref:`coroutine <coroutine>`
      implemented as::

         async def json(self, *, loads=json.loads):
             body = await self.text()
             return loads(body)

      :param collections.abc.Callable loads: any :term:`callable` that accepts
                              :class:`str` and returns :class:`dict`
                              with parsed JSON (:func:`json.loads` by
                              default).

      .. note::

         The method **does** store read data internally, subsequent
         :meth:`~aiohttp.web.BaseRequest.json` call will return the same value.


   .. method:: multipart()
      :async:

      Returns :class:`aiohttp.MultipartReader` which processes
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

      .. versionchanged:: 3.4

         Dropped *reader* parameter.

   .. method:: post()
      :async:

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
         :meth:`~aiohttp.web.BaseRequest.post` call will return the same value.

   .. method:: release()
      :async:

      Release request.

      Eat unread part of HTTP BODY if present.

      .. note::

          User code may never call :meth:`~aiohttp.web.BaseRequest.release`, all
          required work will be processed by :mod:`aiohttp.web`
          internal machinery.

.. class:: Request

   A request used for receiving request's information by *web handler*.

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

   .. attribute:: config_dict

      A :class:`aiohttp.ChainMapProxy` instance for mapping all properties
      from the current application returned by :attr:`app` property
      and all its parents.

      .. seealso:: :ref:`aiohttp-web-data-sharing-app-config`

      .. versionadded:: 3.2

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

   async def handler(request):
       return Response(text="All right!")

Response classes are :obj:`dict` like objects,
allowing them to be used for :ref:`sharing
data<aiohttp-web-data-sharing>` among :ref:`aiohttp-web-middlewares`
and :ref:`aiohttp-web-signals` handlers::

   resp['key'] = value

.. versionadded:: 3.0

   Dict-like interface support.


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

   .. attribute:: task

      A task that serves HTTP request handling.

      May be useful for graceful shutdown of long-running requests
      (streaming, long polling or web-socket).

   .. attribute:: status

      Read-only property for *HTTP response status code*, :class:`int`.

      ``200`` (OK) by default.

   .. attribute:: reason

      Read-only property for *HTTP response reason*, :class:`str`.

   .. method:: set_status(status, reason=None)

      Set :attr:`status` and :attr:`reason`.

      *reason* value is auto calculated if not specified (``None``).

   .. attribute:: keep_alive

      Read-only property, copy of :attr:`aiohttp.web.BaseRequest.keep_alive` by default.

      Can be switched to ``False`` by :meth:`force_close` call.

   .. method:: force_close

      Disable :attr:`keep_alive` for connection. There are no ways to
      enable it back.

   .. attribute:: compression

      Read-only :class:`bool` property, ``True`` if compression is enabled.

      ``False`` by default.

      .. seealso:: :meth:`enable_compression`

   .. method:: enable_compression(force=None, strategy=zlib.Z_DEFAULT_STRATEGY)

      Enable compression.

      When *force* is unset compression encoding is selected based on
      the request's *Accept-Encoding* header.

      *Accept-Encoding* is not checked if *force* is set to a
      :class:`ContentCoding`.

      *strategy* accepts a :mod:`zlib` compression strategy.
      See :func:`zlib.compressobj` for possible values.

      .. seealso:: :attr:`compression`

   .. attribute:: chunked

      Read-only property, indicates if chunked encoding is on.

      Can be enabled by :meth:`enable_chunked_encoding` call.

      .. seealso:: :attr:`enable_chunked_encoding`

   .. method:: enable_chunked_encoding

      Enables :attr:`chunked` encoding for response. There are no ways to
      disable it back. With enabled :attr:`chunked` encoding each :meth:`write`
      operation encoded in separate chunk.

      .. warning:: chunked encoding can be enabled for ``HTTP/1.1`` only.

                   Setting up both :attr:`content_length` and chunked
                   encoding is mutually exclusive.

      .. seealso:: :attr:`chunked`

   .. attribute:: headers

      :class:`~multidict.CIMultiDict` instance
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
                          secure=None, httponly=None, version=None, \
                          samesite=None, partitioned=None)

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
                          conforms. (optional)

      :param str samesite: Asserts that a cookie must not be sent with
         cross-origin requests, providing some protection
         against cross-site request forgery attacks.
         Generally the value should be one of: ``None``,
         ``Lax`` or ``Strict``. (optional)

            .. versionadded:: 3.7

      :param bool partitioned: ``True`` to set a partitioned cookie.
         Available in Python 3.14+. (optional)

            .. versionadded:: 3.12

      .. warning::

         In HTTP version 1.1, ``expires`` was deprecated and replaced with
         the easier-to-use ``max-age``, but Internet Explorer (IE6, IE7,
         and IE8) **does not** support ``max-age``.

   .. method:: del_cookie(name, *, path='/', domain=None)

      Deletes cookie.

      :param str name: cookie name

      :param str domain: optional cookie domain

      :param str path: optional cookie path, ``'/'`` by default

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

   .. attribute:: etag

      *ETag* header for outgoing response.

      This property accepts raw :class:`str` values, :class:`~aiohttp.ETag`
      objects and the value ``None`` to unset the header.

      In case of :class:`str` input, etag is considered as strong by default.

      **Do not** use double quotes ``"`` in the etag value,
      they will be added automatically.

      .. versionadded:: 3.8

   .. method:: prepare(request)
      :async:

      :param aiohttp.web.Request request: HTTP request object, that the
                                          response answers.

      Send *HTTP header*. You should not change any header data after
      calling this method.

      The coroutine calls :attr:`~aiohttp.web.Application.on_response_prepare`
      signal handlers after default headers have been computed and directly
      before headers are sent.

   .. method:: write(data)
      :async:

      Send byte-ish data as the part of *response BODY*::

          await resp.write(data)

      :meth:`prepare` must be invoked before the call.

      Raises :exc:`TypeError` if data is not :class:`bytes`,
      :class:`bytearray` or :class:`memoryview` instance.

      Raises :exc:`RuntimeError` if :meth:`prepare` has not been called.

      Raises :exc:`RuntimeError` if :meth:`write_eof` has been called.

   .. method:: write_eof()
      :async:

      A :ref:`coroutine<coroutine>` *may* be called as a mark of the
      *HTTP response* processing finish.

      *Internal machinery* will call this method at the end of
      the request processing if needed.

      After :meth:`write_eof` call any manipulations with the *response*
      object are forbidden.


.. class:: Response(*, body=None, status=200, reason=None, text=None, \
                    headers=None, content_type=None, charset=None, \
                    zlib_executor_size=sentinel, zlib_executor=None)

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

   :param int zlib_executor_size: length in bytes which will trigger zlib compression
                            of body to happen in an executor

      .. versionadded:: 3.5

   :param int zlib_executor: executor to use for zlib compression

      .. versionadded:: 3.5


   .. attribute:: body

      Read-write attribute for storing response's content aka BODY,
      :class:`bytes`.

      Assigning :class:`str` to :attr:`body` will make the :attr:`body`
      type of :class:`aiohttp.payload.StringPayload`, which tries to encode
      the given data based on *Content-Type* HTTP header, while defaulting
      to ``UTF-8``.

   .. attribute:: text

      Read-write attribute for storing response's
      :attr:`~aiohttp.StreamResponse.body`, represented as :class:`str`.


.. class:: FileResponse(*, path, chunk_size=256*1024, status=200, reason=None, headers=None)

   The response class used to send files, inherited from :class:`StreamResponse`.

   Supports the ``Content-Range`` and ``If-Range`` HTTP Headers in requests.

   The actual :attr:`body` sending happens in overridden :meth:`~StreamResponse.prepare`.

   :param path: Path to file. Accepts both :class:`str` and :class:`pathlib.Path`.
   :param int chunk_size: Chunk size in bytes which will be passed into
                          :meth:`io.RawIOBase.read` in the event that the
                          ``sendfile`` system call is not supported.

   :param int status: HTTP status code, ``200`` by default.

   :param str reason: HTTP reason. If param is ``None`` reason will be
                      calculated basing on *status*
                      parameter. Otherwise pass :class:`str` with
                      arbitrary *status* explanation..

   :param collections.abc.Mapping headers: HTTP headers that should be added to
                           response's ones. The ``Content-Type`` response header
                           will be overridden if provided.


.. class:: WebSocketResponse(*, timeout=10.0, receive_timeout=None, \
                             autoclose=True, autoping=True, heartbeat=None, \
                             protocols=(), compress=True, max_msg_size=4194304, \
                             writer_limit=65536)

   Class for handling server-side websockets, inherited from
   :class:`StreamResponse`.

   After starting (by :meth:`prepare` call) the response you
   cannot use :meth:`~StreamResponse.write` method but should to
   communicate with websocket client by :meth:`send_str`,
   :meth:`receive` and others.

   To enable back-pressure from slow websocket clients treat methods
   :meth:`ping`, :meth:`pong`, :meth:`send_str`,
   :meth:`send_bytes`, :meth:`send_json`, :meth:`send_frame` as coroutines.
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

   :param float heartbeat: Send `ping` message every `heartbeat`
                           seconds and wait `pong` response, close
                           connection if `pong` response is not
                           received. The timer is reset on any data reception.

   :param float timeout: Timeout value for the ``close``
                         operation. After sending the close websocket message,
                         ``close`` waits for ``timeout`` seconds for a response.
                         Default value is ``10.0`` (10 seconds for ``close``
                         operation)

   :param float receive_timeout: Timeout value for `receive`
                                 operations.  Default value is :data:`None`
                                 (no timeout for receive operation)

   :param bool compress: Enable per-message deflate extension support.
                          :data:`False` for disabled, default value is :data:`True`.

   :param int max_msg_size: maximum size of read websocket message, 4
                            MB by default. To disable the size limit use ``0``.

      .. versionadded:: 3.3

   :param bool autoclose: Close connection when the client sends
                           a :const:`~aiohttp.WSMsgType.CLOSE` message,
                           ``True`` by default. If set to ``False``,
                           the connection is not closed and the
                           caller is responsible for calling
                           ``request.transport.close()`` to avoid
                           leaking resources.

   :param int writer_limit: maximum size of write buffer, 64 KB by default.
                            Once the buffer is full, the websocket will pause
                            to drain the buffer.

      .. versionadded:: 3.11

   The class supports ``async for`` statement for iterating over
   incoming messages::

      ws = web.WebSocketResponse()
      await ws.prepare(request)

          async for msg in ws:
              print(msg.data)


   .. method:: prepare(request)
      :async:

      Starts websocket. After the call you can use websocket methods.

      :param aiohttp.web.Request request: HTTP request object, that the
                                          response answers.


      :raises HTTPException: if websocket handshake has failed.

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

   .. attribute:: ws_protocol

      Websocket *subprotocol* chosen after :meth:`start` call.

      May be ``None`` if server and client protocols are
      not overlapping.

   .. method:: get_extra_info(name, default=None)

      Reads optional extra information from the writer's transport.
      If no value associated with ``name`` is found, ``default`` is returned.

      See :meth:`asyncio.BaseTransport.get_extra_info`

      :param str name: The key to look up in the transport extra information.

      :param default: Default value to be used when no value for ``name`` is
                      found (default is ``None``).

   .. method:: exception()

      Returns last occurred exception or None.

   .. method:: ping(message=b'')
      :async:

      Send :const:`~aiohttp.WSMsgType.PING` to peer.

      :param message: optional payload of *ping* message,
                      :class:`str` (converted to *UTF-8* encoded bytes)
                      or :class:`bytes`.

      :raise RuntimeError: if connections is not started or closing.

      .. versionchanged:: 3.0

         The method is converted into :term:`coroutine`

   .. method:: pong(message=b'')
      :async:

      Send *unsolicited* :const:`~aiohttp.WSMsgType.PONG` to peer.

      :param message: optional payload of *pong* message,
                      :class:`str` (converted to *UTF-8* encoded bytes)
                      or :class:`bytes`.

      :raise RuntimeError: if connections is not started or closing.

      .. versionchanged:: 3.0

         The method is converted into :term:`coroutine`

   .. method:: send_str(data, compress=None)
      :async:

      Send *data* to peer as :const:`~aiohttp.WSMsgType.TEXT` message.

      :param str data: data to send.

      :param int compress: sets specific level of compression for
                           single message,
                           ``None`` for not overriding per-socket setting.

      :raise RuntimeError: if connection is not started or closing

      :raise TypeError: if data is not :class:`str`

      .. versionchanged:: 3.0

         The method is converted into :term:`coroutine`,
         *compress* parameter added.

   .. method:: send_bytes(data, compress=None)
      :async:

      Send *data* to peer as :const:`~aiohttp.WSMsgType.BINARY` message.

      :param data: data to send.

      :param int compress: sets specific level of compression for
                           single message,
                           ``None`` for not overriding per-socket setting.

      :raise RuntimeError: if connection is not started or closing

      :raise TypeError: if data is not :class:`bytes`,
                        :class:`bytearray` or :class:`memoryview`.

      .. versionchanged:: 3.0

         The method is converted into :term:`coroutine`,
         *compress* parameter added.

   .. method:: send_json(data, compress=None, *, dumps=json.dumps)
      :async:

      Send *data* to peer as JSON string.

      :param data: data to send.

      :param int compress: sets specific level of compression for
                           single message,
                           ``None`` for not overriding per-socket setting.

      :param collections.abc.Callable dumps: any :term:`callable` that accepts an object and
                             returns a JSON string
                             (:func:`json.dumps` by default).

      :raise RuntimeError: if connection is not started or closing

      :raise ValueError: if data is not serializable object

      :raise TypeError: if value returned by ``dumps`` param is not :class:`str`

      .. versionchanged:: 3.0

         The method is converted into :term:`coroutine`,
         *compress* parameter added.

   .. method:: send_frame(message, opcode, compress=None)
      :async:

      Send a :const:`~aiohttp.WSMsgType` message *message* to peer.

      This method is low-level and should be used with caution as it
      only accepts bytes which must conform to the correct message type
      for *message*.

      It is recommended to use the :meth:`send_str`, :meth:`send_bytes`
      or :meth:`send_json` methods instead of this method.

      The primary use case for this method is to send bytes that are
      have already been encoded without having to decode and
      re-encode them.

      :param bytes message: message to send.

      :param ~aiohttp.WSMsgType opcode: opcode of the message.

      :param int compress: sets specific level of compression for
                           single message,
                           ``None`` for not overriding per-socket setting.

      .. versionadded:: 3.11

   .. method:: close(*, code=WSCloseCode.OK, message=b'', drain=True)
      :async:

      A :ref:`coroutine<coroutine>` that initiates closing
      handshake by sending :const:`~aiohttp.WSMsgType.CLOSE` message.

      It is safe to call `close()` from different task.

      :param int code: closing code. See also :class:`~aiohttp.WSCloseCode`.

      :param message: optional payload of *close* message,
                      :class:`str` (converted to *UTF-8* encoded bytes)
                      or :class:`bytes`.

      :param bool drain: drain outgoing buffer before closing connection.

      :raise RuntimeError: if connection is not started

   .. method:: receive(timeout=None)
      :async:

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

   .. method:: receive_str(*, timeout=None)
      :async:

      A :ref:`coroutine<coroutine>` that calls :meth:`receive` but
      also asserts the message type is :const:`~aiohttp.WSMsgType.TEXT`.

      .. note::

         Can only be called by the request handling task.

      :param timeout: timeout for `receive` operation.

         timeout value overrides response`s receive_timeout attribute.

      :return str: peer's message content.

      :raise aiohttp.WSMessageTypeError: if message is not :const:`~aiohttp.WSMsgType.TEXT`.

   .. method:: receive_bytes(*, timeout=None)
      :async:

      A :ref:`coroutine<coroutine>` that calls :meth:`receive` but
      also asserts the message type is
      :const:`~aiohttp.WSMsgType.BINARY`.

      .. note::

         Can only be called by the request handling task.

      :param timeout: timeout for `receive` operation.

         timeout value overrides response`s receive_timeout attribute.

      :return bytes: peer's message content.

      :raise aiohttp.WSMessageTypeError: if message is not :const:`~aiohttp.WSMsgType.BINARY`.

   .. method:: receive_json(*, loads=json.loads, timeout=None)
      :async:

      A :ref:`coroutine<coroutine>` that calls :meth:`receive_str` and loads the
      JSON string to a Python dict.

      .. note::

         Can only be called by the request handling task.

      :param collections.abc.Callable loads: any :term:`callable` that accepts
                              :class:`str` and returns :class:`dict`
                              with parsed JSON (:func:`json.loads` by
                              default).

      :param timeout: timeout for `receive` operation.

         timeout value overrides response`s receive_timeout attribute.

      :return dict: loaded JSON content

      :raise TypeError: if message is :const:`~aiohttp.WSMsgType.BINARY`.
      :raise ValueError: if message is not valid JSON.


.. seealso:: :ref:`WebSockets handling<aiohttp-web-websockets>`


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


.. function:: json_response([data], *, text=None, body=None, \
                            status=200, reason=None, headers=None, \
                            content_type='application/json', \
                            dumps=json.dumps)

Return :class:`Response` with predefined ``'application/json'``
content type and *data* encoded by ``dumps`` parameter
(:func:`json.dumps` by default).

HTTP Exceptions
^^^^^^^^^^^^^^^
Errors can also be returned by raising a HTTP exception instance from within
the handler.

.. class:: HTTPException(*, headers=None, reason=None, text=None, content_type=None)

   Low-level HTTP failure.

   :param headers: headers for the response
   :type headers: dict or multidict.CIMultiDict

   :param str reason: reason included in the response

   :param str text: response's body

   :param str content_type: response's content type.  This is passed through
      to the :class:`Response` initializer.

   Sub-classes of ``HTTPException`` exist for the standard HTTP response codes
   as described in :ref:`aiohttp-web-exceptions` and the expected usage is to
   simply raise the appropriate exception type to respond with a specific HTTP
   response code.

   Since ``HTTPException`` is a sub-class of :class:`Response`, it contains the
   methods and properties that allow you to directly manipulate details of the
   response.

   .. attribute:: status_code

      HTTP status code for this exception class.  This attribute is usually
      defined at the class level.  ``self.status_code`` is passed to the
      :class:`Response` initializer.


.. _aiohttp-web-app-and-router:

Application and Router
----------------------



.. class:: Application(*, logger=<default>, router=None, middlewares=(), \
                       handler_args=None, client_max_size=1024**2, \
                       loop=None, debug=...)

   Application is a synonym for web-server.

   To get a fully working example, you have to make an *application*, register
   supported urls in the *router* and pass it to :func:`aiohttp.web.run_app`
   or :class:`aiohttp.web.AppRunner`.

   *Application* contains a *router* instance and a list of callbacks that
   will be called during application finishing.

   This class is a :obj:`dict`-like object, so you can use it for
   :ref:`sharing data<aiohttp-web-data-sharing>` globally by storing arbitrary
   properties for later access from a :ref:`handler<aiohttp-web-handler>` via the
   :attr:`Request.app` property::

       app = Application()
       database = AppKey("database", AsyncEngine)
       app[database] = await create_async_engine(db_url)

       async def handler(request):
           async with request.app[database].begin() as conn:
               await conn.execute("DELETE * FROM table")

   Although it` is a :obj:`dict`-like object, it can't be duplicated like one
   using :meth:`~aiohttp.web.Application.copy`.

   The class inherits :class:`dict`.

   :param logger: :class:`logging.Logger` instance for storing application logs.

                  By default the value is ``logging.getLogger("aiohttp.web")``

   :param router: :class:`aiohttp.abc.AbstractRouter` instance, the system
                  creates :class:`UrlDispatcher` by default if
                  *router* is ``None``.

      .. deprecated:: 3.3

         The custom routers support is deprecated, the parameter will
         be removed in 4.0.

   :param middlewares: :class:`list` of middleware factories, see
                       :ref:`aiohttp-web-middlewares` for details.

   :param handler_args: dict-like object that overrides keyword arguments of
                        :meth:`Application.make_handler`

   :param client_max_size: client's maximum size in a request, in
                           bytes.  If a POST request exceeds this
                           value, it raises an
                           `HTTPRequestEntityTooLarge` exception.

   :param loop: event loop

      .. deprecated:: 2.0

         The parameter is deprecated. Loop is get set during freeze
         stage.

   :param debug: Switches debug mode.

      .. deprecated:: 3.5

         Use asyncio :ref:`asyncio-debug-mode` instead.

   .. attribute:: router

      Read-only property that returns *router instance*.

   .. attribute:: logger

      :class:`logging.Logger` instance for storing application logs.

   .. attribute:: loop

      :ref:`event loop<asyncio-event-loop>` used for processing HTTP requests.

      .. deprecated:: 3.5

   .. attribute:: debug

      Boolean value indicating whether the debug mode is turned on or off.

      .. deprecated:: 3.5

         Use asyncio :ref:`asyncio-debug-mode` instead.

   .. attribute:: on_response_prepare

      A :class:`~aiosignal.Signal` that is fired near the end
      of :meth:`StreamResponse.prepare` with parameters *request* and
      *response*. It can be used, for example, to add custom headers to each
      response, or to modify the default headers computed by the application,
      directly before sending the headers to the client.

      Signal handlers should have the following signature::

          async def on_prepare(request, response):
              pass

      .. note::

         The headers are written immediately after these callbacks are run.
         Therefore, if you modify the content of the response, you may need to
         adjust the `Content-Length` header or similar to match. Aiohttp will
         not make any updates to the headers from this point.

   .. attribute:: on_startup

      A :class:`~aiosignal.Signal` that is fired on application start-up.

      Subscribers may use the signal to run background tasks in the event
      loop along with the application's request handler just after the
      application start-up.

      Signal handlers should have the following signature::

          async def on_startup(app):
              pass

      .. seealso:: :ref:`aiohttp-web-signals`.

   .. attribute:: on_shutdown

      A :class:`~aiosignal.Signal` that is fired on application shutdown.

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

      A :class:`~aiosignal.Signal` that is fired on application cleanup.

      Subscribers may use the signal for gracefully closing
      connections to database server etc.

      Signal handlers should have the following signature::

          async def on_cleanup(app):
              pass

      .. seealso:: :ref:`aiohttp-web-signals` and :attr:`on_shutdown`.

   .. attribute:: cleanup_ctx

      A list of *context generators* for *startup*/*cleanup* handling.

      Signal handlers should have the following signature::

          async def context(app):
              # do startup stuff
              yield
              # do cleanup

      .. versionadded:: 3.1

      .. seealso:: :ref:`aiohttp-web-cleanup-ctx`.

   .. method:: add_subapp(prefix, subapp)

      Register nested sub-application under given path *prefix*.

      In resolving process if request's path starts with *prefix* then
      further resolving is passed to *subapp*.

      :param str prefix: path's prefix for the resource.

      :param Application subapp: nested application attached under *prefix*.

      :returns: a :class:`PrefixedSubAppResource` instance.

   .. method:: add_domain(domain, subapp)

      Register nested sub-application that serves
      the domain name or domain name mask.

      In resolving process if request.headers['host']
      matches the pattern *domain* then
      further resolving is passed to *subapp*.

      :param str domain: domain or mask of domain for the resource.

      :param Application subapp: nested application.

      :returns: a :class:`~aiohttp.web.MatchedSubAppResource` instance.

   .. method:: add_routes(routes_table)

      Register route definitions from *routes_table*.

      The table is a :class:`list` of :class:`RouteDef` items or
      :class:`RouteTableDef`.

      :returns: :class:`list` of registered :class:`AbstractRoute` instances.

      The method is a shortcut for
      ``app.router.add_routes(routes_table)``, see also
      :meth:`UrlDispatcher.add_routes`.

      .. versionadded:: 3.1

      .. versionchanged:: 3.7

         Return value updated from ``None`` to :class:`list` of
         :class:`AbstractRoute` instances.

   .. method:: make_handler(loop=None, **kwargs)

      Creates HTTP protocol factory for handling requests.

      :param loop: :ref:`event loop<asyncio-event-loop>` used
        for processing HTTP requests.

        If param is ``None`` :func:`asyncio.get_event_loop`
        used for getting default event loop.

        .. deprecated:: 2.0

      :param bool tcp_keepalive: Enable TCP Keep-Alive. Default: ``True``.
      :param int keepalive_timeout: Number of seconds before closing Keep-Alive
        connection. Default: ``75`` seconds (NGINX's default value).
      :param logger: Custom logger object. Default:
        :data:`aiohttp.log.server_logger`.
      :param access_log: Custom logging object. Default:
        :data:`aiohttp.log.access_logger`.
      :param access_log_class: Class for `access_logger`. Default:
        :data:`aiohttp.helpers.AccessLogger`.
        Must to be a subclass of :class:`aiohttp.abc.AbstractAccessLogger`.
      :param str access_log_format: Access log format string. Default:
        :attr:`helpers.AccessLogger.LOG_FORMAT`.
      :param int max_line_size: Optional maximum header line size. Default:
        ``8190``.
      :param int max_headers: Optional maximum header size. Default: ``32768``.
      :param int max_field_size: Optional maximum header field size. Default:
        ``8190``.

      :param float lingering_time: Maximum time during which the server
        reads and ignores additional data coming from the client when
        lingering close is on.  Use ``0`` to disable lingering on
        server channel closing.

      You should pass result of the method as *protocol_factory* to
      :meth:`~asyncio.AbstractEventLoop.create_server`, e.g.::

         loop = asyncio.get_event_loop()

         app = Application()

         # setup route table
         # app.router.add_route(...)

         await loop.create_server(app.make_handler(),
                                  '0.0.0.0', 8080)

      .. deprecated:: 3.2

         The method is deprecated and will be removed in future
         aiohttp versions.  Please use :ref:`aiohttp-web-app-runners` instead.

   .. method:: startup()
      :async:

      A :ref:`coroutine<coroutine>` that will be called along with the
      application's request handler.

      The purpose of the method is calling :attr:`on_startup` signal
      handlers.

   .. method:: shutdown()
      :async:

      A :ref:`coroutine<coroutine>` that should be called on
      server stopping but before :meth:`cleanup`.

      The purpose of the method is calling :attr:`on_shutdown` signal
      handlers.

   .. method:: cleanup()
      :async:

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
      :class:`~aiohttp.abc.AbstractRouter`: it should have only
      :meth:`aiohttp.abc.AbstractRouter.resolve` coroutine.

      No methods for adding routes or route reversing (getting URL by
      route name). All those are router implementation details (but,
      sure, you need to deal with that methods after choosing the
      router for your application).


.. class:: AppKey(name, t)

   This class should be used for the keys in :class:`Application`. They
   provide a type-safe alternative to `str` keys when checking your code
   with a type checker (e.g. mypy). They also avoid name clashes with keys
   from different libraries etc.

   :param name: A name to help with debugging. This should be the same as
                the variable name (much like how :class:`typing.TypeVar`
                is used).

   :param t: The type that should be used for the value in the dict (e.g.
             `str`, `Iterator[int]` etc.)

.. class:: Server

   A protocol factory compatible with
   :meth:`~asyncio.AbstractEventLoop.create_server`.

   The class is responsible for creating HTTP protocol
   objects that can handle HTTP connections.

   .. attribute:: connections

      List of all currently opened connections.

   .. attribute:: requests_count

      Amount of processed requests.

   .. method:: Server.shutdown(timeout)
      :async:

      A :ref:`coroutine<coroutine>` that should be called to close all opened
      connections.


.. class:: UrlDispatcher()

   For dispatching URLs to :ref:`handlers<aiohttp-web-handler>`
   :mod:`aiohttp.web` uses *routers*, which is any object that implements
   :class:`~aiohttp.abc.AbstractRouter` interface.

   This class is a straightforward url-matching router, implementing
   :class:`collections.abc.Mapping` for access to *named routes*.

   :class:`Application` uses this class as
   :meth:`~aiohttp.web.Application.router` by default.

   Before running an :class:`Application` you should fill *route
   table* first by calling :meth:`add_route` and :meth:`add_static`.

   :ref:`Handler<aiohttp-web-handler>` lookup is performed by iterating on
   added *routes* in FIFO order. The first matching *route* will be used
   to call the corresponding *handler*.

   If during route creation you specify *name* parameter the result is a
   *named route*.

   A *named route* can be retrieved by a ``app.router[name]`` call, checking for
   existence can be done with ``name in app.router`` etc.

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

      :param collections.abc.Callable handler: route handler.

      :param str name: optional route name.

      :param collections.abc.Coroutine expect_handler: optional *expect* header handler.

      :returns: new :class:`AbstractRoute` instance.

   .. method:: add_routes(routes_table)

      Register route definitions from *routes_table*.

      The table is a :class:`list` of :class:`RouteDef` items or
      :class:`RouteTableDef`.

      :returns: :class:`list` of registered :class:`AbstractRoute` instances.

      .. versionadded:: 2.3

      .. versionchanged:: 3.7

         Return value updated from ``None`` to :class:`list` of
         :class:`AbstractRoute` instances.

   .. method:: add_get(path, handler, *, name=None, allow_head=True, **kwargs)

      Shortcut for adding a GET handler. Calls the :meth:`add_route` with \
      ``method`` equals to ``'GET'``.

      If *allow_head* is ``True`` (default) the route for method HEAD
      is added with the same handler as for GET.

      If *name* is provided the name for HEAD route is suffixed with
      ``'-head'``. For example ``router.add_get(path, handler,
      name='route')`` call adds two routes: first for GET with name
      ``'route'`` and second for HEAD with name ``'route-head'``.

   .. method:: add_post(path, handler, **kwargs)

      Shortcut for adding a POST handler. Calls the :meth:`add_route` with \


      ``method`` equals to ``'POST'``.

   .. method:: add_head(path, handler, **kwargs)

      Shortcut for adding a HEAD handler. Calls the :meth:`add_route` with \
      ``method`` equals to ``'HEAD'``.

   .. method:: add_put(path, handler, **kwargs)

      Shortcut for adding a PUT handler. Calls the :meth:`add_route` with \
      ``method`` equals to ``'PUT'``.

   .. method:: add_patch(path, handler, **kwargs)

      Shortcut for adding a PATCH handler. Calls the :meth:`add_route` with \
      ``method`` equals to ``'PATCH'``.

   .. method:: add_delete(path, handler, **kwargs)

      Shortcut for adding a DELETE handler. Calls the :meth:`add_route` with \
      ``method`` equals to ``'DELETE'``.

   .. method:: add_view(path, handler, **kwargs)

      Shortcut for adding a class-based view handler. Calls the \
      :meth:`add_route` with ``method`` equals to ``'*'``.

      .. versionadded:: 3.0

   .. method:: add_static(prefix, path, *, name=None, expect_handler=None, \
                          chunk_size=256*1024, \
                          response_factory=StreamResponse, \
                          show_index=False, \
                          follow_symlinks=False, \
                          append_version=False)

      Adds a router and a handler for returning static files.

      Useful for serving static content like images, javascript and css files.

      On platforms that support it, the handler will transfer files more
      efficiently using the ``sendfile`` system call.

      In some situations it might be necessary to avoid using the ``sendfile``
      system call even if the platform supports it. This can be accomplished by
      by setting environment variable ``AIOHTTP_NOSENDFILE=1``.

      If a Brotli or gzip compressed version of the static content exists at
      the requested path with the ``.br`` or ``.gz`` extension, it will be used
      for the response. Brotli will be preferred over gzip if both files exist.

      .. warning::

         Use :meth:`add_static` for development only. In production,
         static content should be processed by web servers like *nginx*
         or *apache*. Such web servers will be able to provide significantly
         better performance and security for static assets. Several past security
         vulnerabilities in aiohttp only affected applications using
         :meth:`add_static`.

      :param str prefix: URL path prefix for handled static files

      :param path: path to the folder in file system that contains
                   handled static files, :class:`str` or :class:`pathlib.Path`.

      :param str name: optional route name.

      :param collections.abc.Coroutine expect_handler: optional *expect* header handler.

      :param int chunk_size: size of single chunk for file
                             downloading, 256Kb by default.

                             Increasing *chunk_size* parameter to,
                             say, 1Mb may increase file downloading
                             speed but consumes more memory.

      :param bool show_index: flag for allowing to show indexes of a directory,
                              by default it's not allowed and HTTP/403 will
                              be returned on directory access.

      :param bool follow_symlinks: flag for allowing to follow symlinks that lead
                              outside the static root directory, by default it's not allowed and
                              HTTP/404 will be returned on access.  Enabling ``follow_symlinks``
                              can be a security risk, and may lead to a directory transversal attack.
                              You do NOT need this option to follow symlinks which point to somewhere
                              else within the static directory, this option is only used to break out
                              of the security sandbox. Enabling this option is highly discouraged,
                              and only expected to be used for edge cases in a local development
                              setting where remote users do not have access to the server.

      :param bool append_version: flag for adding file version (hash)
                              to the url query string, this value will
                              be used as default when you call to
                              :meth:`~aiohttp.web.AbstractRoute.url` and
                              :meth:`~aiohttp.web.AbstractRoute.url_for` methods.


      :returns: new :class:`~aiohttp.web.AbstractRoute` instance.

   .. method:: resolve(request)
      :async:

      A :ref:`coroutine<coroutine>` that returns
      :class:`~aiohttp.abc.AbstractMatchInfo` for *request*.

      The method never raises exception, but returns
      :class:`~aiohttp.abc.AbstractMatchInfo` instance with:

      1. :attr:`~aiohttp.abc.AbstractMatchInfo.http_exception` assigned to
         :exc:`HTTPException` instance.
      2. :meth:`~aiohttp.abc.AbstractMatchInfo.handler` which raises
         :exc:`HTTPNotFound` or :exc:`HTTPMethodNotAllowed` on handler's
         execution if there is no registered route for *request*.

         *Middlewares* can process that exceptions to render
         pretty-looking error page for example.

      Used by internal machinery, end user unlikely need to call the method.

      .. note:: The method uses :attr:`aiohttp.web.BaseRequest.raw_path` for pattern
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

   .. method:: routes()

      The method returns a *view* for *all* registered routes.

   .. method:: named_resources()

      Returns a :obj:`dict`-like :class:`types.MappingProxyType` *view* over
      *all* named **resources**.

      The view maps every named resource's **name** to the
      :class:`AbstractResource` instance. It supports the usual
      :obj:`dict`-like operations, except for any mutable operations
      (i.e. it's **read-only**)::

          len(app.router.named_resources())

          for name, resource in app.router.named_resources().items():
              print(name, resource)

          "name" in app.router.named_resources()

          app.router.named_resources()["name"]


.. _aiohttp-web-resource:

Resource
^^^^^^^^

Default router :class:`UrlDispatcher` operates with :term:`resource`\s.

Resource is an item in *routing table* which has a *path*, an optional
unique *name* and at least one :term:`route`.

:term:`web-handler` lookup is performed in the following way:

1. The router splits the URL and checks the index from longest to shortest.
   For example, '/one/two/three' will first check the index for
   '/one/two/three', then '/one/two' and finally '/'.
2. If the URL part is found in the index, the list of routes for
   that URL part is iterated over. If a route matches to requested HTTP
   method (or ``'*'`` wildcard) the route's handler is used as the chosen
   :term:`web-handler`. The lookup is finished.
3. If the route is not found in the index, the router tries to find
   the route in the list of :class:`~aiohttp.web.MatchedSubAppResource`,
   (current only created from :meth:`~aiohttp.web.Application.add_domain`),
   and will iterate over the list of
   :class:`~aiohttp.web.MatchedSubAppResource` in a linear fashion
   until a match is found.
4. If no *resource* / *route* pair was found, the *router*
   returns the special :class:`~aiohttp.abc.AbstractMatchInfo`
   instance with :attr:`aiohttp.abc.AbstractMatchInfo.http_exception` is not ``None``
   but :exc:`HTTPException` with  either *HTTP 404 Not Found* or
   *HTTP 405 Method Not Allowed* status code.
   Registered :meth:`~aiohttp.abc.AbstractMatchInfo.handler` raises this exception on call.

Fixed paths are preferred over variable paths. For example,
if you have two routes ``/a/b`` and ``/a/{name}``, then the first
route will always be preferred over the second one.

If there are multiple dynamic paths with the same fixed prefix,
they will be resolved in order of registration.

For example, if you have two dynamic routes that are prefixed
with the fixed ``/users`` path such as ``/users/{x}/{y}/z`` and
``/users/{x}/y/z``, the first one will be preferred over the
second one.

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
     PrefixResource
       StaticResource
       PrefixedSubAppResource
          MatchedSubAppResource


.. class:: AbstractResource

   A base class for all resources.

   Inherited from :class:`collections.abc.Sized` and
   :class:`collections.abc.Iterable`.

   ``len(resource)`` returns amount of :term:`route`\s belongs to the resource,
   ``for route in resource`` allows to iterate over these routes.

   .. attribute:: name

      Read-only *name* of resource or ``None``.

   .. attribute:: canonical

      Read-only *canonical path* associate with the resource. For example
      ``/path/to`` or ``/path/{to}``

      .. versionadded:: 3.3

   .. method:: resolve(request)
      :async:

      Resolve resource by finding appropriate :term:`web-handler` for
      ``(method, path)`` combination.

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

      :param collections.abc.Callable handler: route handler.

      :param collections.abc.Coroutine expect_handler: optional *expect* header handler.

      :returns: new :class:`ResourceRoute` instance.


.. class:: PlainResource

   A resource, inherited from :class:`Resource`.

   The class corresponds to resources with plain-text matching,
   ``'/path/to'`` for example.

   .. attribute:: canonical

      Read-only *canonical path* associate with the resource. Returns the path
      used to create the PlainResource. For example ``/path/to``

      .. versionadded:: 3.3

   .. method:: url_for()

      Returns a :class:`~yarl.URL` for the resource.


.. class:: DynamicResource

   A resource, inherited from :class:`Resource`.

   The class corresponds to resources with
   :ref:`variable <aiohttp-web-variable-handler>` matching,
   e.g. ``'/path/{to}/{param}'`` etc.

   .. attribute:: canonical

      Read-only *canonical path* associate with the resource. Returns the
      formatter obtained from the path used to create the DynamicResource.
      For example, from a path ``/get/{num:^\d+}``, it returns ``/get/{num}``

      .. versionadded:: 3.3

   .. method:: url_for(**params)

      Returns a :class:`~yarl.URL` for the resource.

      :param params: -- a variable substitutions for dynamic resource.

         E.g. for ``'/path/{to}/{param}'`` pattern the method should
         be called as ``resource.url_for(to='val1', param='val2')``


.. class:: StaticResource

   A resource, inherited from :class:`Resource`.

   The class corresponds to resources for :ref:`static file serving
   <aiohttp-web-static-file-handling>`.

   .. attribute:: canonical

      Read-only *canonical path* associate with the resource. Returns the prefix
      used to create the StaticResource. For example ``/prefix``

      .. versionadded:: 3.3

   .. method:: url_for(filename, append_version=None)

      Returns a :class:`~yarl.URL` for file path under resource prefix.

      :param filename: -- a file name substitution for static file handler.

         Accepts both :class:`str` and :class:`pathlib.Path`.

         E.g. an URL for ``'/prefix/dir/file.txt'`` should
         be generated as ``resource.url_for(filename='dir/file.txt')``

      :param bool append_version: -- a flag for adding file version
                                  (hash) to the url query string for
                                  cache boosting

         By default has value from a constructor (``False`` by default)
         When set to ``True`` - ``v=FILE_HASH`` query string param will be added
         When set to ``False`` has no impact

         if file not found has no impact


.. class:: PrefixedSubAppResource

   A resource for serving nested applications. The class instance is
   returned by :class:`~aiohttp.web.Application.add_subapp` call.

   .. attribute:: canonical

      Read-only *canonical path* associate with the resource. Returns the
      prefix used to create the PrefixedSubAppResource.
      For example ``/prefix``

      .. versionadded:: 3.3

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

   .. method:: handle_expect_header(request)
      :async:

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


.. _aiohttp-web-route-def:


RouteDef and StaticDef
^^^^^^^^^^^^^^^^^^^^^^

Route definition, a description for not registered yet route.

Could be used for filing route table by providing a list of route
definitions (Django style).

The definition is created by functions like :func:`get` or
:func:`post`, list of definitions could be added to router by
:meth:`UrlDispatcher.add_routes` call::

   from aiohttp import web

   async def handle_get(request):
       ...


   async def handle_post(request):
       ...

   app.router.add_routes([web.get('/get', handle_get),
                          web.post('/post', handle_post),

.. class:: AbstractRouteDef

   A base class for route definitions.

   Inherited from :class:`abc.ABC`.

   .. versionadded:: 3.1

   .. method:: register(router)

      Register itself into :class:`UrlDispatcher`.

      Abstract method, should be overridden by subclasses.

      :returns: :class:`list` of registered :class:`AbstractRoute` objects.

      .. versionchanged:: 3.7

         Return value updated from ``None`` to :class:`list` of
         :class:`AbstractRoute` instances.


.. class:: RouteDef

   A definition of not registered yet route.

   Implements :class:`AbstractRouteDef`.

   .. versionadded:: 2.3

   .. versionchanged:: 3.1

      The class implements :class:`AbstractRouteDef` interface.

   .. attribute:: method

      HTTP method (``GET``, ``POST`` etc.)  (:class:`str`).

   .. attribute:: path

      Path to resource, e.g. ``/path/to``. Could contain ``{}``
      brackets for :ref:`variable resources
      <aiohttp-web-variable-handler>` (:class:`str`).

   .. attribute:: handler

      An async function to handle HTTP request.

   .. attribute:: kwargs

      A :class:`dict` of additional arguments.


.. class:: StaticDef

   A definition of static file resource.

   Implements :class:`AbstractRouteDef`.

   .. versionadded:: 3.1

   .. attribute:: prefix

      A prefix used for static file handling, e.g. ``/static``.

   .. attribute:: path

      File system directory to serve, :class:`str` or
      :class:`pathlib.Path`
      (e.g. ``'/home/web-service/path/to/static'``.

   .. attribute:: kwargs

      A :class:`dict` of additional arguments, see
      :meth:`UrlDispatcher.add_static` for a list of supported
      options.


.. function:: get(path, handler, *, name=None, allow_head=True, \
              expect_handler=None)

   Return :class:`RouteDef` for processing ``GET`` requests. See
   :meth:`UrlDispatcher.add_get` for information about parameters.

   .. versionadded:: 2.3

.. function:: post(path, handler, *, name=None, expect_handler=None)

   Return :class:`RouteDef` for processing ``POST`` requests. See
   :meth:`UrlDispatcher.add_post` for information about parameters.

   .. versionadded:: 2.3

.. function:: head(path, handler, *, name=None, expect_handler=None)

   Return :class:`RouteDef` for processing ``HEAD`` requests. See
   :meth:`UrlDispatcher.add_head` for information about parameters.

   .. versionadded:: 2.3

.. function:: put(path, handler, *, name=None, expect_handler=None)

   Return :class:`RouteDef` for processing ``PUT`` requests. See
   :meth:`UrlDispatcher.add_put` for information about parameters.

   .. versionadded:: 2.3

.. function:: patch(path, handler, *, name=None, expect_handler=None)

   Return :class:`RouteDef` for processing ``PATCH`` requests. See
   :meth:`UrlDispatcher.add_patch` for information about parameters.

   .. versionadded:: 2.3

.. function:: delete(path, handler, *, name=None, expect_handler=None)

   Return :class:`RouteDef` for processing ``DELETE`` requests. See
   :meth:`UrlDispatcher.add_delete` for information about parameters.

   .. versionadded:: 2.3

.. function:: view(path, handler, *, name=None, expect_handler=None)

   Return :class:`RouteDef` for processing ``ANY`` requests. See
   :meth:`UrlDispatcher.add_view` for information about parameters.

   .. versionadded:: 3.0

.. function:: static(prefix, path, *, name=None, expect_handler=None, \
                     chunk_size=256*1024, \
                     show_index=False, follow_symlinks=False, \
                     append_version=False)

   Return :class:`StaticDef` for processing static files.

   See :meth:`UrlDispatcher.add_static` for information
   about supported parameters.

   .. versionadded:: 3.1

.. function:: route(method, path, handler, *, name=None, expect_handler=None)

   Return :class:`RouteDef` for processing requests that decided by
   ``method``. See :meth:`UrlDispatcher.add_route` for information
   about parameters.

   .. versionadded:: 2.3


.. _aiohttp-web-route-table-def:

RouteTableDef
^^^^^^^^^^^^^

A routes table definition used for describing routes by decorators
(Flask style)::

   from aiohttp import web

   routes = web.RouteTableDef()

   @routes.get('/get')
   async def handle_get(request):
       ...


   @routes.post('/post')
   async def handle_post(request):
       ...

   app.router.add_routes(routes)


   @routes.view("/view")
   class MyView(web.View):
       async def get(self):
           ...

       async def post(self):
           ...

.. class:: RouteTableDef()

   A sequence of :class:`RouteDef` instances (implements
   :class:`collections.abc.Sequence` protocol).

   In addition to all standard :class:`list` methods the class
   provides also methods like ``get()`` and ``post()`` for adding new
   route definition.

   .. versionadded:: 2.3

   .. decoratormethod:: get(path, *, allow_head=True, \
                            name=None, expect_handler=None)

      Add a new :class:`RouteDef` item for registering ``GET`` web-handler.

      See :meth:`UrlDispatcher.add_get` for information about parameters.

   .. decoratormethod:: post(path, *, name=None, expect_handler=None)

      Add a new :class:`RouteDef` item for registering ``POST`` web-handler.

      See :meth:`UrlDispatcher.add_post` for information about parameters.

   .. decoratormethod:: head(path, *, name=None, expect_handler=None)

      Add a new :class:`RouteDef` item for registering ``HEAD`` web-handler.

      See :meth:`UrlDispatcher.add_head` for information about parameters.

   .. decoratormethod:: put(path, *, name=None, expect_handler=None)

      Add a new :class:`RouteDef` item for registering ``PUT`` web-handler.

      See :meth:`UrlDispatcher.add_put` for information about parameters.

   .. decoratormethod:: patch(path, *, name=None, expect_handler=None)

      Add a new :class:`RouteDef` item for registering ``PATCH`` web-handler.

      See :meth:`UrlDispatcher.add_patch` for information about parameters.

   .. decoratormethod:: delete(path, *, name=None, expect_handler=None)

      Add a new :class:`RouteDef` item for registering ``DELETE`` web-handler.

      See :meth:`UrlDispatcher.add_delete` for information about parameters.

   .. decoratormethod:: view(path, *, name=None, expect_handler=None)

      Add a new :class:`RouteDef` item for registering ``ANY`` methods
      against a class-based view.

      See :meth:`UrlDispatcher.add_view` for information about parameters.

      .. versionadded:: 3.0

   .. method:: static(prefix, path, *, name=None, expect_handler=None, \
                      chunk_size=256*1024, \
                      show_index=False, follow_symlinks=False, \
                      append_version=False)


      Add a new :class:`StaticDef` item for registering static files processor.

      See :meth:`UrlDispatcher.add_static` for information about
      supported parameters.

      .. versionadded:: 3.1

   .. decoratormethod:: route(method, path, *, name=None, expect_handler=None)

      Add a new :class:`RouteDef` item for registering a web-handler
      for arbitrary HTTP method.

      See :meth:`UrlDispatcher.add_route` for information about parameters.


MatchInfo
^^^^^^^^^

After route matching web application calls found handler if any.

Matching result can be accessible from handler as
:attr:`Request.match_info` attribute.

In general the result may be any object derived from
:class:`~aiohttp.abc.AbstractMatchInfo` (:class:`UrlMappingMatchInfo` for default
:class:`UrlDispatcher` router).

.. class:: UrlMappingMatchInfo

   Inherited from :class:`dict` and :class:`~aiohttp.abc.AbstractMatchInfo`. Dict
   items are filled by matching info and is :term:`resource`\-specific.

   .. attribute:: expect_handler

      A coroutine for handling ``100-continue``.

   .. attribute:: handler

      A coroutine for handling request.

   .. attribute:: route

      :class:`AbstractRoute` instance for url matching.


View
^^^^

.. class:: View(request)

   Inherited from :class:`~aiohttp.abc.AbstractView`.

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

       app.router.add_view('/view', MyView)

   The view raises *405 Method Not allowed*
   (:class:`HTTPMethodNotAllowed`) if requested web verb is not
   supported.

   :param request: instance of :class:`Request` that has initiated a view
                   processing.


   .. attribute:: request

      Request sent to view's constructor, read-only property.


   Overridable coroutine methods: ``connect()``, ``delete()``,
   ``get()``, ``head()``, ``options()``, ``patch()``, ``post()``,
   ``put()``, ``trace()``.

.. seealso:: :ref:`aiohttp-web-class-based-views`


.. _aiohttp-web-app-runners-reference:

Running Applications
--------------------

To start web application there is ``AppRunner`` and site classes.

Runner is a storage for running application, sites are for running
application on specific TCP or Unix socket, e.g.::

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, 'localhost', 8080)
    await site.start()
    # wait for finish signal
    await runner.cleanup()


.. versionadded:: 3.0

   :class:`AppRunner` / :class:`ServerRunner` and :class:`TCPSite` /
   :class:`UnixSite` / :class:`SockSite` are added in aiohttp 3.0


.. class:: BaseRunner

   A base class for runners. Use :class:`AppRunner` for serving
   :class:`Application`, :class:`ServerRunner` for low-level
   :class:`Server`.

   .. attribute:: server

      Low-level web :class:`Server` for handling HTTP requests,
      read-only attribute.

   .. attribute:: addresses

      A  :class:`list` of served sockets addresses.

      See :meth:`socket.getsockname() <socket.socket.getsockname>` for items type.

      .. versionadded:: 3.3

   .. attribute:: sites

      A read-only :class:`set` of served sites (:class:`TCPSite` /
      :class:`UnixSite` / :class:`NamedPipeSite` / :class:`SockSite` instances).

   .. method:: setup()
      :async:

      Initialize the server. Should be called before adding sites.

   .. method:: cleanup()
      :async:

      Stop handling all registered sites and cleanup used resources.


.. class:: AppRunner(app, *, handle_signals=False, **kwargs)

   A runner for :class:`Application`. Used with conjunction with sites
   to serve on specific port.

   Inherited from :class:`BaseRunner`.

   :param Application app: web application instance to serve.

   :param bool handle_signals: add signal handlers for
                               :data:`signal.SIGINT` and
                               :data:`signal.SIGTERM` (``False`` by
                               default). These handlers will raise
                               :exc:`GracefulExit`.

   :param kwargs: named parameters to pass into
                  web protocol.

   Supported *kwargs*:

   :param bool tcp_keepalive: Enable TCP Keep-Alive. Default: ``True``.
   :param int keepalive_timeout: Number of seconds before closing Keep-Alive
        connection. Default: ``3630`` seconds (when deployed behind a reverse proxy
        it's important for this value to be higher than the proxy's timeout. To avoid
        race conditions we always want the proxy to close the connection).
   :param logger: Custom logger object. Default:
        :data:`aiohttp.log.server_logger`.
   :param access_log: Custom logging object. Default:
        :data:`aiohttp.log.access_logger`.
   :param access_log_class: Class for `access_logger`. Default:
        :data:`aiohttp.helpers.AccessLogger`.
        Must to be a subclass of :class:`aiohttp.abc.AbstractAccessLogger`.
   :param str access_log_format: Access log format string. Default:
        :attr:`helpers.AccessLogger.LOG_FORMAT`.
   :param int max_line_size: Optional maximum header line size. Default:
        ``8190``.
   :param int max_headers: Optional maximum header size. Default: ``32768``.
   :param int max_field_size: Optional maximum header field size. Default:
        ``8190``.

   :param float lingering_time: Maximum time during which the server
        reads and ignores additional data coming from the client when
        lingering close is on.  Use ``0`` to disable lingering on
        server channel closing.
   :param int read_bufsize: Size of the read buffer (:attr:`BaseRequest.content`).
                            ``None`` by default,
                            it means that the session global value is used.

      .. versionadded:: 3.7
   :param bool auto_decompress: Automatically decompress request body,
      ``True`` by default.

      .. versionadded:: 3.8


   .. attribute:: app

      Read-only attribute for accessing to :class:`Application` served
      instance.

   .. method:: setup()
      :async:

      Initialize application. Should be called before adding sites.

      The method calls :attr:`Application.on_startup` registered signals.

   .. method:: cleanup()
      :async:

      Stop handling all registered sites and cleanup used resources.

      :attr:`Application.on_shutdown` and
      :attr:`Application.on_cleanup` signals are called internally.


.. class:: ServerRunner(web_server, *, handle_signals=False, **kwargs)

   A runner for low-level :class:`Server`. Used with conjunction with sites
   to serve on specific port.

   Inherited from :class:`BaseRunner`.

   :param Server web_server: low-level web server instance to serve.

   :param bool handle_signals: add signal handlers for
                               :data:`signal.SIGINT` and
                               :data:`signal.SIGTERM` (``False`` by
                               default). These handlers will raise
                               :exc:`GracefulExit`.

   :param kwargs: named parameters to pass into
                  web protocol.

   .. seealso::

      :ref:`aiohttp-web-lowlevel` demonstrates low-level server usage

.. class:: BaseSite

   An abstract class for handled sites.

   .. attribute:: name

      An identifier for site, read-only :class:`str` property. Could
      be a handled URL or UNIX socket path.

   .. method:: start()
      :async:

      Start handling a site.

   .. method:: stop()
      :async:

      Stop handling a site.


.. class:: TCPSite(runner, host=None, port=None, *, \
                   shutdown_timeout=60.0, ssl_context=None, \
                   backlog=128, reuse_address=None, \
                   reuse_port=None)

   Serve a runner on TCP socket.

   :param runner: a runner to serve.

   :param str host: HOST to listen on, all interfaces if ``None`` (default).

   :param int port: PORT to listed on, ``8080`` if ``None`` (default).

   :param float shutdown_timeout: a timeout used for both waiting on pending
                                  tasks before application shutdown and for
                                  closing opened connections on
                                  :meth:`BaseSite.stop` call.

   :param ssl_context: a :class:`ssl.SSLContext` instance for serving
                       SSL/TLS secure server, ``None`` for plain HTTP
                       server (default).

   :param int backlog: a number of unaccepted connections that the
                       system will allow before refusing new
                       connections, see :meth:`socket.socket.listen` for details.

                       ``128`` by default.

   :param bool reuse_address: tells the kernel to reuse a local socket in
                              TIME_WAIT state, without waiting for its
                              natural timeout to expire. If not specified
                              will automatically be set to True on UNIX.

   :param bool reuse_port: tells the kernel to allow this endpoint to be
                           bound to the same port as other existing
                           endpoints are bound to, so long as they all set
                           this flag when being created. This option is not
                           supported on Windows.

.. class:: UnixSite(runner, path, *, \
                   shutdown_timeout=60.0, ssl_context=None, \
                   backlog=128)

   Serve a runner on UNIX socket.

   :param runner: a runner to serve.

   :param str path: PATH to UNIX socket to listen.

   :param float shutdown_timeout: a timeout used for both waiting on pending
                                  tasks before application shutdown and for
                                  closing opened connections on
                                  :meth:`BaseSite.stop` call.

   :param ssl_context: a :class:`ssl.SSLContext` instance for serving
                       SSL/TLS secure server, ``None`` for plain HTTP
                       server (default).

   :param int backlog: a number of unaccepted connections that the
                       system will allow before refusing new
                       connections, see :meth:`socket.socket.listen` for details.

                       ``128`` by default.

.. class:: NamedPipeSite(runner, path, *, shutdown_timeout=60.0)

   Serve a runner on Named Pipe in Windows.

   :param runner: a runner to serve.

   :param str path: PATH of named pipe to listen.

   :param float shutdown_timeout: a timeout used for both waiting on pending
                                  tasks before application shutdown and for
                                  closing opened connections on
                                  :meth:`BaseSite.stop` call.

.. class:: SockSite(runner, sock, *, \
                   shutdown_timeout=60.0, ssl_context=None, \
                   backlog=128)

   Serve a runner on UNIX socket.

   :param runner: a runner to serve.

   :param sock: A :ref:`socket instance <socket-objects>` to listen to.

   :param float shutdown_timeout: a timeout used for both waiting on pending
                                  tasks before application shutdown and for
                                  closing opened connections on
                                  :meth:`BaseSite.stop` call.

   :param ssl_context: a :class:`ssl.SSLContext` instance for serving
                       SSL/TLS secure server, ``None`` for plain HTTP
                       server (default).

   :param int backlog: a number of unaccepted connections that the
                       system will allow before refusing new
                       connections, see :meth:`socket.socket.listen` for details.

                       ``128`` by default.

.. exception:: GracefulExit

   Raised by signal handlers for :data:`signal.SIGINT` and :data:`signal.SIGTERM`
   defined in :class:`AppRunner` and :class:`ServerRunner`
   when ``handle_signals`` is set to ``True``.

   Inherited from :exc:`SystemExit`,
   which exits with error code ``1`` if not handled.


Utilities
---------

.. class:: FileField

   A :mod:`dataclass <dataclasses>` instance that is returned as
   multidict value by :meth:`aiohttp.web.BaseRequest.post` if field is uploaded file.

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
                      keepalive_timeout=3630, \
                      ssl_context=None, print=print, backlog=128, \
                      access_log_class=aiohttp.helpers.AccessLogger, \
                      access_log_format=aiohttp.helpers.AccessLogger.LOG_FORMAT, \
                      access_log=aiohttp.log.access_logger, \
                      handle_signals=True, \
                      reuse_address=None, \
                      reuse_port=None, \
                      handler_cancellation=False)

   A high-level function for running an application, serving it until
   keyboard interrupt and performing a
   :ref:`aiohttp-web-graceful-shutdown`.

   This is a high-level function very similar to :func:`asyncio.run` and
   should be used as the main entry point for an application. The
   :class:`Application` object essentially becomes our `main()` function.
   If additional tasks need to be run in parallel, see
   :ref:`aiohttp-web-complex-applications`.

   The server will listen on any host or Unix domain socket path you supply.
   If no hosts or paths are supplied, or only a port is supplied, a TCP server
   listening on 0.0.0.0 (all hosts) will be launched.

   Distributing HTTP traffic to multiple hosts or paths on the same
   application process provides no performance benefit as the requests are
   handled on the same event loop. See :doc:`deployment` for ways of
   distributing work for increased performance.

   :param app: :class:`Application` instance to run or a *coroutine*
               that returns an application.

   :param str host: TCP/IP host or a sequence of hosts for HTTP server.
                    Default is ``'0.0.0.0'`` if *port* has been specified
                    or if *path* is not supplied.

   :param int port: TCP/IP port for HTTP server. Default is ``8080`` for plain
                    text HTTP and ``8443`` for HTTP via SSL (when
                    *ssl_context* parameter is specified).

   :param path: file system path for HTTP server Unix domain socket.
                    A sequence of file system paths can be used to bind
                    multiple domain sockets. Listening on Unix domain
                    sockets is not supported by all operating systems,
                    :class:`str`, :class:`pathlib.Path` or an iterable of these.

   :param socket.socket sock: a preexisting socket object to accept connections on.
                       A sequence of socket objects can be passed.

   :param int shutdown_timeout: a delay to wait for graceful server
                                shutdown before disconnecting all
                                open client sockets hard way.

                                This is used as a delay to wait for
                                pending tasks to complete and then
                                again to close any pending connections.

                                A system with properly
                                :ref:`aiohttp-web-graceful-shutdown`
                                implemented never waits for the second
                                timeout but closes a server in a few
                                milliseconds.

   :param float keepalive_timeout: a delay before a TCP connection is
                                   closed after a HTTP request. The delay
                                   allows for reuse of a TCP connection.

                                   When deployed behind a reverse proxy
                                   it's important for this value to be
                                   higher than the proxy's timeout. To avoid
                                   race conditions, we always want the proxy
                                   to handle connection closing.

      .. versionadded:: 3.8

   :param ssl_context: :class:`ssl.SSLContext` for HTTPS server,
                       ``None`` for HTTP connection.

   :param print: a callable compatible with :func:`print`. May be used
                 to override STDOUT output or suppress it. Passing `None`
                 disables output.

   :param int backlog: the number of unaccepted connections that the
                       system will allow before refusing new
                       connections (``128`` by default).

   :param access_log_class: class for `access_logger`. Default:
                            :data:`aiohttp.helpers.AccessLogger`.
                            Must to be a subclass of :class:`aiohttp.abc.AbstractAccessLogger`.

   :param access_log: :class:`logging.Logger` instance used for saving
                      access logs. Use ``None`` for disabling logs for
                      sake of speedup.

   :param access_log_format: access log format, see
                             :ref:`aiohttp-logging-access-log-format-spec`
                             for details.

   :param bool handle_signals: override signal TERM handling to gracefully
                               exit the application.

   :param bool reuse_address: tells the kernel to reuse a local socket in
                              TIME_WAIT state, without waiting for its
                              natural timeout to expire. If not specified
                              will automatically be set to True on UNIX.

   :param bool reuse_port: tells the kernel to allow this endpoint to be
                           bound to the same port as other existing
                           endpoints are bound to, so long as they all set
                           this flag when being created. This option is not
                           supported on Windows.

   :param bool handler_cancellation: cancels the web handler task if the client
                                     drops the connection. This is recommended
                                     if familiar with asyncio behavior or
                                     scalability is a concern.
                                     :ref:`aiohttp-web-peer-disconnection`

   .. versionadded:: 3.0

      Support *access_log_class* parameter.

      Support *reuse_address*, *reuse_port* parameter.

   .. versionadded:: 3.1

      Accept a coroutine as *app* parameter.

   .. versionadded:: 3.9

      Support handler_cancellation parameter (this was the default behavior
      in aiohttp <3.7).

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

.. function:: normalize_path_middleware(*, \
                                        append_slash=True, \
                                        remove_slash=False, \
                                        merge_slashes=True, \
                                        redirect_class=HTTPPermanentRedirect)

   Middleware factory which produces a middleware that normalizes
   the path of a request. By normalizing it means:

     - Add or remove a trailing slash to the path.
     - Double slashes are replaced by one.

   The middleware returns as soon as it finds a path that resolves
   correctly. The order if both merge and append/remove are enabled is:

     1. *merge_slashes*
     2. *append_slash* or *remove_slash*
     3. both *merge_slashes* and *append_slash* or *remove_slash*

   If the path resolves with at least one of those conditions, it will
   redirect to the new path.

   Only one of *append_slash* and *remove_slash* can be enabled. If both are
   ``True`` the factory will raise an ``AssertionError``

   If *append_slash* is ``True`` the middleware will append a slash when
   needed. If a resource is defined with trailing slash and the request
   comes without it, it will append it automatically.

   If *remove_slash* is ``True``, *append_slash* must be ``False``. When enabled
   the middleware will remove trailing slashes and redirect if the resource is
   defined.

   If *merge_slashes* is ``True``, merge multiple consecutive slashes in the
   path into one.

   .. versionadded:: 3.4

      Support for *remove_slash*
