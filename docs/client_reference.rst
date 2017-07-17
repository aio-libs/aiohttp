.. _aiohttp-client-reference:

Client Reference
================

.. module:: aiohttp
.. currentmodule:: aiohttp


Client Session
--------------

Client session is the recommended interface for making HTTP requests.

Session encapsulates a *connection pool* (*connector* instance) and
supports keepalives by default. Unless you are connecting to a large,
unknown number of different servers over the lifetime of your
application, it is suggested you use a single session for the
lifetime of your application to benefit from connection pooling.

Usage example::

     import aiohttp
     import asyncio

     async def fetch(client):
         async with client.get('http://python.org') as resp:
             assert resp.status == 200
             return await resp.text()

     async def main(loop):
         async with aiohttp.ClientSession(loop=loop) as client:
             html = await fetch(client)
             print(html)

     loop = asyncio.get_event_loop()
     loop.run_until_complete(main(loop))


.. versionadded:: 0.17

The client session supports the context manager protocol for self closing.

.. class:: ClientSession(*, connector=None, loop=None, cookies=None, \
                         headers=None, skip_auto_headers=None, \
                         auth=None, json_serialize=func:`json.dumps`, \
                         version=aiohttp.HttpVersion11, \
                         cookie_jar=None, read_timeout=None, conn_timeout=None, \
                         raise_for_status=False)

   The class for creating client sessions and making requests.


   :param aiohttp.connector.BaseConnector connector: BaseConnector
      sub-class instance to support connection pooling.

   :param loop: :ref:`event loop<asyncio-event-loop>` used for
      processing HTTP requests.

      If *loop* is ``None`` the constructor
      borrows it from *connector* if specified.

      :func:`asyncio.get_event_loop` is used for getting default event
      loop otherwise.

   :param dict cookies: Cookies to send with the request (optional)

   :param headers: HTTP Headers to send with every request (optional).

                   May be either *iterable of key-value pairs* or
                   :class:`~collections.abc.Mapping`
                   (e.g. :class:`dict`,
                   :class:`~aiohttp.CIMultiDict`).

   :param skip_auto_headers: set of headers for which autogeneration
      should be skipped.

      *aiohttp* autogenerates headers like ``User-Agent`` or
      ``Content-Type`` if these headers are not explicitly
      passed. Using ``skip_auto_headers`` parameter allows to skip
      that generation. Note that ``Content-Length`` autogeneration can't
      be skipped.

      Iterable of :class:`str` or :class:`~aiohttp.istr` (optional)

   :param aiohttp.BasicAuth auth: an object that represents HTTP Basic
                                  Authorization (optional)

   :param version: supported HTTP version, ``HTTP 1.1`` by default.

      .. versionadded:: 0.21

   :param cookie_jar: Cookie Jar, :class:`AbstractCookieJar` instance.

      By default every session instance has own private cookie jar for
      automatic cookies processing but user may redefine this behavior
      by providing own jar implementation.

      One example is not processing cookies at all when working in
      proxy mode.

      If no cookie processing is needed, a :class:`aiohttp.helpers.DummyCookieJar`
      instance can be provided.

      .. versionadded:: 0.22

   :param callable json_serialize: Json `serializer` function. (:func:`json.dumps` by default)

   :param bool raise_for_status: Automatically call `raise_for_status()` for each response.
      (default is False)

      .. versionadded:: 2.0

   :param float read_timeout: Request operations timeout. ``read_timeout`` is
      cumulative for all request operations (request, redirects, responses,
      data consuming). By default, the read timeout is 5*60 seconds.
      Use ``None`` or ``0`` to disable timeout checks.

   :param float conn_timeout: timeout for connection establishing
      (optional). Values ``0`` or ``None`` mean no timeout.

   .. versionchanged:: 1.0

   ``.cookies`` attribute was dropped. Use :attr:`cookie_jar`
      instead.

   .. attribute:: closed

      ``True`` if the session has been closed, ``False`` otherwise.

      A read-only property.

   .. attribute:: connector

   :class:`aiohttp.connector.BaseConnector` derived instance used
      for the session.

      A read-only property.

   .. attribute:: cookie_jar

      The session cookies, :class:`~aiohttp.AbstractCookieJar` instance.

      Gives access to cookie jar's content and modifiers.

      A read-only property.

      .. versionadded:: 1.0

   .. attribute:: requote_redirect_url

      aiohttp re quote's redirect urls by default, but some servers
      require exact url from location header. to disable `re-quote` system
      set `requote_redirect_url` to `False`.

      .. note:: this parameter affects all subsequent requests.

   .. attribute:: loop

      A loop instance used for session creation.

      A read-only property.

   .. comethod:: request(method, url, *, params=None, data=None, json=None,\
                         headers=None, skip_auto_headers=None, \
                         auth=None, allow_redirects=True,\
                         max_redirects=10,\
                         compress=None, chunked=None, expect100=False,\
                         read_until_eof=True, proxy=None, proxy_auth=None,\
                         timeout=5*60)
      :async-with:
      :coroutine:

      Performs an asynchronous HTTP request. Returns a response object.

      :param str method: HTTP method

      :param url: Request URL, :class:`str` or :class:`~yarl.URL`.

      :param params: Mapping, iterable of tuple of *key*/*value* pairs or
                     string to be sent as parameters in the query
                     string of the new request. Ignored for subsequent
                     redirected requests (optional)

                     Allowed values are:

                     - :class:`collections.abc.Mapping` e.g. :class:`dict`,
                       :class:`aiohttp.MultiDict` or
                       :class:`aiohttp.MultiDictProxy`
                     - :class:`collections.abc.Iterable` e.g. :class:`tuple` or
                       :class:`list`
                     - :class:`str` with preferably url-encoded content
                       (**Warning:** content will not be encoded by *aiohttp*)

      :param data: Dictionary, bytes, or file-like object to
                   send in the body of the request (optional)

      :param json: Any json compatible python object (optional). `json` and `data`
                   parameters could not be used at the same time.

      :param dict headers: HTTP Headers to send with
                           the request (optional)

      :param skip_auto_headers: set of headers for which autogeneration
         should be skipped.

         *aiohttp* autogenerates headers like ``User-Agent`` or
         ``Content-Type`` if these headers are not explicitly
         passed. Using ``skip_auto_headers`` parameter allows to skip
         that generation.

         Iterable of :class:`str` or :class:`~aiohttp.istr`
         (optional)

      :param aiohttp.BasicAuth auth: an object that represents HTTP
                                     Basic Authorization (optional)

      :param bool allow_redirects: If set to ``False``, do not follow redirects.
                                   ``True`` by default (optional).

      :param bool compress: Set to ``True`` if request has to be compressed
         with deflate encoding. If `compress` can not be combined
         with a *Content-Encoding* and *Content-Length* headers.
         ``None`` by default (optional).

      :param int chunked: Enable chunked transfer encoding. It is up to the developer
         to decide how to chunk data streams. If chunking is enabled, aiohttp
         encodes the provided chunks in the "Transfer-encoding: chunked" format.
         If *chunked* is set, then the *Transfer-encoding* and *content-length*
         headers are disallowed. ``None`` by default (optional).

      :param bool expect100: Expect 100-continue response from server.
                             ``False`` by default (optional).

      :param bool read_until_eof: Read response until EOF if response
                                  does not have Content-Length header.
                                  ``True`` by default (optional).

      :param proxy: Proxy URL, :class:`str` or :class:`~yarl.URL` (optional)

      :param aiohttp.BasicAuth proxy_auth: an object that represents proxy HTTP
                                           Basic Authorization (optional)

      :param int timeout: override the session's timeout (``read_timeout``) for IO operations.

      :return ClientResponse: a :class:`client response <ClientResponse>` object.

      .. versionadded:: 1.0

         Added ``proxy`` and ``proxy_auth`` parameters.

         Added ``timeout`` parameter.

      .. versionchanged:: 1.1

         URLs may be either :class:`str` or :class:`~yarl.URL`

   .. comethod:: get(url, *, allow_redirects=True, **kwargs)
      :async-with:
      :coroutine:

      Perform a ``GET`` request.

      In order to modify inner
      :meth:`request<aiohttp.client.ClientSession.request>`
      parameters, provide `kwargs`.

      :param url: Request URL, :class:`str` or :class:`~yarl.URL`

      :param bool allow_redirects: If set to ``False``, do not follow redirects.
                                   ``True`` by default (optional).

      :return ClientResponse: a :class:`client response
                              <ClientResponse>` object.

      .. versionchanged:: 1.1

         URLs may be either :class:`str` or :class:`~yarl.URL`

   .. comethod:: post(url, *, data=None, **kwargs)
      :async-with:
      :coroutine:

      Perform a ``POST`` request.

      In order to modify inner
      :meth:`request<aiohttp.client.ClientSession.request>`
      parameters, provide `kwargs`.


      :param url: Request URL, :class:`str` or :class:`~yarl.URL`

      :param data: Dictionary, bytes, or file-like object to
                   send in the body of the request (optional)

      :return ClientResponse: a :class:`client response
                              <ClientResponse>` object.

      .. versionchanged:: 1.1

         URLs may be either :class:`str` or :class:`~yarl.URL`

   .. comethod:: put(url, *, data=None, **kwargs)
      :async-with:
      :coroutine:

      Perform a ``PUT`` request.

      In order to modify inner
      :meth:`request<aiohttp.client.ClientSession.request>`
      parameters, provide `kwargs`.


      :param url: Request URL, :class:`str` or :class:`~yarl.URL`

      :param data: Dictionary, bytes, or file-like object to
                   send in the body of the request (optional)

      :return ClientResponse: a :class:`client response
                              <ClientResponse>` object.

      .. versionchanged:: 1.1

         URLs may be either :class:`str` or :class:`~yarl.URL`

   .. comethod:: delete(url, **kwargs)
      :async-with:
      :coroutine:

      Perform a ``DELETE`` request.

      In order to modify inner
      :meth:`request<aiohttp.client.ClientSession.request>`
      parameters, provide `kwargs`.

      :param url: Request URL, :class:`str` or :class:`~yarl.URL`

      :return ClientResponse: a :class:`client response
                              <ClientResponse>` object.

      .. versionchanged:: 1.1

         URLs may be either :class:`str` or :class:`~yarl.URL`

   .. comethod:: head(url, *, allow_redirects=False, **kwargs)
      :async-with:
      :coroutine:

      Perform a ``HEAD`` request.

      In order to modify inner
      :meth:`request<aiohttp.client.ClientSession.request>`
      parameters, provide `kwargs`.

      :param url: Request URL, :class:`str` or :class:`~yarl.URL`

      :param bool allow_redirects: If set to ``False``, do not follow redirects.
                                   ``False`` by default (optional).

      :return ClientResponse: a :class:`client response
                              <ClientResponse>` object.

      .. versionchanged:: 1.1

         URLs may be either :class:`str` or :class:`~yarl.URL`

   .. comethod:: options(url, *, allow_redirects=True, **kwargs)
      :async-with:
      :coroutine:

      Perform an ``OPTIONS`` request.

      In order to modify inner
      :meth:`request<aiohttp.client.ClientSession.request>`
      parameters, provide `kwargs`.


      :param url: Request URL, :class:`str` or :class:`~yarl.URL`

      :param bool allow_redirects: If set to ``False``, do not follow redirects.
                                   ``True`` by default (optional).

      :return ClientResponse: a :class:`client response
                              <ClientResponse>` object.

      .. versionchanged:: 1.1

         URLs may be either :class:`str` or :class:`~yarl.URL`

   .. comethod:: patch(url, *, data=None, **kwargs)
      :async-with:
      :coroutine:

      Perform a ``PATCH`` request.

      In order to modify inner
      :meth:`request<aiohttp.client.ClientSession.request>`
      parameters, provide `kwargs`.

      :param url: Request URL, :class:`str` or :class:`~yarl.URL`

      :param data: Dictionary, bytes, or file-like object to
                   send in the body of the request (optional)


      :return ClientResponse: a :class:`client response
                              <ClientResponse>` object.

      .. versionchanged:: 1.1

         URLs may be either :class:`str` or :class:`~yarl.URL`

   .. comethod:: ws_connect(url, *, protocols=(), timeout=10.0,\
                            receive_timeout=None,\
                            auth=None,\
                            autoclose=True,\
                            autoping=True,\
                            heartbeat=None,\
                            origin=None, \
                            proxy=None, proxy_auth=None)
      :async-with:
      :coroutine:

      Create a websocket connection. Returns a
      :class:`ClientWebSocketResponse` object.

      :param url: Websocket server url, :class:`str` or :class:`~yarl.URL`

      :param tuple protocols: Websocket protocols

      :param float timeout: Timeout for websocket to close. 10 seconds by default

      :param float receive_timeout: Timeout for websocket to receive complete message.
                                    None(unlimited) seconds by default

      :param aiohttp.BasicAuth auth: an object that represents HTTP
                                     Basic Authorization (optional)

      :param bool autoclose: Automatically close websocket connection on close
                             message from server. If `autoclose` is False
                             them close procedure has to be handled manually

      :param bool autoping: automatically send `pong` on `ping`
                            message from server

      :param float heartbeat: Send `ping` message every `heartbeat` seconds
                              and wait `pong` response, if `pong` response is not received
                              then close connection.

      :param str origin: Origin header to send to server

      :param str proxy: Proxy URL, :class:`str` or :class:`~yarl.URL` (optional)

      :param aiohttp.BasicAuth proxy_auth: an object that represents proxy HTTP
                                           Basic Authorization (optional)

      .. versionadded:: 0.16

         Add :meth:`ws_connect`.

      .. versionadded:: 0.18

         Add *auth* parameter.

      .. versionadded:: 0.19

         Add *origin* parameter.

      .. versionadded:: 1.0

         Added ``proxy`` and ``proxy_auth`` parameters.

      .. versionchanged:: 1.1

         URLs may be either :class:`str` or :class:`~yarl.URL`

   .. method:: close()

      Close underlying connector.

      Release all acquired resources.

      .. versionchanged:: 2.0

   .. method:: detach()

      Detach connector from session without closing the former.

      Session is switched to closed state anyway.


Basic API
---------

While we encourage :class:`ClientSession` usage we also provide simple
coroutines for making HTTP requests.

Basic API is good for performing simple HTTP requests without
keepaliving, cookies and complex connection stuff like properly configured SSL
certification chaining.


.. coroutinefunction:: request(method, url, *, params=None, data=None, json=None,\
                               headers=None, cookies=None, auth=None, \
                               allow_redirects=True, max_redirects=10, \
                               encoding='utf-8', \
                               version=HttpVersion(major=1, minor=1), \
                               compress=None, chunked=None, expect100=False, \
                               connector=None, loop=None,\
                               read_until_eof=True)

   Perform an asynchronous HTTP request. Return a response object
   (:class:`ClientResponse` or derived from).

   :param str method: HTTP method

   :param url: Requested URL, :class:`str` or :class:`~yarl.URL`

   :param dict params: Parameters to be sent in the query
                       string of the new request (optional)

   :param data: Dictionary, bytes, or file-like object to
                send in the body of the request (optional)

   :param json: Any json compatible python object (optional). `json` and `data`
                parameters could not be used at the same time.

   :param dict headers: HTTP Headers to send with the request (optional)

   :param dict cookies: Cookies to send with the request (optional)

   :param aiohttp.BasicAuth auth: an object that represents HTTP Basic
                                  Authorization (optional)

   :param bool allow_redirects: If set to ``False``, do not follow redirects.
                                ``True`` by default (optional).

   :param aiohttp.protocol.HttpVersion version: Request HTTP version (optional)

   :param bool compress: Set to ``True`` if request has to be compressed
                         with deflate encoding.
                         ``False`` instructs aiohttp to not compress data.
                         ``None`` by default (optional).

   :param int chunked: Enables chunked transfer encoding.
                       ``None`` by default (optional).

   :param bool expect100: Expect 100-continue response from server.
                          ``False`` by default (optional).

   :param aiohttp.connector.BaseConnector connector: BaseConnector sub-class
      instance to support connection pooling.

   :param bool read_until_eof: Read response until EOF if response
                               does not have Content-Length header.
                               ``True`` by default (optional).

   :param loop: :ref:`event loop<asyncio-event-loop>`
                used for processing HTTP requests.
                If param is ``None``, :func:`asyncio.get_event_loop`
                is used for getting default event loop, but we strongly
                recommend to use explicit loops everywhere.
                (optional)


   :return ClientResponse: a :class:`client response <ClientResponse>` object.

   Usage::

      import aiohttp

      async def fetch():
          async with aiohttp.request('GET', 'http://python.org/') as resp:
              assert resp.status == 200
              print(await resp.text())

   .. versionchanged:: 1.1

      URLs may be either :class:`str` or :class:`~yarl.URL`


.. _aiohttp-client-reference-connectors:

Connectors
----------

Connectors are transports for aiohttp client API.

There are standard connectors:

1. :class:`TCPConnector` for regular *TCP sockets* (both *HTTP* and
   *HTTPS* schemes supported).
2. :class:`UnixConnector` for connecting via UNIX socket (it's used mostly for
   testing purposes).

All connector classes should be derived from :class:`BaseConnector`.

By default all *connectors* support *keep-alive connections* (behavior is controlled by
*force_close* constructor's parameter).


BaseConnector
^^^^^^^^^^^^^

.. class:: BaseConnector(*, keepalive_timeout=30, \
                         limit=100, limit_per_host=None, \
                         force_close=False, loop=None)

   Base class for all connectors.

   :param float keepalive_timeout: timeout for connection reusing
                                   after releasing (optional). Values
                                   ``0``. For disabling *keep-alive*
                                   feature use ``force_close=True``
                                   flag.

   :param int limit: Total number simultaneous connections. If *limit* is
                     ``None`` the connector has no limit (default: 100).

   :param int limit_per_host: limit for simultaneous connections to the same
      endpoint.  Endpoints are the same if they are
      have equal ``(host, port, is_ssl)`` triple.
      If *limit* is ``None`` the connector has no limit (default: None).

   :param bool force_close: do close underlying sockets after
                            connection releasing (optional).

   :param loop: :ref:`event loop<asyncio-event-loop>`
      used for handling connections.
      If param is ``None``, :func:`asyncio.get_event_loop`
      is used for getting default event loop, but we strongly
      recommend to use explicit loops everywhere.
      (optional)

   .. attribute:: closed

      Read-only property, ``True`` if connector is closed.

   .. attribute:: force_close

      Read-only property, ``True`` if connector should ultimately
      close connections on releasing.

      .. versionadded:: 0.16

   .. attribute:: limit

      The total number for simultaneous connections.
      If limit is 0 the connector has no limit. The default limit size is 100.

   .. attribute:: limit_per_host

      The limit for simultaneous connections to the same
      endpoint.

      Endpoints are the same if they are have equal ``(host, port,
      is_ssl)`` triple.

      If *limit_per_host* is ``None`` the connector has no limit per host.

      Read-only property.

   .. method:: close()

      Close all opened connections.

      .. versionadded:: 2.0

   .. comethod:: connect(request)

      Get a free connection from pool or create new one if connection
      is absent in the pool.

      The call may be paused if :attr:`limit` is exhausted until used
      connections returns to pool.

      :param aiohttp.client.ClientRequest request: request object
                                                   which is connection
                                                   initiator.

      :return: :class:`Connection` object.

   .. comethod:: _create_connection(req)

      Abstract method for actual connection establishing, should be
      overridden in subclasses.




TCPConnector
^^^^^^^^^^^^

.. class:: TCPConnector(*, verify_ssl=True, fingerprint=None,\
                        use_dns_cache=True, \
                        ttl_dns_cache=10, \
                        family=0, ssl_context=None, conn_timeout=None, \
                        keepalive_timeout=30, limit=None, \
                        force_close=False, loop=None, local_addr=None, \
                        disable_cleanup_closed=True)

   Connector for working with *HTTP* and *HTTPS* via *TCP* sockets.

   The most common transport. When you don't know what connector type
   to use, use a :class:`TCPConnector` instance.

   :class:`TCPConnector` inherits from :class:`BaseConnector`.

   Constructor accepts all parameters suitable for
   :class:`BaseConnector` plus several TCP-specific ones:

   :param bool verify_ssl: Perform SSL certificate validation for
      *HTTPS* requests (enabled by default). May be disabled to
      skip validation for sites with invalid certificates.

   :param bytes fingerprint: Pass the SHA256 digest of the expected
        certificate in DER format to verify that the certificate the
        server presents matches. Useful for `certificate pinning
        <https://en.wikipedia.org/wiki/Transport_Layer_Security#Certificate_pinning>`_.

        Note: use of MD5 or SHA1 digests is insecure and deprecated.

        .. versionadded:: 0.16

   :param bool use_dns_cache: use internal cache for DNS lookups, ``True``
      by default.

      Enabling an option *may* speedup connection
      establishing a bit but may introduce some
      *side effects* also.

      .. versionadded:: 0.17

      .. versionchanged:: 1.0

         The default is changed to ``True``

   :param int ttl_dns_cache: expire after some seconds the DNS entries, ``None``
      means cached forever. By default 10 seconds.

      By default DNS entries are cached forever, in some environments the IP
      addresses related to a specific HOST can change after a specific time. Use
      this option to keep the DNS cache updated refreshing each entry after N
      seconds.

      .. versionadded:: 2.0.8

   :param aiohttp.abc.AbstractResolver resolver: Custom resolver
      instance to use.  ``aiohttp.DefaultResolver`` by
      default (asynchronous if ``aiodns>=1.1`` is installed).

      Custom resolvers allow to resolve hostnames differently than the
      way the host is configured.

      .. versionadded:: 0.22

      .. versionchanged:: 1.0

         The resolver is ``aiohttp.AsyncResolver`` now if
         :term:`aiodns` is installed.

   :param int family: TCP socket family, both IPv4 and IPv6 by default.
                      For *IPv4* only use :const:`socket.AF_INET`,
                      for  *IPv6* only -- :const:`socket.AF_INET6`.

      .. versionchanged:: 0.18

         *family* is `0` by default, that means both IPv4 and IPv6 are
         accepted. To specify only concrete version please pass
         :const:`socket.AF_INET` or :const:`socket.AF_INET6`
         explicitly.

   :param ssl.SSLContext ssl_context: ssl context used for processing
      *HTTPS* requests (optional).

      *ssl_context* may be used for configuring certification
      authority channel, supported SSL options etc.

   :param tuple local_addr: tuple of ``(local_host, local_port)`` used to bind
      socket locally if specified.

      .. versionadded:: 0.21

   :param tuple enable_cleanup_closed: Some ssl servers do not properly complete
      ssl shutdown process, in that case asyncio leaks ssl connections.
      If this parameter is set to True, aiohttp additionally aborts underlining
      transport after 2 seconds. It is off by default.

   .. attribute:: verify_ssl

      Check *ssl certifications* if ``True``.

      Read-only :class:`bool` property.

   .. attribute:: ssl_context

      :class:`ssl.SSLContext` instance for *https* requests, read-only property.

   .. attribute:: family

      *TCP* socket family e.g. :const:`socket.AF_INET` or
      :const:`socket.AF_INET6`

      Read-only property.

   .. attribute:: dns_cache

      Use quick lookup in internal *DNS* cache for host names if ``True``.

      Read-only :class:`bool` property.

      .. versionadded:: 0.17

   .. attribute:: cached_hosts

      The cache of resolved hosts if :attr:`dns_cache` is enabled.

      Read-only :class:`types.MappingProxyType` property.

      .. versionadded:: 0.17

   .. attribute:: fingerprint

      MD5, SHA1, or SHA256 hash of the expected certificate in DER
      format, or ``None`` if no certificate fingerprint check
      required.

      Read-only :class:`bytes` property.

      .. versionadded:: 0.16

   .. method:: clear_dns_cache(self, host=None, port=None)

      Clear internal *DNS* cache.

      Remove specific entry if both *host* and *port* are specified,
      clear all cache otherwise.

      .. versionadded:: 0.17


UnixConnector
^^^^^^^^^^^^^

.. class:: UnixConnector(path, *, conn_timeout=None, \
                         keepalive_timeout=30, limit=None, \
                         force_close=False, loop=None)

   Unix socket connector.

   Use :class:`UnixConnector` for sending *HTTP/HTTPS* requests
   through *UNIX Sockets* as underlying transport.

   UNIX sockets are handy for writing tests and making very fast
   connections between processes on the same host.

   :class:`UnixConnector` is inherited from :class:`BaseConnector`.

    Usage::

       conn = UnixConnector(path='/path/to/socket')
       session = ClientSession(connector=conn)
       async with session.get('http://python.org') as resp:
           ...

   Constructor accepts all parameters suitable for
   :class:`BaseConnector` plus UNIX-specific one:

   :param str path: Unix socket path


   .. attribute:: path

      Path to *UNIX socket*, read-only :class:`str` property.


Connection
^^^^^^^^^^

.. class:: Connection

   Encapsulates single connection in connector object.

   End user should never create :class:`Connection` instances manually
   but get it by :meth:`BaseConnector.connect` coroutine.

   .. attribute:: closed

      :class:`bool` read-only property, ``True`` if connection was
      closed, released or detached.

   .. attribute:: loop

      Event loop used for connection

   .. attribute:: transport

      Connection transport

   .. method:: close()

      Close connection with forcibly closing underlying socket.

   .. method:: release()

      Release connection back to connector.

      Underlying socket is not closed, the connection may be reused
      later if timeout (30 seconds by default) for connection was not
      expired.

   .. method:: detach()

      Detach underlying socket from connection.

      Underlying socket is not closed, next :meth:`close` or
      :meth:`release` calls don't return socket to free pool.


Response object
---------------

.. class:: ClientResponse

   Client response returned be :meth:`ClientSession.request` and family.

   User never creates the instance of ClientResponse class but gets it
   from API calls.

   :class:`ClientResponse` supports async context manager protocol, e.g.::

       resp = await client_session.get(url)
       async with resp:
           assert resp.status == 200

   After exiting from ``async with`` block response object will be
   *released* (see :meth:`release` coroutine).

   .. versionadded:: 0.18

      Support for ``async with``.

   .. attribute:: version

      Response's version, :class:`HttpVersion` instance.

   .. attribute:: status

      HTTP status code of response (:class:`int`), e.g. ``200``.

   .. attribute:: reason

      HTTP status reason of response (:class:`str`), e.g. ``"OK"``.

   .. attribute:: method

      Request's method (:class:`str`).

   .. attribute:: url

      URL of request (:class:`~yarl.URL`).

   .. attribute:: connection

      :class:`Connection` used for handling response.

   .. attribute:: content

      Payload stream, contains response's BODY (:class:`StreamReader`).

      Reading from the stream may raise
      :exc:`aiohttp.ClientPayloadError` if the response object is
      closed before response receives all data or in case if any transfer encoding
      related errors like mis-formed chunked encoding of broken compression data.

   .. attribute:: cookies

      HTTP cookies of response (*Set-Cookie* HTTP header,
      :class:`~http.cookies.SimpleCookie`).

   .. attribute:: headers

      A case-insensitive multidict proxy with HTTP headers of
      response, :class:`CIMultiDictProxy`.

   .. attribute:: raw_headers

      Unmodified HTTP headers of response as unconverted bytes, a sequence of
      ``(key, value)`` pairs.

   .. attribute:: content_type

      Read-only property with *content* part of *Content-Type* header.

      .. note::

         Returns value is ``'application/octet-stream'`` if no
         Content-Type header present in HTTP headers according to
         :rfc:`2616`. To make sure Content-Type header is not present in
         the server reply, use :attr:`headers` or :attr:`raw_headers`, e.g.
         ``'CONTENT-TYPE' not in resp.headers``.

   .. attribute:: charset

   Read-only property that specifies the *encoding* for the request's BODY.

      The value is parsed from the *Content-Type* HTTP header.

      Returns :class:`str` like ``'utf-8'`` or ``None`` if no *Content-Type*
      header present in HTTP headers or it has no charset information.

   .. attribute:: history

      A :class:`~collections.abc.Sequence` of :class:`ClientResponse`
      objects of preceding requests (earliest request first) if there were
      redirects, an empty sequence otherwise.

   .. method:: close()

      Close response and underlying connection.

      For :term:`keep-alive` support see :meth:`release`.

   .. comethod:: read()

      Read the whole response's body as :class:`bytes`.

      Close underlying connection if data reading gets an error,
      release connection otherwise.

      :return bytes: read *BODY*.

      .. seealso:: :meth:`close`, :meth:`release`.

   .. comethod:: release()

      It is not required to call `release` on the response object. When the
      client fully receives the payload, the underlying connection automatically
      returns back to pool. If the payload is not fully read, the connection is closed

   .. method:: raise_for_status()

      Raise an :exc:`aiohttp.ClientResponseError` if the response status is 400 or higher.
      Do nothing for success responses (less than 400).

   .. comethod:: text(encoding=None)

      Read response's body and return decoded :class:`str` using
      specified *encoding* parameter.

      If *encoding* is ``None`` content encoding is autocalculated
      using :term:`cchardet` or :term:`chardet` as fallback if
      *cchardet* is not available.

      Close underlying connection if data reading gets an error,
      release connection otherwise.

      :param str encoding: text encoding used for *BODY* decoding, or
                           ``None`` for encoding autodetection
                           (default).

      :return str: decoded *BODY*

   .. comethod:: json(encoding=None, loads=json.loads, content_type='application/json')

      Read response's body as *JSON*, return :class:`dict` using
      specified *encoding* and *loader*.

      If *encoding* is ``None`` content encoding is autocalculated
      using :term:`cchardet` or :term:`chardet` as fallback if
      *cchardet* is not available.

      if response's `content-type` does not match `content_type` parameter
      :exc:`aiohttp.ClientResponseError` get raised. To disable content type
      check pass ``None`` value.

      :param str encoding: text encoding used for *BODY* decoding, or
                           ``None`` for encoding autodetection
                           (default).

      :param callable loads: :func:`callable` used for loading *JSON*
                             data, :func:`json.loads` by default.

      :param str content_type: specify response's content-type, if content type
         does not match raise :exc:`aiohttp.ClientResponseError`.
         To disable `content-type` check, pass ``None`` as value.
         (default: `application/json`).

      :return: *BODY* as *JSON* data parsed by *loads* parameter or
               ``None`` if *BODY* is empty or contains white-spaces only.

    .. attribute:: request_info

       A namedtuple with request URL and headers from :class:`ClientRequest`
       object.


ClientWebSocketResponse
-----------------------

To connect to a websocket server :func:`aiohttp.ws_connect` or
:meth:`aiohttp.ClientSession.ws_connect` coroutines should be used, do
not create an instance of class :class:`ClientWebSocketResponse`
manually.

.. class:: ClientWebSocketResponse()

   Class for handling client-side websockets.

   .. attribute:: closed

      Read-only property, ``True`` if :meth:`close` has been called of
      :const:`~aiohttp.WSMsgType.CLOSE` message has been received from peer.

   .. attribute:: protocol

      Websocket *subprotocol* chosen after :meth:`start` call.

      May be ``None`` if server and client protocols are
      not overlapping.

   .. method:: get_extra_info(name, default=None)

      Reads extra info from connection's transport

   .. method:: exception()

      Returns exception if any occurs or returns None.

   .. method:: ping(message=b'')

      Send :const:`~aiohttp.WSMsgType.PING` to peer.

      :param message: optional payload of *ping* message,
                      :class:`str` (converted to *UTF-8* encoded bytes)
                      or :class:`bytes`.

   .. comethod:: send_str(data)

      Send *data* to peer as :const:`~aiohttp.WSMsgType.TEXT` message.

      :param str data: data to send.

      :raise TypeError: if data is not :class:`str`

   .. comethod:: send_bytes(data)

      Send *data* to peer as :const:`~aiohttp.WSMsgType.BINARY` message.

      :param data: data to send.

      :raise TypeError: if data is not :class:`bytes`,
                        :class:`bytearray` or :class:`memoryview`.

   .. comethod:: send_json(data, *, dumps=json.loads)

      Send *data* to peer as JSON string.

      :param data: data to send.

      :param callable dumps: any :term:`callable` that accepts an object and
                             returns a JSON string
                             (:func:`json.dumps` by default).

      :raise RuntimeError: if connection is not started or closing

      :raise ValueError: if data is not serializable object

      :raise TypeError: if value returned by ``dumps(data)`` is not
                        :class:`str`

   .. comethod:: close(*, code=1000, message=b'')

      A :ref:`coroutine<coroutine>` that initiates closing handshake by sending
      :const:`~aiohttp.WSMsgType.CLOSE` message. It waits for
      close response from server. To add a timeout to `close()` call
      just wrap the call with `asyncio.wait()` or `asyncio.wait_for()`.

      :param int code: closing code

      :param message: optional payload of *pong* message,
         :class:`str` (converted to *UTF-8* encoded bytes) or :class:`bytes`.

   .. comethod:: receive()

      A :ref:`coroutine<coroutine>` that waits upcoming *data*
      message from peer and returns it.

      The coroutine implicitly handles
      :const:`~aiohttp.WSMsgType.PING`,
      :const:`~aiohttp.WSMsgType.PONG` and
      :const:`~aiohttp.WSMsgType.CLOSE` without returning the
      message.

      It process *ping-pong game* and performs *closing handshake* internally.

      :return: :class:`~aiohttp.WSMessage`, `tp` is a type from
         :class:`~aiohttp.WSMsgType` enumeration.

   .. coroutinemethod:: receive_str()

      A :ref:`coroutine<coroutine>` that calls :meth:`receive` but
      also asserts the message type is
      :const:`~aiohttp.WSMsgType.TEXT`.

      :return str: peer's message content.

      :raise TypeError: if message is :const:`~aiohttp.WSMsgType.BINARY`.

   .. coroutinemethod:: receive_bytes()

      A :ref:`coroutine<coroutine>` that calls :meth:`receive` but
      also asserts the message type is
      :const:`~aiohttp.WSMsgType.BINARY`.

      :return bytes: peer's message content.

      :raise TypeError: if message is :const:`~aiohttp.WSMsgType.TEXT`.

   .. coroutinemethod:: receive_json(*, loads=json.loads)

      A :ref:`coroutine<coroutine>` that calls :meth:`receive_str` and loads
      the JSON string to a Python dict.

      :param callable loads: any :term:`callable` that accepts
                              :class:`str` and returns :class:`dict`
                              with parsed JSON (:func:`json.loads` by
                              default).

      :return dict: loaded JSON content

      :raise TypeError: if message is :const:`~aiohttp.WSMsgType.BINARY`.
      :raise ValueError: if message is not valid JSON.


Utilities
---------


BasicAuth
^^^^^^^^^

.. class:: BasicAuth(login, password='', encoding='latin1')

   HTTP basic authentication helper.

   :param str login: login
   :param str password: password
   :param str encoding: encoding (`'latin1'` by default)


   Should be used for specifying authorization data in client API,
   e.g. *auth* parameter for :meth:`ClientSession.request`.


   .. classmethod:: decode(auth_header, encoding='latin1')

      Decode HTTP basic authentication credentials.

      :param str auth_header:  The ``Authorization`` header to decode.
      :param str encoding: (optional) encoding ('latin1' by default)

      :return:  decoded authentication data, :class:`BasicAuth`.


   .. method:: encode()

      Encode credentials into string suitable for ``Authorization``
      header etc.

      :return: encoded authentication data, :class:`str`.


CookieJar
^^^^^^^^^

.. class:: CookieJar(unsafe=False, loop=None)

   The cookie jar instance is available as :attr:`ClientSession.cookie_jar`.

   The jar contains :class:`~http.cookies.Morsel` items for storing
   internal cookie data.

   API provides a count of saved cookies::

       len(session.cookie_jar)

   These cookies may be iterated over::

       for cookie in session.cookie_jar:
           print(cookie.key)
           print(cookie["domain"])

   The class implements :class:`collections.abc.Iterable`,
   :class:`collections.abc.Sized` and
   :class:`aiohttp.AbstractCookieJar` interfaces.

   Implements cookie storage adhering to RFC 6265.

   :param bool unsafe: (optional) Whether to accept cookies from IPs.

   :param bool loop: an :ref:`event loop<asyncio-event-loop>` instance.
      See :class:`aiohttp.abc.AbstractCookieJar`

   .. method:: update_cookies(cookies, response_url=None)

      Update cookies returned by server in ``Set-Cookie`` header.

      :param cookies: a :class:`collections.abc.Mapping`
         (e.g. :class:`dict`, :class:`~http.cookies.SimpleCookie`) or
         *iterable* of *pairs* with cookies returned by server's
         response.

      :param str response_url: URL of response, ``None`` for *shared
         cookies*.  Regular cookies are coupled with server's URL and
         are sent only to this server, shared ones are sent in every
         client request.

   .. method:: filter_cookies(request_url)

      Return jar's cookies acceptable for URL and available in
      ``Cookie`` header for sending client requests for given URL.

      :param str response_url: request's URL for which cookies are asked.

      :return: :class:`http.cookies.SimpleCookie` with filtered
         cookies for given URL.

   .. method:: save(file_path)

      Write a pickled representation of cookies into the file
      at provided path.

      :param file_path: Path to file where cookies will be serialized,
          :class:`str` or :class:`pathlib.Path` instance.

   .. method:: load(file_path)

      Load a pickled representation of cookies from the file
      at provided path.

      :param file_path: Path to file from where cookies will be
           imported, :class:`str` or :class:`pathlib.Path` instance.


Client exceptions
^^^^^^^^^^^^^^^^^

Exception hierarchy has been significantly modified in version 2.0. aiohttp defines only
exceptions that covers connection handling and server response misbehaviors.
For developer specific mistakes, aiohttp uses python standard exceptions
like `ValueError` or `TypeError`.

Reading a response content may raise a :exc:`ClientPayloadError` exception. This exception
indicates errors specific to the payload encoding. Such as invalid compressed data,
malformed chunked-encoded chunks or not enough data that satisfy the content-length header.

All exceptions are available as attributes in `aiohttp` module.

Hierarchy of exceptions:

* `aiohttp.ClientError` - Base class for all client specific exceptions

  - `aiohttp.ClientResponseError` - exceptions that could happen after we get response from server.

      `request_info` - Instance of `RequestInfo` object, contains information about request.

      `history` - History from `ClientResponse` object, if available, else empty tuple.

     - `aiohttp.WSServerHandshakeError` - web socket server response error

     - `aiohttp.ClientHttpProxyError` - proxy response

  - `aiohttp.ClientConnectionError` - exceptions related to low-level connection problems

    - `aiohttp.ClientOSError` - subset of connection errors that are initiated by an OSError exception

      - `aiohttp.ClientConnectorError` - connector related exceptions

         - `aiohttp.ClientProxyConnectionError` - proxy connection initialization error

    - `aiohttp.ServerConnectionError` - server connection related errors

    - `aiohttp.ServerDisconnectedError` - server disconnected

      `message` - Partially parsed http message (optional)

    - `aiohttp.ServerTimeoutError` - server operation timeout, (read timeout, etc)

    - `aiohttp.ServerFingerprintMismatch` - server fingerprint mismatch

  - `aiohttp.ClientPayloadError` - This exception can only be raised while reading the response
     payload if one of these errors occurs: invalid compression, malformed chunked encoding or
     not enough data that satisfy content-length header.


.. disqus::
   :title: aiohttp client reference
