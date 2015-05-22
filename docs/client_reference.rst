.. _aiohttp-client-reference:

HTTP Client Reference
=====================

.. highlight:: python

.. module:: aiohttp.client



Client Session
--------------

Client session is the recommended interface for making HTTP requests.

Session encapsulates *connection pool* (*connector* instance) and
supports keep-alives by default.

Usage example::

     >>> import aiohttp
     >>> session = aiohttp.ClientSession()
     >>> resp = yield from session.get('http://python.org')
     >>> resp
     <ClientResponse(python.org/) [200]>
     >>> data = yield from resp.read()

.. versionadded:: 0.15.2


.. class:: ClientSession(*, connector=None, loop=None, cookies=None,\
                         headers=None, auth=None, request_class=ClientRequest,\
                         response_class=ClientResponse, ws_response_class=ClientWebSocketResponse)

   The class for creating client sessions and making requests.

   :param aiohttp.connector.BaseConnector connector: BaseConnector
      sub-class instance to support connection pooling.


   :param loop: :ref:`event loop<asyncio-event-loop>`
      used for processing HTTP requests.
      If param is ``None``, :func:`asyncio.get_event_loop`
      is used for getting default event loop, but we strongly
      recommend to use explicit loops everywhere.
      (optional)

   :param dict cookies: Cookies to send with the request (optional)

   :param dict headers: HTTP Headers to send with
                        the request (optional)

   :param aiohttp.helpers.BasicAuth auth: BasicAuth named tuple that represents
                                          HTTP Basic Auth (optional)

   :param request_class: Request class implementation. ``ClientRequest`` by
                         default.

   :param response_class: Response class implementation. ``ClientResponse`` by
                          default.

   :param ws_response_class: WebSocketResponse class implementation.
                             ``ClientWebSocketResponse`` by default.

                             .. versionadded:: 0.16

   .. versionchanged:: 0.16
      *request_class* default changed from ``None`` to ``ClientRequest``

   .. versionchanged:: 0.16
      *response_class* default changed from ``None`` to ``ClientResponse``

   .. attribute:: closed

      ``True`` if the session has been closed, ``False`` otherwise.

      A read-only property.

   .. attribute:: connector

      :class:`aiohttp.connector.BaseConnector` derived instance used
      for the session.

      A read-only property.

   .. attribute:: cookies

      The session cookies, :class:`http.cookies.SimpleCookie` instance.

      A read-only property. Overriding `session.cookies = new_val` is
      forbidden, but you may modify the object inplace if needed.


   .. coroutinemethod:: request(method, url, *, params=None, data=None,\
                                headers=None, auth=None, allow_redirects=True,\
                                max_redirects=10, encoding='utf-8',\
                                version=HttpVersion(major=1, minor=1),\
                                compress=None, chunked=None, expect100=False,\
                                read_until_eof=True)

      Performs an asynchronous http request. Returns a response object.


      :param str method: HTTP method

      :param str url: Request URL

      :param dict params: Parameters to be sent in the query
                          string of the new request (optional)

      :param data: Dictionary, bytes, or file-like object to
                   send in the body of the request (optional)

      :param dict headers: HTTP Headers to send with
                           the request (optional)

      :param aiohttp.helpers.BasicAuth auth: BasicAuth named tuple that
                                             represents HTTP Basic Auth
                                             (optional)

      :param bool allow_redirects: If set to ``False``, do not follow redirects.
                                   ``True`` by default (optional).

      :param aiohttp.protocol.HttpVersion version: Request http version
                                                   (optional)

      :param bool compress: Set to ``True`` if request has to be compressed
                            with deflate encoding.
                            ``None`` by default (optional).

      :param int chunked: Set to chunk size for chunked transfer encoding.
                      ``None`` by default (optional).

      :param bool expect100: Expect 100-continue response from server.
                             ``False`` by default (optional).

      :param bool read_until_eof: Read response until eof if response
                                  does not have Content-Length header.
                                  ``True`` by default (optional).

   .. coroutinemethod:: get(url, *, allow_redirects=True, **kwargs)

      Perform a ``GET`` request.

      In order to modify inner
      :meth:`request<aiohttp.client.ClientSession.request>`
      parameters, provide `kwargs`.

      :param str url: Request URL

      :param bool allow_redirects: If set to ``False``, do not follow redirects.
                                   ``True`` by default (optional).


   .. coroutinemethod:: post(url, *, data=None, **kwargs)

      Perform a ``POST`` request.

      In order to modify inner
      :meth:`request<aiohttp.client.ClientSession.request>`
      parameters, provide `kwargs`.


      :param str url: Request URL

      :param data: Dictionary, bytes, or file-like object to
                   send in the body of the request (optional)

   .. coroutinemethod:: put(url, *, data=None, **kwargs)

      Perform a ``PUT`` request.

      In order to modify inner
      :meth:`request<aiohttp.client.ClientSession.request>`
      parameters, provide `kwargs`.


      :param str url: Request URL

      :param data: Dictionary, bytes, or file-like object to
                   send in the body of the request (optional)

   .. coroutinemethod:: delete(url, **kwargs)

      Perform a ``DELETE`` request.

      In order to modify inner
      :meth:`request<aiohttp.client.ClientSession.request>`
      parameters, provide `kwargs`.

      :param str url: Request URL

   .. coroutinemethod:: head(url, *, allow_redirects=False, **kwargs)

      Perform a ``HEAD`` request.

      In order to modify inner
      :meth:`request<aiohttp.client.ClientSession.request>`
      parameters, provide `kwargs`.


      :param str url: Request URL

      :param bool allow_redirects: If set to ``False``, do not follow redirects.
                                   ``False`` by default (optional).


   .. coroutinemethod:: options(url, *, allow_redirects=True, **kwargs)

      Perform an ``OPTIONS`` request.

      In order to modify inner
      :meth:`request<aiohttp.client.ClientSession.request>`
      parameters, provide `kwargs`.


      :param str url: Request URL

      :param bool allow_redirects: If set to ``False``, do not follow redirects.
                                   ``True`` by default (optional).


   .. coroutinemethod:: patch(url, *, data=None, **kwargs)

      Perform a ``PATCH`` request.

      In order to modify inner
      :meth:`request<aiohttp.client.ClientSession.request>`
      parameters, provide `kwargs`.


      :param str url: Request URL

      :param data: Dictionary, bytes, or file-like object to
                   send in the body of the request (optional)


   .. coroutinemethod:: ws_connect(url, *, protocols=(), timeout=10.0\
                                   autoclose=True, autoping=True)

      Create a websocket connection. Returns a :class:`ClientWebSocketResponse` object.

      :param str url: Websocket server url

      :param tuple protocols: Websocket protocols

      :param float timeout: Timeout for websocket read. 10 seconds by default

      :param bool autoclose: Automatically close websocket connection on close
                             message from server. If `autoclose` is False
                             them close procedure has to be handled manually

      :param bool autoping: automatically send `pong` on `ping` message from server

      .. versionadded:: 0.16

   .. method:: close()

      Close underlying connector.

      Release all acquired resources.

   .. method:: detach()

      Detach connector from session without closing the former.

      Session is switched to closed state anyway.



request coroutine
-----------------

.. coroutinefunction:: request(method, url, *, params=None, data=None, \
                       headers=None, cookies=None, files=None, auth=None, \
                       allow_redirects=True, max_redirects=10, \
                       encoding='utf-8', \
                       version=HttpVersion(major=1, minor=1), \
                       compress=None, chunked=None, expect100=False, \
                       connector=None, loop=None,\
                       read_until_eof=True, request_class=None,\
                       response_class=None)

   Perform an asynchronous http request. Return a response object
   (:class:`ClientResponse` or derived from).

   :param str method: HTTP method

   :param str url: Request URL

   :param dict params: Parameters to be sent in the query
                       string of the new request (optional)

   :param data: Dictionary, bytes, or file-like object to
                send in the body of the request (optional)

   :param dict headers: HTTP Headers to send with
                        the request (optional)

   :param dict cookies: Cookies to send with the request (optional)

   :param aiohttp.helpers.BasicAuth auth: BasicAuth named tuple that represents
                                          HTTP Basic Auth (optional)

   :param bool allow_redirects: If set to ``False``, do not follow redirects.
                                ``True`` by default (optional).

   :param aiohttp.protocol.HttpVersion version: Request http version (optional)

   :param bool compress: Set to ``True`` if request has to be compressed
                         with deflate encoding.
                         ``None`` by default (optional).

   :param int chunked: Set to chunk size for chunked transfer encoding.
                   ``None`` by default (optional).

   :param bool expect100: Expect 100-continue response from server.
                          ``False`` by default (optional).

   :param aiohttp.connector.BaseConnector connector: BaseConnector sub-class
                                                     instance to support connection pooling.

   :param bool read_until_eof: Read response until eof if response
                               does not have Content-Length header.
                               ``True`` by default (optional).

   :param request_class: Custom Request class implementation (optional)

   :param response_class: Custom Response class implementation (optional)

   :param loop: :ref:`event loop<asyncio-event-loop>`
                used for processing HTTP requests.
                If param is ``None``, :func:`asyncio.get_event_loop`
                is used for getting default event loop, but we strongly
                recommend to use explicit loops everywhere.
                (optional)


Usage::

     >>> import aiohttp
     >>> resp = yield from aiohttp.request('GET', 'http://python.org/')
     >>> resp
     <ClientResponse(python.org/) [200]>
     >>> data = yield from resp.read()


Connectors
----------

.. module:: aiohttp.connector

Connectors are transports for aiohttp client API.

There are standard connectors:

1. :class:`TCPConnector` for regular *TCP sockets* (both *HTTP* and
   *HTTPS* schemas supported).
2. :class:`ProxyConnector` for connecting via HTTP proxy.
3. :class:`UnixConnector` for connecting via UNIX socket (it's used mostly for
   testing purposes).

All connector classes should be derived from :class:`BaseConnector`.

By default all *connectors* except :class:`ProxyConnector` support
*keep-alive connections* (behavior controlled by *force_close*
constructor's parameter).



BaseConnector
^^^^^^^^^^^^^

.. class:: BaseConnector(*, conn_timeout=None, keepalive_timeout=30, \
                         limit=None, \
                         share_cookies=False, force_close=False, loop=None)

   Base class for all connectors.

   :param float conn_timeout: timeout for connection establishing
                              (optional). Values ``0`` or ``None``
                              mean no timeout.

   :param float keepalive_timeout: timeout for connection reusing
                                   after releasing (optional). Values
                                   ``0`` or ``None`` mean no timeout.

   :param int limit: limit for simultaneous connections to the same
                     endpoint.  Endpoints are the same if they are
                     have equal ``(host, port, is_ssl)`` triple.
                     If *limit* is ``None`` the connector has no limit.

   :param bool share_cookies: update :attr:`cookies` on connection
                              processing (optional, deprecated).

   :param bool force_close: do close underlying sockets after
                            connection releasing (optional).

   :param loop: :ref:`event loop<asyncio-event-loop>`
      used for handling connections.
      If param is ``None``, :func:`asyncio.get_event_loop`
      is used for getting default event loop, but we strongly
      recommend to use explicit loops everywhere.
      (optional)

   .. deprecated:: 0.15.2

      *share_cookies* parameter is deprecated, use
      :class:`~aiohttp.client.ClientSession` for hadling cookies for
      client connections.

   .. attribute:: closed

      Read-only property, ``True`` if connector is closed.

   .. attribute:: force_close

      Read-only property, ``True`` if connector should ultimately
      close connections on releasing.

      .. versionadded:: 0.16

   .. attribute:: limit

      The limit for simultaneous connections to the same
      endpoint.

      Endpoints are the same if they are have equal ``(host, port,
      is_ssl)`` triple.

      If *limit* is ``None`` the connector has no limit (default).

      Read-only property.

      .. versionadded:: 0.16

   .. method:: close()

      Close all opened connections.

   .. coroutinemethod:: connect(request)

      Get a free connection from pool or create new one if connection
      is absent in the pool.

      The call may be paused if :attr:`limit` is exhausted until used
      connetions returns to pool.

      :param aiohttp.client.ClientRequest request: request object
                                                   which is connection
                                                   initiator.

      :return: :class:`Connection` object.

   .. coroutinemethod:: _create_connection(req)

      Abstract method for actual connection establishing, should be
      overriden in subclasses.




TCPConnector
^^^^^^^^^^^^

.. class:: TCPConnector(*, verify_ssl=True, fingerprint=None, resolve=False, \
                        family=socket.AF_INET, \
                        ssl_context=None, conn_timeout=None, \
                        keepalive_timeout=30, limit=None, share_cookies=False, \
                        force_close=False, loop=None)

   Connector for working with *HTTP* and *HTTPS* via *TCP* sockets.

   The most common transport. When you don't know what connector type
   to use, use a :class:`TCPConnector` instance.

   :class:`TCPConnector` inherits from :class:`BaseConnector`.

   Constructor accepts all parameters suitable for
   :class:`BaseConnector` plus several TCP-specific ones:

   :param bool verify_ssl: Perform SSL certificate validation for
      *HTTPS* requests (enabled by default). May be disabled to
      skip validation for sites with invalid certificates.

   :param bytes fingerprint: Pass the binary md5, sha1, or sha256
        digest of the expected certificate in DER format to verify
        that the certificate the server presents matches. Useful
        for `certificate pinning
        <https://en.wikipedia.org/wiki/Transport_Layer_Security#Certificate_pinning>`_.

        .. versionadded:: 0.16

   :param bool resolve: use internal cache for DNS lookups, ``False``
      by default.

      Enabling an option *may* speedup connection
      establishing a bit but may introduce some
      *side effects* also.

   :param int family: TCP socket family, ``AF_INET`` by default
                      (*IPv4*). For *IPv6* use ``AF_INET6``.

   :param ssl.SSLContext ssl_context: ssl context used for processing
      *HTTPS* requests (optional).

      *ssl_context* may be used for configuring certification
      authority channel, supported SSL options etc.

   .. attribute:: verify_ssl

      Check *ssl certifications* if ``True``.

      Read-only :class:`bool` property.

   .. attribute:: ssl_context

      :class:`ssl.SSLContext` instance for *https* requests, read-only property.

   .. attribute:: family

      *TCP* socket family e.g. :const:`socket.AF_INET` or
      :const:`socket.AF_INET6`

      Read-only property.

   .. attribute:: resolve

      Use quick lookup in internal *DNS* cache for host names if ``True``.

      Read-only :class:`bool` property.

   .. attribute:: resolve

      Use quick lookup in internal *DNS* cache for host names if ``True``.

      Read-only :class:`bool` property.

   .. attribute:: resolved_hosts

      The cache of resolved hosts if :attr:`resolve` is enabled.

      Read-only :class:`types.MappingProxyType` property.

   .. attribute:: fingerprint

      md5, sha1, or sha256 hash of the expected certificate in DER
      format, or ``None`` if no certificate fingerprint check
      required.

      Read-only :class:`bytes` property.

      .. versionadded:: 0.16

   .. method:: clear_resolved_hosts(self, host=None, port=None)

      Clear internal *DNS* cache.

      Remove specific entry if both *host* and *port* are specified,
      clear all cache otherwise.




ProxyConnector
^^^^^^^^^^^^^^

.. class:: ProxyConnector(proxy, *, proxy_auth=None, \
                          conn_timeout=None, \
                          keepalive_timeout=30, limit=None, \
                          share_cookies=False, \
                          force_close=True, loop=None)

   HTTP Proxy connector.

   Use :class:`ProxyConnector` for sending *HTTP/HTTPS* requests
   through *HTTP proxy*.

   :class:`ProxyConnector` is inherited from :class:`TCPConnector`.

   Usage::

      >>> conn = ProxyConnector(proxy="http://some.proxy.com")
      >>> session = ClientSession(connector=conn)
      >>> resp = yield from session.get('http://python.org')

   Constructor accepts all parameters suitable for
   :class:`TCPConnector` plus several proxy-specific ones:

   :param str proxy: URL for proxy, e.g. ``"http://some.proxy.com"``.

   :param aiohttp.helpers.BasicAuth proxy_auth: basic-auth
      authenthication info used for proxies with authorization.

   .. note::

      :class:`ProxyConnector` in opposite to all other connectors
      **doesn't** support *keep-alives* by default
      (:attr:`force_close` is ``True``).

   .. versionchanged:: 0.16

      *force_close* parameter changed to ``True`` by default.

   .. attribute:: proxy

      Proxy *URL*, read-only :class:`str` property.

   .. attribute:: proxy_auth

      Proxy auth info, read-only :class:`BasicAuth` property or
      ``None`` for proxy without authentication.

      .. versionadded:: 0.16



UnixConnector
^^^^^^^^^^^^^

.. class:: UnixConnector(path, *, \
                         conn_timeout=None, \
                         keepalive_timeout=30, limit=None, \
                         share_cookies=False, \
                         force_close=False, loop=None)

   Unix socket connector.

   Use :class:`ProxyConnector` for sending *HTTP/HTTPS* requests
   through *UNIX Sockets* as underlying transport.

   UNIX sockets are handy for writing tests and making very fast
   connections between processes on the same host.

   :class:`UnixConnector` is inherited from :class:`BaseConnector`.

    Usage::

       >>> conn = UnixConnector(path='/path/to/socket')
       >>> session = ClientSession(connector=conn)
       >>> resp = yield from session.get('http://python.org')

   Constructor accepts all parameters suitable for
   :class:`BaseConnector` plus unix-specific one:

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
