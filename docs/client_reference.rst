.. _aiohttp-client-reference:

Client Reference
================

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

     async def main():
         async with aiohttp.ClientSession() as client:
             html = await fetch(client)
             print(html)

     loop = asyncio.get_event_loop()
     loop.run_until_complete(main())


The client session supports the context manager protocol for self closing.

.. class:: ClientSession(*, connector=None, loop=None, cookies=None, \
                         headers=None, skip_auto_headers=None, \
                         auth=None, json_serialize=json.dumps, \
                         version=aiohttp.HttpVersion11, \
                         cookie_jar=None, read_timeout=None, \
                         conn_timeout=None, \
                         timeout=sentinel, \
                         raise_for_status=False, \
                         connector_owner=True, \
                         auto_decompress=True, \
                         read_bufsize=2**16, \
                         requote_redirect_url=False, \
                         trust_env=False, \
                         trace_configs=None)

   The class for creating client sessions and making requests.


   :param aiohttp.BaseConnector connector: BaseConnector
      sub-class instance to support connection pooling.

   :param loop: :ref:`event loop<asyncio-event-loop>` used for
      processing HTTP requests.

      If *loop* is ``None`` the constructor
      borrows it from *connector* if specified.

      :func:`asyncio.get_event_loop` is used for getting default event
      loop otherwise.

      .. deprecated:: 2.0

   :param dict cookies: Cookies to send with the request (optional)

   :param headers: HTTP Headers to send with every request (optional).

                   May be either *iterable of key-value pairs* or
                   :class:`~collections.abc.Mapping`
                   (e.g. :class:`dict`,
                   :class:`~multidict.CIMultiDict`).

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

   :param cookie_jar: Cookie Jar, :class:`AbstractCookieJar` instance.

      By default every session instance has own private cookie jar for
      automatic cookies processing but user may redefine this behavior
      by providing own jar implementation.

      One example is not processing cookies at all when working in
      proxy mode.

      If no cookie processing is needed, a
      :class:`aiohttp.DummyCookieJar` instance can be
      provided.

   :param callable json_serialize: Json *serializer* callable.

      By default :func:`json.dumps` function.

   :param bool raise_for_status:

      Automatically call :meth:`ClientResponse.raise_for_status()` for
      each response, ``False`` by default.

      This parameter can be overridden when you making a request, e.g.::

          client_session = aiohttp.ClientSession(raise_for_status=True)
          resp = await client_session.get(url, raise_for_status=False)
          async with resp:
              assert resp.status == 200

      Set the parameter to ``True`` if you need ``raise_for_status``
      for most of cases but override ``raise_for_status`` for those
      requests where you need to handle responses with status 400 or
      higher.

   :param timeout: a :class:`ClientTimeout` settings structure, 300 seconds (5min)
        total timeout by default.

      .. versionadded:: 3.3

   :param float read_timeout: Request operations timeout. ``read_timeout`` is
      cumulative for all request operations (request, redirects, responses,
      data consuming). By default, the read timeout is 5*60 seconds.
      Use ``None`` or ``0`` to disable timeout checks.

      .. deprecated:: 3.3

         Use ``timeout`` parameter instead.

   :param float conn_timeout: timeout for connection establishing
      (optional). Values ``0`` or ``None`` mean no timeout.

      .. deprecated:: 3.3

         Use ``timeout`` parameter instead.

   :param bool connector_owner:

      Close connector instance on session closing.

      Setting the parameter to ``False`` allows to share
      connection pool between sessions without sharing session state:
      cookies etc.

   :param bool auto_decompress: Automatically decompress response body,
       ``True`` by default

      .. versionadded:: 2.3

   :param int read_bufsize: Size of the read buffer (:attr:`ClientResponse.content`).
                            64 KiB by default.

      .. versionadded:: 3.7

   :param bool trust_env: Get proxies information from *HTTP_PROXY* /
      *HTTPS_PROXY* environment variables if the parameter is ``True``
      (``False`` by default).

      Get proxy credentials from ``~/.netrc`` file if present.

      .. seealso::

         ``.netrc`` documentation: https://www.gnu.org/software/inetutils/manual/html_node/The-_002enetrc-file.html

      .. versionadded:: 2.3

      .. versionchanged:: 3.0

         Added support for ``~/.netrc`` file.

   :param bool requote_redirect_url: Apply *URL requoting* for redirection URLs if
                                     automatic redirection is enabled (``True`` by
                                     default).

      .. versionadded:: 3.5

   :param trace_configs: A list of :class:`TraceConfig` instances used for client
                         tracing.  ``None`` (default) is used for request tracing
                         disabling.  See :ref:`aiohttp-client-tracing-reference` for
                         more information.

   .. attribute:: closed

      ``True`` if the session has been closed, ``False`` otherwise.

      A read-only property.

   .. attribute:: connector

      :class:`aiohttp.BaseConnector` derived instance used
      for the session.

      A read-only property.

   .. attribute:: cookie_jar

      The session cookies, :class:`~aiohttp.AbstractCookieJar` instance.

      Gives access to cookie jar's content and modifiers.

      A read-only property.

   .. attribute:: requote_redirect_url

      aiohttp re quote's redirect urls by default, but some servers
      require exact url from location header. To disable *re-quote* system
      set :attr:`requote_redirect_url` attribute to ``False``.

      .. versionadded:: 2.1

      .. note:: This parameter affects all subsequent requests.

      .. deprecated:: 3.5

         The attribute modification is deprecated.

   .. attribute:: loop

      A loop instance used for session creation.

      A read-only property.

      .. deprecated:: 3.5

   .. attribute:: timeout

      Default client timeouts, :class:`ClientTimeout` instance.  The value can
      be tuned by passing *timeout* parameter to :class:`ClientSession`
      constructor.

      .. versionadded:: 3.7

   .. attribute:: headers

      HTTP Headers that sent with every request

      May be either *iterable of key-value pairs* or
      :class:`~collections.abc.Mapping`
      (e.g. :class:`dict`,
      :class:`~multidict.CIMultiDict`).

      .. versionadded:: 3.7

   .. attribute:: skip_auto_headers

      Set of headers for which autogeneration skipped.

      :class:`frozenset` of :class:`str` or :class:`~aiohttp.istr` (optional)

      .. versionadded:: 3.7

   .. attribute:: auth

      An object that represents HTTP Basic Authorization.

      :class:`~aiohttp.BasicAuth` (optional)

      .. versionadded:: 3.7

   .. attribute:: json_serialize

      Json serializer callable.

      By default :func:`json.dumps` function.

      .. versionadded:: 3.7

   .. attribute:: connector_owner

      Should connector be closed on session closing

      :class:`bool` (optional)

      .. versionadded:: 3.7

   .. attribute:: raise_for_status

      Should :meth:`ClientResponse.raise_for_status()` be called for each response

      Either :class:`bool` or :class:`callable`

      .. versionadded:: 3.7

   .. attribute:: auto_decompress

      Should the body response be automatically decompressed

      :class:`bool` default is ``True``

      .. versionadded:: 3.7

   .. attribute:: trust_env

      Should get proxies information from HTTP_PROXY / HTTPS_PROXY environment
      variables or ~/.netrc file if present

      :class:`bool` default is ``False``

      .. versionadded:: 3.7

   .. attribute:: trace_config

      A list of :class:`TraceConfig` instances used for client
      tracing.  ``None`` (default) is used for request tracing
      disabling.  See :ref:`aiohttp-client-tracing-reference` for more information.

      .. versionadded:: 3.7

   .. comethod:: request(method, url, *, params=None, data=None, json=None,\
                         cookies=None, headers=None, skip_auto_headers=None, \
                         auth=None, allow_redirects=True,\
                         max_redirects=10,\
                         compress=None, chunked=None, expect100=False, raise_for_status=None,\
                         read_until_eof=True, \
                         read_bufsize=None, \
                         proxy=None, proxy_auth=None,\
                         timeout=sentinel, ssl=None, \
                         verify_ssl=None, fingerprint=None, \
                         ssl_context=None, proxy_headers=None)
      :async-with:
      :coroutine:
      :noindex:

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

      :param data: The data to send in the body of the request. This can be a
                   :class:`FormData` object or anything that can be passed into
                   :class:`FormData`, e.g. a dictionary, bytes, or file-like object.
                   (optional)

      :param json: Any json compatible python object
                   (optional). *json* and *data* parameters could not
                   be used at the same time.

      :param dict cookies: HTTP Cookies to send with
                           the request (optional)

         Global session cookies and the explicitly set cookies will be merged
         when sending the request.

         .. versionadded:: 3.5

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

      :param int max_redirects: Maximum number of redirects to follow.
                                ``10`` by default.

      :param bool compress: Set to ``True`` if request has to be compressed
         with deflate encoding. If `compress` can not be combined
         with a *Content-Encoding* and *Content-Length* headers.
         ``None`` by default (optional).

      :param int chunked: Enable chunked transfer encoding.
         It is up to the developer
         to decide how to chunk data streams. If chunking is enabled, aiohttp
         encodes the provided chunks in the "Transfer-encoding: chunked" format.
         If *chunked* is set, then the *Transfer-encoding* and *content-length*
         headers are disallowed. ``None`` by default (optional).

      :param bool expect100: Expect 100-continue response from server.
                             ``False`` by default (optional).

      :param bool raise_for_status: Automatically call :meth:`ClientResponse.raise_for_status()` for
                                    response if set to ``True``.
                                    If set to ``None`` value from ``ClientSession`` will be used.
                                    ``None`` by default (optional).

          .. versionadded:: 3.4

      :param bool read_until_eof: Read response until EOF if response
                                  does not have Content-Length header.
                                  ``True`` by default (optional).

      :param int read_bufsize: Size of the read buffer (:attr:`ClientResponse.content`).
                              ``None`` by default,
                              it means that the session global value is used.

          .. versionadded:: 3.7

      :param proxy: Proxy URL, :class:`str` or :class:`~yarl.URL` (optional)

      :param aiohttp.BasicAuth proxy_auth: an object that represents proxy HTTP
                                           Basic Authorization (optional)

      :param int timeout: override the session's timeout.

         .. versionchanged:: 3.3

            The parameter is :class:`ClientTimeout` instance,
            :class:`float` is still supported for sake of backward
            compatibility.

            If :class:`float` is passed it is a *total* timeout (in seconds).

      :param ssl: SSL validation mode. ``None`` for default SSL check
                  (:func:`ssl.create_default_context` is used),
                  ``False`` for skip SSL certificate validation,
                  :class:`aiohttp.Fingerprint` for fingerprint
                  validation, :class:`ssl.SSLContext` for custom SSL
                  certificate validation.

                  Supersedes *verify_ssl*, *ssl_context* and
                  *fingerprint* parameters.

         .. versionadded:: 3.0

      :param bool verify_ssl: Perform SSL certificate validation for
         *HTTPS* requests (enabled by default). May be disabled to
         skip validation for sites with invalid certificates.

         .. versionadded:: 2.3

         .. deprecated:: 3.0

            Use ``ssl=False``

      :param bytes fingerprint: Pass the SHA256 digest of the expected
         certificate in DER format to verify that the certificate the
         server presents matches. Useful for `certificate pinning
         <https://en.wikipedia.org/wiki/Transport_Layer_Security#Certificate_pinning>`_.

         Warning: use of MD5 or SHA1 digests is insecure and removed.

         .. versionadded:: 2.3

         .. deprecated:: 3.0

            Use ``ssl=aiohttp.Fingerprint(digest)``

      :param ssl.SSLContext ssl_context: ssl context used for processing
         *HTTPS* requests (optional).

         *ssl_context* may be used for configuring certification
         authority channel, supported SSL options etc.

         .. versionadded:: 2.3

         .. deprecated:: 3.0

            Use ``ssl=ssl_context``

      :param abc.Mapping proxy_headers: HTTP headers to send to the proxy if the
         parameter proxy has been provided.

         .. versionadded:: 2.3

      :param trace_request_ctx: Object used to give as a kw param for each new
        :class:`TraceConfig` object instantiated,
        used to give information to the
        tracers that is only available at request time.

         .. versionadded:: 3.0

      :return ClientResponse: a :class:`client response <ClientResponse>`
         object.

   .. comethod:: get(url, *, allow_redirects=True, **kwargs)
      :async-with:
      :coroutine:

      Perform a ``GET`` request.

      In order to modify inner
      :meth:`request<aiohttp.ClientSession.request>`
      parameters, provide `kwargs`.

      :param url: Request URL, :class:`str` or :class:`~yarl.URL`

      :param bool allow_redirects: If set to ``False``, do not follow redirects.
                                   ``True`` by default (optional).

      :return ClientResponse: a :class:`client response
                              <ClientResponse>` object.

   .. comethod:: post(url, *, data=None, **kwargs)
      :async-with:
      :coroutine:

      Perform a ``POST`` request.

      In order to modify inner
      :meth:`request<aiohttp.ClientSession.request>`
      parameters, provide `kwargs`.


      :param url: Request URL, :class:`str` or :class:`~yarl.URL`

      :param data: Data to send in the body of the request; see
                   :meth:`request<aiohttp.ClientSession.request>`
                   for details (optional)

      :return ClientResponse: a :class:`client response
                              <ClientResponse>` object.

   .. comethod:: put(url, *, data=None, **kwargs)
      :async-with:
      :coroutine:

      Perform a ``PUT`` request.

      In order to modify inner
      :meth:`request<aiohttp.ClientSession.request>`
      parameters, provide `kwargs`.


      :param url: Request URL, :class:`str` or :class:`~yarl.URL`

      :param data: Data to send in the body of the request; see
                   :meth:`request<aiohttp.ClientSession.request>`
                   for details (optional)

      :return ClientResponse: a :class:`client response
                              <ClientResponse>` object.

   .. comethod:: delete(url, **kwargs)
      :async-with:
      :coroutine:

      Perform a ``DELETE`` request.

      In order to modify inner
      :meth:`request<aiohttp.ClientSession.request>`
      parameters, provide `kwargs`.

      :param url: Request URL, :class:`str` or :class:`~yarl.URL`

      :return ClientResponse: a :class:`client response
                              <ClientResponse>` object.

   .. comethod:: head(url, *, allow_redirects=False, **kwargs)
      :async-with:
      :coroutine:

      Perform a ``HEAD`` request.

      In order to modify inner
      :meth:`request<aiohttp.ClientSession.request>`
      parameters, provide `kwargs`.

      :param url: Request URL, :class:`str` or :class:`~yarl.URL`

      :param bool allow_redirects: If set to ``False``, do not follow redirects.
                                   ``False`` by default (optional).

      :return ClientResponse: a :class:`client response
                              <ClientResponse>` object.

   .. comethod:: options(url, *, allow_redirects=True, **kwargs)
      :async-with:
      :coroutine:

      Perform an ``OPTIONS`` request.

      In order to modify inner
      :meth:`request<aiohttp.ClientSession.request>`
      parameters, provide `kwargs`.


      :param url: Request URL, :class:`str` or :class:`~yarl.URL`

      :param bool allow_redirects: If set to ``False``, do not follow redirects.
                                   ``True`` by default (optional).

      :return ClientResponse: a :class:`client response
                              <ClientResponse>` object.

   .. comethod:: patch(url, *, data=None, **kwargs)
      :async-with:
      :coroutine:

      Perform a ``PATCH`` request.

      In order to modify inner
      :meth:`request<aiohttp.ClientSession.request>`
      parameters, provide `kwargs`.

      :param url: Request URL, :class:`str` or :class:`~yarl.URL`

      :param data: Data to send in the body of the request; see
                   :meth:`request<aiohttp.ClientSession.request>`
                   for details (optional)

      :return ClientResponse: a :class:`client response
                              <ClientResponse>` object.

   .. comethod:: ws_connect(url, *, method='GET', \
                            protocols=(), timeout=10.0,\
                            receive_timeout=None,\
                            auth=None,\
                            autoclose=True,\
                            autoping=True,\
                            heartbeat=None,\
                            origin=None, \
                            headers=None, \
                            proxy=None, proxy_auth=None, ssl=None, \
                            verify_ssl=None, fingerprint=None, \
                            ssl_context=None, proxy_headers=None, \
                            compress=0, max_msg_size=4194304)
      :async-with:
      :coroutine:

      Create a websocket connection. Returns a
      :class:`ClientWebSocketResponse` object.

      :param url: Websocket server url, :class:`str` or :class:`~yarl.URL`

      :param tuple protocols: Websocket protocols

      :param float timeout: Timeout for websocket to close. ``10`` seconds
                            by default

      :param float receive_timeout: Timeout for websocket to receive
                                    complete message.  ``None`` (unlimited)
                                    seconds by default

      :param aiohttp.BasicAuth auth: an object that represents HTTP
                                     Basic Authorization (optional)

      :param bool autoclose: Automatically close websocket connection on close
                             message from server. If *autoclose* is False
                             then close procedure has to be handled manually.
                             ``True`` by default

      :param bool autoping: automatically send *pong* on *ping*
                            message from server. ``True`` by default

      :param float heartbeat: Send *ping* message every *heartbeat*
                              seconds and wait *pong* response, if
                              *pong* response is not received then
                              close connection. The timer is reset on any data
                              reception.(optional)

      :param str origin: Origin header to send to server(optional)

      :param dict headers: HTTP Headers to send with
                           the request (optional)

      :param str proxy: Proxy URL, :class:`str` or :class:`~yarl.URL` (optional)

      :param aiohttp.BasicAuth proxy_auth: an object that represents proxy HTTP
                                           Basic Authorization (optional)

      :param ssl: SSL validation mode. ``None`` for default SSL check
                  (:func:`ssl.create_default_context` is used),
                  ``False`` for skip SSL certificate validation,
                  :class:`aiohttp.Fingerprint` for fingerprint
                  validation, :class:`ssl.SSLContext` for custom SSL
                  certificate validation.

                  Supersedes *verify_ssl*, *ssl_context* and
                  *fingerprint* parameters.

         .. versionadded:: 3.0

      :param bool verify_ssl: Perform SSL certificate validation for
         *HTTPS* requests (enabled by default). May be disabled to
         skip validation for sites with invalid certificates.

         .. versionadded:: 2.3

         .. deprecated:: 3.0

            Use ``ssl=False``

      :param bytes fingerprint: Pass the SHA256 digest of the expected
         certificate in DER format to verify that the certificate the
         server presents matches. Useful for `certificate pinning
         <https://en.wikipedia.org/wiki/Transport_Layer_Security#Certificate_pinning>`_.

         Note: use of MD5 or SHA1 digests is insecure and deprecated.

         .. versionadded:: 2.3

         .. deprecated:: 3.0

            Use ``ssl=aiohttp.Fingerprint(digest)``

      :param ssl.SSLContext ssl_context: ssl context used for processing
         *HTTPS* requests (optional).

         *ssl_context* may be used for configuring certification
         authority channel, supported SSL options etc.

         .. versionadded:: 2.3

         .. deprecated:: 3.0

            Use ``ssl=ssl_context``

      :param dict proxy_headers: HTTP headers to send to the proxy if the
         parameter proxy has been provided.

         .. versionadded:: 2.3

      :param int compress: Enable Per-Message Compress Extension support.
                           0 for disable, 9 to 15 for window bit support.
                           Default value is 0.

         .. versionadded:: 2.3

      :param int max_msg_size: maximum size of read websocket message,
                               4 MB by default. To disable the size
                               limit use ``0``.

         .. versionadded:: 3.3

      :param str method: HTTP method to establish WebSocket connection,
                         ``'GET'`` by default.

         .. versionadded:: 3.5


   .. comethod:: close()

      Close underlying connector.

      Release all acquired resources.

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


.. cofunction:: request(method, url, *, params=None, data=None, \
                        json=None,\
                        headers=None, cookies=None, auth=None, \
                        allow_redirects=True, max_redirects=10, \
                        encoding='utf-8', \
                        version=HttpVersion(major=1, minor=1), \
                        compress=None, chunked=None, expect100=False, raise_for_status=False, \
                        read_bufsize=None, \
                        connector=None, loop=None,\
                        read_until_eof=True, timeout=sentinel)
   :async-with:

   Asynchronous context manager for performing an asynchronous HTTP
   request. Returns a :class:`ClientResponse` response object.

   :param str method: HTTP method

   :param url: Requested URL, :class:`str` or :class:`~yarl.URL`

   :param dict params: Parameters to be sent in the query
                       string of the new request (optional)

   :param data: The data to send in the body of the request. This can be a
                :class:`FormData` object or anything that can be passed into
                :class:`FormData`, e.g. a dictionary, bytes, or file-like object.
                (optional)

   :param json: Any json compatible python object (optional). *json* and *data*
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

   :param bool raise_for_status: Automatically call
                                 :meth:`ClientResponse.raise_for_status()`
                                 for response if set to ``True``.  If
                                 set to ``None`` value from
                                 ``ClientSession`` will be used.
                                 ``None`` by default (optional).

      .. versionadded:: 3.4

   :param aiohttp.BaseConnector connector: BaseConnector sub-class
      instance to support connection pooling.

   :param bool read_until_eof: Read response until EOF if response
                               does not have Content-Length header.
                               ``True`` by default (optional).

   :param int read_bufsize: Size of the read buffer (:attr:`ClientResponse.content`).
                            ``None`` by default,
                            it means that the session global value is used.

      .. versionadded:: 3.7

   :param timeout: a :class:`ClientTimeout` settings structure, 300 seconds (5min)
        total timeout by default.

   :param loop: :ref:`event loop<asyncio-event-loop>`
                used for processing HTTP requests.
                If param is ``None``, :func:`asyncio.get_event_loop`
                is used for getting default event loop.

      .. deprecated:: 2.0

   :return ClientResponse: a :class:`client response <ClientResponse>` object.

   Usage::

      import aiohttp

      async def fetch():
          async with aiohttp.request('GET',
                  'http://python.org/') as resp:
              assert resp.status == 200
              print(await resp.text())


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

By default all *connectors* support *keep-alive connections* (behavior
is controlled by *force_close* constructor's parameter).


BaseConnector
^^^^^^^^^^^^^

.. class:: BaseConnector(*, keepalive_timeout=15, \
                         force_close=False, limit=100, limit_per_host=0, \
                         enable_cleanup_closed=False, loop=None)

   Base class for all connectors.

   :param float keepalive_timeout: timeout for connection reusing
                                   after releasing (optional). Values
                                   ``0``. For disabling *keep-alive*
                                   feature use ``force_close=True``
                                   flag.

   :param int limit: total number simultaneous connections. If *limit* is
                     ``None`` the connector has no limit (default: 100).

   :param int limit_per_host: limit simultaneous connections to the same
      endpoint.  Endpoints are the same if they are
      have equal ``(host, port, is_ssl)`` triple.
      If *limit* is ``0`` the connector has no limit (default: 0).

   :param bool force_close: close underlying sockets after
                            connection releasing (optional).

   :param bool enable_cleanup_closed: some SSL servers do not properly complete
      SSL shutdown process, in that case asyncio leaks ssl connections.
      If this parameter is set to True, aiohttp additionally aborts underlining
      transport after 2 seconds. It is off by default.


   :param loop: :ref:`event loop<asyncio-event-loop>`
      used for handling connections.
      If param is ``None``, :func:`asyncio.get_event_loop`
      is used for getting default event loop.

      .. deprecated:: 2.0

   .. attribute:: closed

      Read-only property, ``True`` if connector is closed.

   .. attribute:: force_close

      Read-only property, ``True`` if connector should ultimately
      close connections on releasing.

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

   .. comethod:: close()

      Close all opened connections.

   .. comethod:: connect(request)

      Get a free connection from pool or create new one if connection
      is absent in the pool.

      The call may be paused if :attr:`limit` is exhausted until used
      connections returns to pool.

      :param aiohttp.ClientRequest request: request object
                                                   which is connection
                                                   initiator.

      :return: :class:`Connection` object.

   .. comethod:: _create_connection(req)

      Abstract method for actual connection establishing, should be
      overridden in subclasses.




TCPConnector
^^^^^^^^^^^^

.. class:: TCPConnector(*, ssl=None, verify_ssl=True, fingerprint=None, \
                 use_dns_cache=True, ttl_dns_cache=10, \
                 family=0, ssl_context=None, local_addr=None, \
                 resolver=None, keepalive_timeout=sentinel, \
                 force_close=False, limit=100, limit_per_host=0, \
                 enable_cleanup_closed=False, loop=None)

   Connector for working with *HTTP* and *HTTPS* via *TCP* sockets.

   The most common transport. When you don't know what connector type
   to use, use a :class:`TCPConnector` instance.

   :class:`TCPConnector` inherits from :class:`BaseConnector`.

   Constructor accepts all parameters suitable for
   :class:`BaseConnector` plus several TCP-specific ones:

      :param ssl: SSL validation mode. ``None`` for default SSL check
                  (:func:`ssl.create_default_context` is used),
                  ``False`` for skip SSL certificate validation,
                  :class:`aiohttp.Fingerprint` for fingerprint
                  validation, :class:`ssl.SSLContext` for custom SSL
                  certificate validation.

                  Supersedes *verify_ssl*, *ssl_context* and
                  *fingerprint* parameters.

         .. versionadded:: 3.0

   :param bool verify_ssl: perform SSL certificate validation for
      *HTTPS* requests (enabled by default). May be disabled to
      skip validation for sites with invalid certificates.

      .. deprecated:: 2.3

         Pass *verify_ssl* to ``ClientSession.get()`` etc.

   :param bytes fingerprint: pass the SHA256 digest of the expected
      certificate in DER format to verify that the certificate the
      server presents matches. Useful for `certificate pinning
      <https://en.wikipedia.org/wiki/Transport_Layer_Security#Certificate_pinning>`_.

      Note: use of MD5 or SHA1 digests is insecure and deprecated.

      .. deprecated:: 2.3

         Pass *verify_ssl* to ``ClientSession.get()`` etc.

   :param bool use_dns_cache: use internal cache for DNS lookups, ``True``
      by default.

      Enabling an option *may* speedup connection
      establishing a bit but may introduce some
      *side effects* also.

   :param int ttl_dns_cache: expire after some seconds the DNS entries, ``None``
      means cached forever. By default 10 seconds (optional).

      In some environments the IP addresses related to a specific HOST can
      change after a specific time. Use this option to keep the DNS cache
      updated refreshing each entry after N seconds.

   :param int limit: total number simultaneous connections. If *limit* is
                     ``None`` the connector has no limit (default: 100).

   :param int limit_per_host: limit simultaneous connections to the same
      endpoint.  Endpoints are the same if they are
      have equal ``(host, port, is_ssl)`` triple.
      If *limit* is ``0`` the connector has no limit (default: 0).

   :param aiohttp.abc.AbstractResolver resolver: custom resolver
      instance to use.  ``aiohttp.DefaultResolver`` by
      default (asynchronous if ``aiodns>=1.1`` is installed).

      Custom resolvers allow to resolve hostnames differently than the
      way the host is configured.

      The resolver is ``aiohttp.ThreadedResolver`` by default,
      asynchronous version is pretty robust but might fail in
      very rare cases.

   :param int family: TCP socket family, both IPv4 and IPv6 by default.
                      For *IPv4* only use :const:`socket.AF_INET`,
                      for  *IPv6* only -- :const:`socket.AF_INET6`.

                      *family* is ``0`` by default, that means both
                      IPv4 and IPv6 are accepted. To specify only
                      concrete version please pass
                      :const:`socket.AF_INET` or
                      :const:`socket.AF_INET6` explicitly.

   :param ssl.SSLContext ssl_context: SSL context used for processing
      *HTTPS* requests (optional).

      *ssl_context* may be used for configuring certification
      authority channel, supported SSL options etc.

   :param tuple local_addr: tuple of ``(local_host, local_port)`` used to bind
      socket locally if specified.

   :param bool force_close: close underlying sockets after
                            connection releasing (optional).

   :param bool enable_cleanup_closed: Some ssl servers do not properly complete
      SSL shutdown process, in that case asyncio leaks SSL connections.
      If this parameter is set to True, aiohttp additionally aborts underlining
      transport after 2 seconds. It is off by default.

   .. attribute:: family

      *TCP* socket family e.g. :const:`socket.AF_INET` or
      :const:`socket.AF_INET6`

      Read-only property.

   .. attribute:: dns_cache

      Use quick lookup in internal *DNS* cache for host names if ``True``.

      Read-only :class:`bool` property.

   .. attribute:: cached_hosts

      The cache of resolved hosts if :attr:`dns_cache` is enabled.

      Read-only :class:`types.MappingProxyType` property.

   .. method:: clear_dns_cache(self, host=None, port=None)

      Clear internal *DNS* cache.

      Remove specific entry if both *host* and *port* are specified,
      clear all cache otherwise.


UnixConnector
^^^^^^^^^^^^^

.. class:: UnixConnector(path, *, conn_timeout=None, \
                         keepalive_timeout=30, limit=100, \
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

      .. deprecated:: 3.5

   .. attribute:: transport

      Connection transport

   .. method:: close()

      Close connection with forcibly closing underlying socket.

   .. method:: release()

      Release connection back to connector.

      Underlying socket is not closed, the connection may be reused
      later if timeout (30 seconds by default) for connection was not
      expired.


Response object
---------------

.. class:: ClientResponse

   Client response returned by :meth:`ClientSession.request` and family.

   User never creates the instance of ClientResponse class but gets it
   from API calls.

   :class:`ClientResponse` supports async context manager protocol, e.g.::

       resp = await client_session.get(url)
       async with resp:
           assert resp.status == 200

   After exiting from ``async with`` block response object will be
   *released* (see :meth:`release` coroutine).

   .. attribute:: version

      Response's version, :class:`HttpVersion` instance.

   .. attribute:: status

      HTTP status code of response (:class:`int`), e.g. ``200``.

   .. attribute:: reason

      HTTP status reason of response (:class:`str`), e.g. ``"OK"``.

   .. attribute:: ok

      Boolean representation of HTTP status code (:class:`bool`).
      ``True`` if ``status`` is less than ``400``; otherwise, ``False``.

   .. attribute:: method

      Request's method (:class:`str`).

   .. attribute:: url

      URL of request (:class:`~yarl.URL`).

   .. attribute:: real_url

      Unmodified URL of request with URL fragment unstripped (:class:`~yarl.URL`).

      .. versionadded:: 3.2

   .. attribute:: connection

      :class:`Connection` used for handling response.

   .. attribute:: content

      Payload stream, which contains response's BODY (:class:`StreamReader`).
      It supports various reading methods depending on the expected format.
      When chunked transfer encoding is used by the server, allows retrieving
      the actual http chunks.

      Reading from the stream may raise
      :exc:`aiohttp.ClientPayloadError` if the response object is
      closed before response receives all data or in case if any
      transfer encoding related errors like misformed chunked
      encoding of broken compression data.

   .. attribute:: cookies

      HTTP cookies of response (*Set-Cookie* HTTP header,
      :class:`~http.cookies.SimpleCookie`).

   .. attribute:: headers

      A case-insensitive multidict proxy with HTTP headers of
      response, :class:`~multidict.CIMultiDictProxy`.

   .. attribute:: raw_headers

      Unmodified HTTP headers of response as unconverted bytes, a sequence of
      ``(key, value)`` pairs.

   .. attribute:: links

      Link HTTP header parsed into a :class:`~multidict.MultiDictProxy`.

      For each link, key is link param `rel` when it exists, or link url as
      :class:`str` otherwise, and value is :class:`~multidict.MultiDictProxy`
      of link params and url at key `url` as :class:`~yarl.URL` instance.

      .. versionadded:: 3.2

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

   .. attribute:: content_disposition

      Read-only property that specified the *Content-Disposition* HTTP header.

      Instance of :class:`ContentDisposition` or ``None`` if no *Content-Disposition*
      header present in HTTP headers.

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

      Raise an :exc:`aiohttp.ClientResponseError` if the data can't
      be read.

      :return bytes: read *BODY*.

      .. seealso:: :meth:`close`, :meth:`release`.

   .. comethod:: release()

      It is not required to call `release` on the response
      object. When the client fully receives the payload, the
      underlying connection automatically returns back to pool. If the
      payload is not fully read, the connection is closed

   .. method:: raise_for_status()

      Raise an :exc:`aiohttp.ClientResponseError` if the response
      status is 400 or higher.

      Do nothing for success responses (less than 400).

   .. comethod:: text(encoding=None)

      Read response's body and return decoded :class:`str` using
      specified *encoding* parameter.

      If *encoding* is ``None`` content encoding is autocalculated
      using ``Content-Type`` HTTP header and *chardet* tool if the
      header is not provided by server.

      :term:`cchardet` is used with fallback to :term:`chardet` if
      *cchardet* is not available.

      Close underlying connection if data reading gets an error,
      release connection otherwise.

      :param str encoding: text encoding used for *BODY* decoding, or
                           ``None`` for encoding autodetection
                           (default).

      :return str: decoded *BODY*

      :raise LookupError: if the encoding detected by chardet or cchardet is
                          unknown by Python (e.g. VISCII).

      .. note::

         If response has no ``charset`` info in ``Content-Type`` HTTP
         header :term:`cchardet` / :term:`chardet` is used for content
         encoding autodetection.

         It may hurt performance. If page encoding is known passing
         explicit *encoding* parameter might help::

            await resp.text('ISO-8859-1')

   .. comethod:: json(*, encoding=None, loads=json.loads, \
                      content_type='application/json')

      Read response's body as *JSON*, return :class:`dict` using
      specified *encoding* and *loader*. If data is not still available
      a ``read`` call will be done,

      If *encoding* is ``None`` content encoding is autocalculated
      using :term:`cchardet` or :term:`chardet` as fallback if
      *cchardet* is not available.

      if response's `content-type` does not match `content_type` parameter
      :exc:`aiohttp.ContentTypeError` get raised.
      To disable content type check pass ``None`` value.

      :param str encoding: text encoding used for *BODY* decoding, or
                           ``None`` for encoding autodetection
                           (default).

                           By the standard JSON encoding should be
                           ``UTF-8`` but practice beats purity: some
                           servers return non-UTF
                           responses. Autodetection works pretty fine
                           anyway.

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
       object, :class:`aiohttp.RequestInfo` instance.

   .. method:: get_encoding()

      Automatically detect content encoding using ``charset`` info in
      ``Content-Type`` HTTP header. If this info is not exists or there
      are no appropriate codecs for encoding then :term:`cchardet` /
      :term:`chardet` is used.

      Beware that it is not always safe to use the result of this function to
      decode a response. Some encodings detected by cchardet are not known by
      Python (e.g. VISCII).

      :raise RuntimeError: if called before the body has been read,
                           for :term:`cchardet` usage

      .. versionadded:: 3.0


ClientWebSocketResponse
-----------------------

To connect to a websocket server :func:`aiohttp.ws_connect` or
:meth:`aiohttp.ClientSession.ws_connect` coroutines should be used, do
not create an instance of class :class:`ClientWebSocketResponse`
manually.

.. class:: ClientWebSocketResponse()

   Class for handling client-side websockets.

   .. attribute:: closed

      Read-only property, ``True`` if :meth:`close` has been called or
      :const:`~aiohttp.WSMsgType.CLOSE` message has been received from peer.

   .. attribute:: protocol

      Websocket *subprotocol* chosen after :meth:`start` call.

      May be ``None`` if server and client protocols are
      not overlapping.

   .. method:: get_extra_info(name, default=None)

      Reads extra info from connection's transport

   .. method:: exception()

      Returns exception if any occurs or returns None.

   .. comethod:: ping(message=b'')

      Send :const:`~aiohttp.WSMsgType.PING` to peer.

      :param message: optional payload of *ping* message,
                      :class:`str` (converted to *UTF-8* encoded bytes)
                      or :class:`bytes`.

      .. versionchanged:: 3.0

         The method is converted into :term:`coroutine`

   .. comethod:: pong(message=b'')

      Send :const:`~aiohttp.WSMsgType.PONG` to peer.

      :param message: optional payload of *pong* message,
                      :class:`str` (converted to *UTF-8* encoded bytes)
                      or :class:`bytes`.

      .. versionchanged:: 3.0

         The method is converted into :term:`coroutine`

   .. comethod:: send_str(data, compress=None)

      Send *data* to peer as :const:`~aiohttp.WSMsgType.TEXT` message.

      :param str data: data to send.

      :param int compress: sets specific level of compression for
                           single message,
                           ``None`` for not overriding per-socket setting.

      :raise TypeError: if data is not :class:`str`

      .. versionchanged:: 3.0

         The method is converted into :term:`coroutine`,
         *compress* parameter added.

   .. comethod:: send_bytes(data, compress=None)

      Send *data* to peer as :const:`~aiohttp.WSMsgType.BINARY` message.

      :param data: data to send.

      :param int compress: sets specific level of compression for
                           single message,
                           ``None`` for not overriding per-socket setting.

      :raise TypeError: if data is not :class:`bytes`,
                        :class:`bytearray` or :class:`memoryview`.

      .. versionchanged:: 3.0

         The method is converted into :term:`coroutine`,
         *compress* parameter added.

   .. comethod:: send_json(data, compress=None, *, dumps=json.dumps)

      Send *data* to peer as JSON string.

      :param data: data to send.

      :param int compress: sets specific level of compression for
                           single message,
                           ``None`` for not overriding per-socket setting.

      :param callable dumps: any :term:`callable` that accepts an object and
                             returns a JSON string
                             (:func:`json.dumps` by default).

      :raise RuntimeError: if connection is not started or closing

      :raise ValueError: if data is not serializable object

      :raise TypeError: if value returned by ``dumps(data)`` is not
                        :class:`str`

      .. versionchanged:: 3.0

         The method is converted into :term:`coroutine`,
         *compress* parameter added.

   .. comethod:: close(*, code=1000, message=b'')

      A :ref:`coroutine<coroutine>` that initiates closing handshake by sending
      :const:`~aiohttp.WSMsgType.CLOSE` message. It waits for
      close response from server. To add a timeout to `close()` call
      just wrap the call with `asyncio.wait()` or `asyncio.wait_for()`.

      :param int code: closing code

      :param message: optional payload of *close* message,
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

      :return: :class:`~aiohttp.WSMessage`

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


ClientTimeout
^^^^^^^^^^^^^

.. class:: ClientTimeout(*, total=None, connect=None, \
                         sock_connect=None, sock_read=None)

   A data class for client timeout settings.

   See :ref:`aiohttp-client-timeouts` for usage examples.

   .. attribute:: total

      Total number of seconds for the whole request.

      :class:`float`, ``None`` by default.

   .. attribute:: connect

      Maximal number of seconds for acquiring a connection from pool.  The time
      consists connection establishment for a new connection or
      waiting for a free connection from a pool if pool connection
      limits are exceeded.

      For pure socket connection establishment time use
      :attr:`sock_connect`.

      :class:`float`, ``None`` by default.

   .. attribute:: sock_connect

      Maximal number of seconds for connecting to a peer for a new connection, not
      given from a pool.  See also :attr:`connect`.

      :class:`float`, ``None`` by default.

   .. attribute:: sock_read

      Maximal number of seconds for reading a portion of data from a peer.

      :class:`float`, ``None`` by default.

   .. versionadded:: 3.3

RequestInfo
^^^^^^^^^^^

.. class:: RequestInfo()

   A data class with request URL and headers from :class:`ClientRequest`
   object, available as :attr:`ClientResponse.request_info` attribute.

   .. attribute:: url

      Requested *url*, :class:`yarl.URL` instance.

   .. attribute:: method

      Request HTTP method like ``'GET'`` or ``'POST'``, :class:`str`.

   .. attribute:: headers

      HTTP headers for request, :class:`multidict.CIMultiDict` instance.

   .. attribute:: real_url

      Requested *url* with URL fragment unstripped, :class:`yarl.URL` instance.

      .. versionadded:: 3.2


BasicAuth
^^^^^^^^^

.. class:: BasicAuth(login, password='', encoding='latin1')

   HTTP basic authentication helper.

   :param str login: login
   :param str password: password
   :param str encoding: encoding (``'latin1'`` by default)


   Should be used for specifying authorization data in client API,
   e.g. *auth* parameter for :meth:`ClientSession.request`.


   .. classmethod:: decode(auth_header, encoding='latin1')

      Decode HTTP basic authentication credentials.

      :param str auth_header:  The ``Authorization`` header to decode.
      :param str encoding: (optional) encoding ('latin1' by default)

      :return:  decoded authentication data, :class:`BasicAuth`.

   .. classmethod:: from_url(url)

      Constructed credentials info from url's *user* and *password*
      parts.

      :return: credentials data, :class:`BasicAuth` or ``None`` is
                credentials are not provided.

      .. versionadded:: 2.3

   .. method:: encode()

      Encode credentials into string suitable for ``Authorization``
      header etc.

      :return: encoded authentication data, :class:`str`.


CookieJar
^^^^^^^^^

.. class:: CookieJar(*, unsafe=False, quote_cookie=True, loop=None)

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

   :param bool quote_cookie: (optional) Whether to quote cookies according to
                             :rfc:`2109`.  Some backend systems
                             (not compatible with RFC mentioned above)
                             does not support quoted cookies.

      .. versionadded:: 3.7

   :param bool loop: an :ref:`event loop<asyncio-event-loop>` instance.
      See :class:`aiohttp.abc.AbstractCookieJar`

      .. deprecated:: 2.0


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


.. class:: DummyCookieJar(*, loop=None)

   Dummy cookie jar which does not store cookies but ignores them.

   Could be useful e.g. for web crawlers to iterate over Internet
   without blowing up with saved cookies information.

   To install dummy cookie jar pass it into session instance::

      jar = aiohttp.DummyCookieJar()
      session = aiohttp.ClientSession(cookie_jar=DummyCookieJar())


.. class:: Fingerprint(digest)

   Fingerprint helper for checking SSL certificates by *SHA256* digest.

   :param bytes digest: *SHA256* digest for certificate in DER-encoded
                        binary form (see
                        :meth:`ssl.SSLSocket.getpeercert`).

   To check fingerprint pass the object into :meth:`ClientSession.get`
   call, e.g.::

      import hashlib

      with open(path_to_cert, 'rb') as f:
          digest = hashlib.sha256(f.read()).digest()

      await session.get(url, ssl=aiohttp.Fingerprint(digest))

   .. versionadded:: 3.0

FormData
^^^^^^^^

A :class:`FormData` object contains the form data and also handles
encoding it into a body that is either ``multipart/form-data`` or
``application/x-www-form-urlencoded``. ``multipart/form-data`` is
used if at least one field is an :class:`io.IOBase` object or was
added with at least one optional argument to :meth:`add_field<aiohttp.FormData.add_field>`
(``content_type``, ``filename``, or ``content_transfer_encoding``).
Otherwise, ``application/x-www-form-urlencoded`` is used.

:class:`FormData` instances are callable and return a :class:`Payload`
on being called.

.. class:: FormData(fields, quote_fields=True, charset=None)

   Helper class for multipart/form-data and application/x-www-form-urlencoded body generation.

   :param fields: A container for the key/value pairs of this form.

                  Possible types are:

                  - :class:`dict`
                  - :class:`tuple` or :class:`list`
                  - :class:`io.IOBase`, e.g. a file-like object
                  - :class:`multidict.MultiDict` or :class:`multidict.MultiDictProxy`

                  If it is a :class:`tuple` or :class:`list`, it must be a valid argument
                  for :meth:`add_fields<aiohttp.FormData.add_fields>`.

                  For :class:`dict`, :class:`multidict.MultiDict`, and :class:`multidict.MultiDictProxy`,
                  the keys and values must be valid `name` and `value` arguments to
                  :meth:`add_field<aiohttp.FormData.add_field>`, respectively.

   .. method:: add_field(name, value, content_type=None, filename=None,\
                         content_transfer_encoding=None)

      Add a field to the form.

      :param str name: Name of the field

      :param value: Value of the field

                    Possible types are:

                    - :class:`str`
                    - :class:`bytes`, :class:`bytesarray`, or :class:`memoryview`
                    - :class:`io.IOBase`, e.g. a file-like object

      :param str content_type: The field's content-type header (optional)

      :param str filename: The field's filename (optional)

                           If this is not set and ``value`` is a :class:`bytes`, :class:`bytesarray`,
                           or :class:`memoryview` object, the `name` argument is used as the filename
                           unless ``content_transfer_encoding`` is specified.

                           If ``filename`` is not set and ``value`` is an :class:`io.IOBase`
                           object, the filename is extracted from the object if possible.

      :param str content_transfer_encoding: The field's content-transfer-encoding
                                            header (optional)

   .. method:: add_fields(fields)

      Add one or more fields to the form.

      :param fields: An iterable containing:

                     - :class:`io.IOBase`, e.g. a file-like object
                     - :class:`multidict.MultiDict` or :class:`multidict.MultiDictProxy`
                     - :class:`tuple` or :class:`list` of length two, containing a name-value pair

Client exceptions
-----------------

Exception hierarchy has been significantly modified in version
2.0. aiohttp defines only exceptions that covers connection handling
and server response misbehaviors.  For developer specific mistakes,
aiohttp uses python standard exceptions like :exc:`ValueError` or
:exc:`TypeError`.

Reading a response content may raise a :exc:`ClientPayloadError`
exception. This exception indicates errors specific to the payload
encoding. Such as invalid compressed data, malformed chunked-encoded
chunks or not enough data that satisfy the content-length header.

All exceptions are available as members of *aiohttp* module.

.. exception:: ClientError

   Base class for all client specific exceptions.

   Derived from :exc:`Exception`


.. class:: ClientPayloadError

   This exception can only be raised while reading the response
   payload if one of these errors occurs:

   1. invalid compression
   2. malformed chunked encoding
   3. not enough data that satisfy ``Content-Length`` HTTP header.

   Derived from :exc:`ClientError`

.. exception:: InvalidURL

   URL used for fetching is malformed, e.g. it does not contain host
   part.

   Derived from :exc:`ClientError` and :exc:`ValueError`

   .. attribute:: url

      Invalid URL, :class:`yarl.URL` instance.

.. class:: ContentDisposition

    Represent Content-Disposition header

    .. attribute:: value

    A :class:`str` instance. Value of Content-Disposition header
    itself, e.g. ``attachment``.

    .. attribute:: filename

    A :class:`str` instance. Content filename extracted from
    parameters. May be ``None``.

    .. attribute:: parameters

    Read-only mapping contains all parameters.

Response errors
^^^^^^^^^^^^^^^

.. exception:: ClientResponseError

   These exceptions could happen after we get response from server.

   Derived from :exc:`ClientError`

   .. attribute:: request_info

      Instance of :class:`RequestInfo` object, contains information
      about request.

   .. attribute:: status

      HTTP status code of response (:class:`int`), e.g. ``400``.

   .. attribute:: message

      Message of response (:class:`str`), e.g. ``"OK"``.

   .. attribute:: headers

      Headers in response, a list of pairs.

   .. attribute:: history

      History from failed response, if available, else empty tuple.

      A :class:`tuple` of :class:`ClientResponse` objects used for
      handle redirection responses.

   .. attribute:: code

      HTTP status code of response (:class:`int`), e.g. ``400``.

      .. deprecated:: 3.1


.. class:: WSServerHandshakeError

   Web socket server response error.

   Derived from :exc:`ClientResponseError`


.. class:: ContentTypeError

   Invalid content type.

   Derived from :exc:`ClientResponseError`

   .. versionadded:: 2.3


.. class:: TooManyRedirects

   Client was redirected too many times.

   Maximum number of redirects can be configured by using
   parameter ``max_redirects`` in :meth:`request<aiohttp.ClientSession.request>`.

   Derived from :exc:`ClientResponseError`

   .. versionadded:: 3.2

Connection errors
^^^^^^^^^^^^^^^^^

.. class:: ClientConnectionError

   These exceptions related to low-level connection problems.

   Derived from :exc:`ClientError`

.. class:: ClientOSError

   Subset of connection errors that are initiated by an :exc:`OSError`
   exception.

   Derived from :exc:`ClientConnectionError` and :exc:`OSError`

.. class:: ClientConnectorError

   Connector related exceptions.

   Derived from :exc:`ClientOSError`

.. class:: ClientProxyConnectionError

   Derived from :exc:`ClientConnectorError`

.. class:: ServerConnectionError

   Derived from :exc:`ClientConnectionError`

.. class:: ClientSSLError

   Derived from :exc:`ClientConnectorError`

.. class:: ClientConnectorSSLError

   Response ssl error.

   Derived from :exc:`ClientSSLError` and :exc:`ssl.SSLError`

.. class:: ClientConnectorCertificateError

   Response certificate error.

   Derived from :exc:`ClientSSLError` and :exc:`ssl.CertificateError`

.. class:: ServerDisconnectedError

   Server disconnected.

   Derived from :exc:`ServerDisconnectionError`

   .. attribute:: message

      Partially parsed HTTP message (optional).


.. class:: ServerTimeoutError

   Server operation timeout: read timeout, etc.

   Derived from :exc:`ServerConnectionError` and :exc:`asyncio.TimeoutError`

.. class:: ServerFingerprintMismatch

   Server fingerprint mismatch.

   Derived from :exc:`ServerConnectionError`


Hierarchy of exceptions
^^^^^^^^^^^^^^^^^^^^^^^

* :exc:`ClientError`

  * :exc:`ClientResponseError`

    * :exc:`ContentTypeError`
    * :exc:`WSServerHandshakeError`
    * :exc:`ClientHttpProxyError`

  * :exc:`ClientConnectionError`

    * :exc:`ClientOSError`

      * :exc:`ClientConnectorError`

         * :exc:`ClientSSLError`

           * :exc:`ClientConnectorCertificateError`

           * :exc:`ClientConnectorSSLError`

         * :exc:`ClientProxyConnectionError`

      * :exc:`ServerConnectionError`

         * :exc:`ServerDisconnectedError`
         * :exc:`ServerTimeoutError`

      * :exc:`ServerFingerprintMismatch`

  * :exc:`ClientPayloadError`

  * :exc:`InvalidURL`
