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

     asyncio.run(main())


The client session supports the context manager protocol for self closing.

.. class:: ClientSession(base_url=None, *, \
                         connector=None, cookies=None, \
                         headers=None, skip_auto_headers=None, \
                         auth=None, json_serialize=json.dumps, \
                         request_class=ClientRequest, \
                         response_class=ClientResponse, \
                         ws_response_class=ClientWebSocketResponse, \
                         version=aiohttp.HttpVersion11, \
                         cookie_jar=None, \
                         connector_owner=True, \
                         raise_for_status=False, \
                         timeout=sentinel, \
                         auto_decompress=True, \
                         trust_env=False, \
                         requote_redirect_url=True, \
                         trace_configs=None, \
                         read_bufsize=2**16, \
                         max_line_size=8190, \
                         max_field_size=8190, \
                         fallback_charset_resolver=lambda r, b: "utf-8")

   The class for creating client sessions and making requests.


   :param base_url: Base part of the URL (optional)
      If set, it allows to skip the base part (https://docs.aiohttp.org) in
      request calls. It must not include a path (as in
      https://docs.aiohttp.org/en/stable).

      .. versionadded:: 3.8

   :param aiohttp.BaseConnector connector: BaseConnector
      sub-class instance to support connection pooling.

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

      Iterable of :class:`str` or :class:`~multidict.istr` (optional)

   :param aiohttp.BasicAuth auth: an object that represents HTTP Basic
                                  Authorization (optional). It will be included
                                  with any request. However, if the
                                  ``_base_url`` parameter is set, the request
                                  URL's origin must match the base URL's origin;
                                  otherwise, the default auth will not be
                                  included.

   :param collections.abc.Callable json_serialize: Json *serializer* callable.

      By default :func:`json.dumps` function.

   :param aiohttp.ClientRequest request_class: Custom class to use for client requests.

   :param ClientResponse response_class: Custom class to use for client responses.

   :param ClientWebSocketResponse ws_response_class: Custom class to use for websocket responses.

   :param version: supported HTTP version, ``HTTP 1.1`` by default.

   :param cookie_jar: Cookie Jar, :class:`~aiohttp.abc.AbstractCookieJar` instance.

      By default every session instance has own private cookie jar for
      automatic cookies processing but user may redefine this behavior
      by providing own jar implementation.

      One example is not processing cookies at all when working in
      proxy mode.

      If no cookie processing is needed, a
      :class:`aiohttp.DummyCookieJar` instance can be
      provided.

   :param bool connector_owner:

      Close connector instance on session closing.

      Setting the parameter to ``False`` allows to share
      connection pool between sessions without sharing session state:
      cookies etc.

   :param bool raise_for_status:

      Automatically call :meth:`ClientResponse.raise_for_status` for
      each response, ``False`` by default.

      This parameter can be overridden when making a request, e.g.::

          client_session = aiohttp.ClientSession(raise_for_status=True)
          resp = await client_session.get(url, raise_for_status=False)
          async with resp:
              assert resp.status == 200

      Set the parameter to ``True`` if you need ``raise_for_status``
      for most of cases but override ``raise_for_status`` for those
      requests where you need to handle responses with status 400 or
      higher.

   :param timeout: a :class:`ClientTimeout` settings structure, 300 seconds (5min)
        total timeout, 30 seconds socket connect timeout by default.

      .. versionadded:: 3.3

      .. versionchanged:: 3.10.9

         The default value for the ``sock_connect`` timeout has been changed to 30 seconds.

   :param bool auto_decompress: Automatically decompress response body (``True`` by default).

      .. versionadded:: 2.3

   :param bool trust_env: Trust environment settings for proxy configuration if the parameter
      is ``True`` (``False`` by default). See :ref:`aiohttp-client-proxy-support` for
      more information.

      Get proxy credentials from ``~/.netrc`` file if present.

      Get HTTP Basic Auth credentials from :file:`~/.netrc` file if present.

      If :envvar:`NETRC` environment variable is set, read from file specified
      there rather than from :file:`~/.netrc`.

      .. seealso::

         ``.netrc`` documentation: https://www.gnu.org/software/inetutils/manual/html_node/The-_002enetrc-file.html

      .. versionadded:: 2.3

      .. versionchanged:: 3.0

         Added support for ``~/.netrc`` file.

      .. versionchanged:: 3.9

         Added support for reading HTTP Basic Auth credentials from :file:`~/.netrc` file.

   :param bool requote_redirect_url: Apply *URL requoting* for redirection URLs if
                                     automatic redirection is enabled (``True`` by
                                     default).

      .. versionadded:: 3.5

   :param trace_configs: A list of :class:`TraceConfig` instances used for client
                         tracing.  ``None`` (default) is used for request tracing
                         disabling.  See :ref:`aiohttp-client-tracing-reference` for
                         more information.

   :param int read_bufsize: Size of the read buffer (:attr:`ClientResponse.content`).
                            64 KiB by default.

      .. versionadded:: 3.7

   :param int max_line_size: Maximum allowed size of lines in responses.

   :param int max_field_size: Maximum allowed size of header fields in responses.

   :param Callable[[ClientResponse,bytes],str] fallback_charset_resolver:
      A :term:`callable` that accepts a :class:`ClientResponse` and the
      :class:`bytes` contents, and returns a :class:`str` which will be used as
      the encoding parameter to :meth:`bytes.decode()`.

      This function will be called when the charset is not known (e.g. not specified in the
      Content-Type header). The default function simply defaults to ``utf-8``.

      .. versionadded:: 3.8.6

   .. attribute:: closed

      ``True`` if the session has been closed, ``False`` otherwise.

      A read-only property.

   .. attribute:: connector

      :class:`aiohttp.BaseConnector` derived instance used
      for the session.

      A read-only property.

   .. attribute:: cookie_jar

      The session cookies, :class:`~aiohttp.abc.AbstractCookieJar` instance.

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

      :class:`frozenset` of :class:`str` or :class:`~multidict.istr` (optional)

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

      Should :meth:`ClientResponse.raise_for_status` be called for each response

      Either :class:`bool` or :class:`collections.abc.Callable`

      .. versionadded:: 3.7

   .. attribute:: auto_decompress

      Should the body response be automatically decompressed

      :class:`bool` default is ``True``

      .. versionadded:: 3.7

   .. attribute:: trust_env

      Trust environment settings for proxy configuration
      or ~/.netrc file if present. See :ref:`aiohttp-client-proxy-support` for
      more information.

      :class:`bool` default is ``False``

      .. versionadded:: 3.7

   .. attribute:: trace_config

      A list of :class:`TraceConfig` instances used for client
      tracing.  ``None`` (default) is used for request tracing
      disabling.  See :ref:`aiohttp-client-tracing-reference` for more information.

      .. versionadded:: 3.7

   .. method:: request(method, url, *, params=None, data=None, json=None,\
                         cookies=None, headers=None, skip_auto_headers=None, \
                         auth=None, allow_redirects=True,\
                         max_redirects=10,\
                         compress=None, chunked=None, expect100=False, raise_for_status=None,\
                         read_until_eof=True, \
                         proxy=None, proxy_auth=None,\
                         timeout=sentinel, ssl=True, \
                         server_hostname=None, \
                         proxy_headers=None, \
                         trace_request_ctx=None, \
                         read_bufsize=None, \
                         auto_decompress=None, \
                         max_line_size=None, \
                         max_field_size=None)
      :async:
      :noindexentry:

      Performs an asynchronous HTTP request. Returns a response object that
      should be used as an async context manager.

      :param str method: HTTP method

      :param url: Request URL, :class:`~yarl.URL` or :class:`str` that will
                  be encoded with :class:`~yarl.URL` (see :class:`~yarl.URL`
                  to skip encoding).

      :param params: Mapping, iterable of tuple of *key*/*value* pairs or
                     string to be sent as parameters in the query
                     string of the new request. Ignored for subsequent
                     redirected requests (optional)

                     Allowed values are:

                     - :class:`collections.abc.Mapping` e.g. :class:`dict`,
                       :class:`multidict.MultiDict` or
                       :class:`multidict.MultiDictProxy`
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

         Iterable of :class:`str` or :class:`~multidict.istr`
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

      :param bool raise_for_status: Automatically call :meth:`ClientResponse.raise_for_status` for
                                    response if set to ``True``.
                                    If set to ``None`` value from ``ClientSession`` will be used.
                                    ``None`` by default (optional).

          .. versionadded:: 3.4

      :param bool read_until_eof: Read response until EOF if response
                                  does not have Content-Length header.
                                  ``True`` by default (optional).

      :param proxy: Proxy URL, :class:`str` or :class:`~yarl.URL` (optional)

      :param aiohttp.BasicAuth proxy_auth: an object that represents proxy HTTP
                                           Basic Authorization (optional)

      :param int timeout: override the session's timeout.

         .. versionchanged:: 3.3

            The parameter is :class:`ClientTimeout` instance,
            :class:`float` is still supported for sake of backward
            compatibility.

            If :class:`float` is passed it is a *total* timeout (in seconds).

      :param ssl: SSL validation mode. ``True`` for default SSL check
                  (:func:`ssl.create_default_context` is used),
                  ``False`` for skip SSL certificate validation,
                  :class:`aiohttp.Fingerprint` for fingerprint
                  validation, :class:`ssl.SSLContext` for custom SSL
                  certificate validation.

                  Supersedes *verify_ssl*, *ssl_context* and
                  *fingerprint* parameters.

         .. versionadded:: 3.0

      :param str server_hostname: Sets or overrides the host name that the
         target server’s certificate will be matched against.

         See :py:meth:`asyncio.loop.create_connection` for more information.

         .. versionadded:: 3.9

      :param collections.abc.Mapping proxy_headers: HTTP headers to send to the proxy if the
         parameter proxy has been provided.

         .. versionadded:: 2.3

      :param trace_request_ctx: Object used to give as a kw param for each new
        :class:`TraceConfig` object instantiated,
        used to give information to the
        tracers that is only available at request time.

         .. versionadded:: 3.0

      :param int read_bufsize: Size of the read buffer (:attr:`ClientResponse.content`).
                              ``None`` by default,
                              it means that the session global value is used.

          .. versionadded:: 3.7

      :param bool auto_decompress: Automatically decompress response body.
         Overrides :attr:`ClientSession.auto_decompress`.
         May be used to enable/disable auto decompression on a per-request basis.

      :param int max_line_size: Maximum allowed size of lines in responses.

      :param int max_field_size: Maximum allowed size of header fields in responses.

      :return ClientResponse: a :class:`client response <ClientResponse>`
         object.

   .. method:: get(url, *, allow_redirects=True, **kwargs)
      :async:

      Perform a ``GET`` request. Returns an async context manager.

      In order to modify inner
      :meth:`request<aiohttp.ClientSession.request>`
      parameters, provide `kwargs`.

      :param url: Request URL, :class:`str` or :class:`~yarl.URL`

      :param bool allow_redirects: If set to ``False``, do not follow redirects.
                                   ``True`` by default (optional).

      :return ClientResponse: a :class:`client response
                              <ClientResponse>` object.

   .. method:: post(url, *, data=None, **kwargs)
      :async:

      Perform a ``POST`` request. Returns an async context manager.

      In order to modify inner
      :meth:`request<aiohttp.ClientSession.request>`
      parameters, provide `kwargs`.


      :param url: Request URL, :class:`str` or :class:`~yarl.URL`

      :param data: Data to send in the body of the request; see
                   :meth:`request<aiohttp.ClientSession.request>`
                   for details (optional)

      :return ClientResponse: a :class:`client response
                              <ClientResponse>` object.

   .. method:: put(url, *, data=None, **kwargs)
      :async:

      Perform a ``PUT`` request. Returns an async context manager.

      In order to modify inner
      :meth:`request<aiohttp.ClientSession.request>`
      parameters, provide `kwargs`.


      :param url: Request URL, :class:`str` or :class:`~yarl.URL`

      :param data: Data to send in the body of the request; see
                   :meth:`request<aiohttp.ClientSession.request>`
                   for details (optional)

      :return ClientResponse: a :class:`client response
                              <ClientResponse>` object.

   .. method:: delete(url, **kwargs)
      :async:

      Perform a ``DELETE`` request. Returns an async context manager.

      In order to modify inner
      :meth:`request<aiohttp.ClientSession.request>`
      parameters, provide `kwargs`.

      :param url: Request URL, :class:`str` or :class:`~yarl.URL`

      :return ClientResponse: a :class:`client response
                              <ClientResponse>` object.

   .. method:: head(url, *, allow_redirects=False, **kwargs)
      :async:

      Perform a ``HEAD`` request. Returns an async context manager.

      In order to modify inner
      :meth:`request<aiohttp.ClientSession.request>`
      parameters, provide `kwargs`.

      :param url: Request URL, :class:`str` or :class:`~yarl.URL`

      :param bool allow_redirects: If set to ``False``, do not follow redirects.
                                   ``False`` by default (optional).

      :return ClientResponse: a :class:`client response
                              <ClientResponse>` object.

   .. method:: options(url, *, allow_redirects=True, **kwargs)
      :async:

      Perform an ``OPTIONS`` request. Returns an async context manager.

      In order to modify inner
      :meth:`request<aiohttp.ClientSession.request>`
      parameters, provide `kwargs`.


      :param url: Request URL, :class:`str` or :class:`~yarl.URL`

      :param bool allow_redirects: If set to ``False``, do not follow redirects.
                                   ``True`` by default (optional).

      :return ClientResponse: a :class:`client response
                              <ClientResponse>` object.

   .. method:: patch(url, *, data=None, **kwargs)
      :async:

      Perform a ``PATCH`` request. Returns an async context manager.

      In order to modify inner
      :meth:`request<aiohttp.ClientSession.request>`
      parameters, provide `kwargs`.

      :param url: Request URL, :class:`str` or :class:`~yarl.URL`

      :param data: Data to send in the body of the request; see
                   :meth:`request<aiohttp.ClientSession.request>`
                   for details (optional)

      :return ClientResponse: a :class:`client response
                              <ClientResponse>` object.

   .. method:: ws_connect(url, *, method='GET', \
                            protocols=(), \
                            timeout=sentinel,\
                            auth=None,\
                            autoclose=True,\
                            autoping=True,\
                            heartbeat=None,\
                            origin=None, \
                            params=None, \
                            headers=None, \
                            proxy=None, proxy_auth=None, ssl=True, \
                            verify_ssl=None, fingerprint=None, \
                            ssl_context=None, proxy_headers=None, \
                            compress=0, max_msg_size=4194304)
      :async:

      Create a websocket connection. Returns a
      :class:`ClientWebSocketResponse` async context manager object.

      :param url: Websocket server url, :class:`~yarl.URL` or :class:`str` that
                  will be encoded with :class:`~yarl.URL` (see :class:`~yarl.URL`
                  to skip encoding).

      :param tuple protocols: Websocket protocols

      :param timeout: a :class:`ClientWSTimeout` timeout for websocket.
                      By default, the value
                      `ClientWSTimeout(ws_receive=None, ws_close=10.0)` is used
                      (``10.0`` seconds for the websocket to close).
                      ``None`` means no timeout will be used.

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

      :param params: Mapping, iterable of tuple of *key*/*value* pairs or
                     string to be sent as parameters in the query
                     string of the new request. Ignored for subsequent
                     redirected requests (optional)

                     Allowed values are:

                     - :class:`collections.abc.Mapping` e.g. :class:`dict`,
                       :class:`multidict.MultiDict` or
                       :class:`multidict.MultiDictProxy`
                     - :class:`collections.abc.Iterable` e.g. :class:`tuple` or
                       :class:`list`
                     - :class:`str` with preferably url-encoded content
                       (**Warning:** content will not be encoded by *aiohttp*)

      :param dict headers: HTTP Headers to send with
                           the request (optional)

      :param str proxy: Proxy URL, :class:`str` or :class:`~yarl.URL` (optional)

      :param aiohttp.BasicAuth proxy_auth: an object that represents proxy HTTP
                                           Basic Authorization (optional)

      :param ssl: SSL validation mode. ``True`` for default SSL check
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
         <https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning>`_.

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


   .. method:: close()
      :async:

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


.. function:: request(method, url, *, params=None, data=None, \
                        json=None,\
                        headers=None, cookies=None, auth=None, \
                        allow_redirects=True, max_redirects=10, \
                        encoding='utf-8', \
                        version=HttpVersion(major=1, minor=1), \
                        compress=None, chunked=None, expect100=False, raise_for_status=False, \
                        read_bufsize=None, \
                        connector=None, loop=None,\
                        read_until_eof=True, timeout=sentinel)
   :async:

   Asynchronous context manager for performing an asynchronous HTTP
   request. Returns a :class:`ClientResponse` response object. Use as
   an async context manager.

   :param str method: HTTP method

   :param url: Request URL, :class:`~yarl.URL` or :class:`str` that will
               be encoded with :class:`~yarl.URL` (see :class:`~yarl.URL`
               to skip encoding).

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
                                 :meth:`ClientResponse.raise_for_status`
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
        total timeout, 30 seconds socket connect timeout by default.

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
                     ``0`` the connector has no limit (default: 100).

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

      If *limit_per_host* is ``0`` the connector has no limit per host.

      Read-only property.

   .. method:: close()
      :async:

      Close all opened connections.

   .. method:: connect(request)
      :async:

      Get a free connection from pool or create new one if connection
      is absent in the pool.

      The call may be paused if :attr:`limit` is exhausted until used
      connections returns to pool.

      :param aiohttp.ClientRequest request: request object
                                                   which is connection
                                                   initiator.

      :return: :class:`Connection` object.

   .. method:: _create_connection(req)
      :async:

      Abstract method for actual connection establishing, should be
      overridden in subclasses.


.. class:: TCPConnector(*, ssl=True, verify_ssl=True, fingerprint=None, \
                 use_dns_cache=True, ttl_dns_cache=10, \
                 family=0, ssl_context=None, local_addr=None, \
                 resolver=None, keepalive_timeout=sentinel, \
                 force_close=False, limit=100, limit_per_host=0, \
                 enable_cleanup_closed=False, timeout_ceil_threshold=5, \
                 happy_eyeballs_delay=0.25, interleave=None, loop=None)

   Connector for working with *HTTP* and *HTTPS* via *TCP* sockets.

   The most common transport. When you don't know what connector type
   to use, use a :class:`TCPConnector` instance.

   :class:`TCPConnector` inherits from :class:`BaseConnector`.

   Constructor accepts all parameters suitable for
   :class:`BaseConnector` plus several TCP-specific ones:

      :param ssl: SSL validation mode. ``True`` for default SSL check
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
      <https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning>`_.

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
                     ``0`` the connector has no limit (default: 100).

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
                      For *IPv4* only use :data:`socket.AF_INET`,
                      for  *IPv6* only -- :data:`socket.AF_INET6`.

                      *family* is ``0`` by default, that means both
                      IPv4 and IPv6 are accepted. To specify only
                      concrete version please pass
                      :data:`socket.AF_INET` or
                      :data:`socket.AF_INET6` explicitly.

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

   :param float happy_eyeballs_delay: The amount of time in seconds to wait for a
      connection attempt to complete, before starting the next attempt in parallel.
      This is the “Connection Attempt Delay” as defined in RFC 8305. To disable
      Happy Eyeballs, set this to ``None``. The default value recommended by the
      RFC is 0.25 (250 milliseconds).

        .. versionadded:: 3.10

   :param int interleave: controls address reordering when a host name resolves
      to multiple IP addresses. If ``0`` or unspecified, no reordering is done, and
      addresses are tried in the order returned by the resolver. If a positive
      integer is specified, the addresses are interleaved by address family, and
      the given integer is interpreted as “First Address Family Count” as defined
      in RFC 8305. The default is ``0`` if happy_eyeballs_delay is not specified, and
      ``1`` if it is.

        .. versionadded:: 3.10

   .. attribute:: family

      *TCP* socket family e.g. :data:`socket.AF_INET` or
      :data:`socket.AF_INET6`

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

   Client response returned by :meth:`aiohttp.ClientSession.request` and family.

   User never creates the instance of ClientResponse class but gets it
   from API calls.

   :class:`ClientResponse` supports async context manager protocol, e.g.::

       resp = await client_session.get(url)
       async with resp:
           assert resp.status == 200

   After exiting from ``async with`` block response object will be
   *released* (see :meth:`release` method).

   .. attribute:: version

      Response's version, :class:`~aiohttp.protocol.HttpVersion` instance.

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
      transfer encoding related errors like malformed chunked
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

   .. method:: read()
      :async:

      Read the whole response's body as :class:`bytes`.

      Close underlying connection if data reading gets an error,
      release connection otherwise.

      Raise an :exc:`aiohttp.ClientResponseError` if the data can't
      be read.

      :return bytes: read *BODY*.

      .. seealso:: :meth:`close`, :meth:`release`.

   .. method:: release()

      It is not required to call `release` on the response
      object. When the client fully receives the payload, the
      underlying connection automatically returns back to pool. If the
      payload is not fully read, the connection is closed

   .. method:: raise_for_status()

      Raise an :exc:`aiohttp.ClientResponseError` if the response
      status is 400 or higher.

      Do nothing for success responses (less than 400).

   .. method:: text(encoding=None)
      :async:

      Read response's body and return decoded :class:`str` using
      specified *encoding* parameter.

      If *encoding* is ``None`` content encoding is determined from the
      Content-Type header, or using the ``fallback_charset_resolver`` function.

      Close underlying connection if data reading gets an error,
      release connection otherwise.

      :param str encoding: text encoding used for *BODY* decoding, or
                           ``None`` for encoding autodetection
                           (default).


      :raises: :exc:`UnicodeDecodeError` if decoding fails. See also
               :meth:`get_encoding`.

      :return str: decoded *BODY*

   .. method:: json(*, encoding=None, loads=json.loads, \
                      content_type='application/json')
      :async:

      Read response's body as *JSON*, return :class:`dict` using
      specified *encoding* and *loader*. If data is not still available
      a ``read`` call will be done.

      If response's `content-type` does not match `content_type` parameter
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

      :param collections.abc.Callable loads: :term:`callable` used for loading *JSON*
                             data, :func:`json.loads` by default.

      :param str content_type: specify response's content-type, if content type
         does not match raise :exc:`aiohttp.ClientResponseError`.
         To disable `content-type` check, pass ``None`` as value.
         (default: `application/json`).

      :return: *BODY* as *JSON* data parsed by *loads* parameter or
               ``None`` if *BODY* is empty or contains white-spaces only.

   .. attribute:: request_info

       A namedtuple with request URL and headers from :class:`~aiohttp.ClientRequest`
       object, :class:`aiohttp.RequestInfo` instance.

   .. method:: get_encoding()

      Retrieve content encoding using ``charset`` info in ``Content-Type`` HTTP header.
      If no charset is present or the charset is not understood by Python, the
      ``fallback_charset_resolver`` function associated with the ``ClientSession`` is called.

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

      Reads optional extra information from the connection's transport.
      If no value associated with ``name`` is found, ``default`` is returned.

      See :meth:`asyncio.BaseTransport.get_extra_info`

      :param str name: The key to look up in the transport extra information.

      :param default: Default value to be used when no value for ``name`` is
                      found (default is ``None``).

   .. method:: exception()

      Returns exception if any occurs or returns None.

   .. method:: ping(message=b'')
      :async:

      Send :const:`~aiohttp.WSMsgType.PING` to peer.

      :param message: optional payload of *ping* message,
                      :class:`str` (converted to *UTF-8* encoded bytes)
                      or :class:`bytes`.

      .. versionchanged:: 3.0

         The method is converted into :term:`coroutine`

   .. method:: pong(message=b'')
      :async:

      Send :const:`~aiohttp.WSMsgType.PONG` to peer.

      :param message: optional payload of *pong* message,
                      :class:`str` (converted to *UTF-8* encoded bytes)
                      or :class:`bytes`.

      .. versionchanged:: 3.0

         The method is converted into :term:`coroutine`

   .. method:: send_str(data, compress=None)
      :async:

      Send *data* to peer as :const:`~aiohttp.WSMsgType.TEXT` message.

      :param str data: data to send.

      :param int compress: sets specific level of compression for
                           single message,
                           ``None`` for not overriding per-socket setting.

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

      :raise TypeError: if value returned by ``dumps(data)`` is not
                        :class:`str`

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

   .. method:: close(*, code=WSCloseCode.OK, message=b'')
      :async:

      A :ref:`coroutine<coroutine>` that initiates closing handshake by sending
      :const:`~aiohttp.WSMsgType.CLOSE` message. It waits for
      close response from server. To add a timeout to `close()` call
      just wrap the call with `asyncio.wait()` or `asyncio.wait_for()`.

      :param int code: closing code. See also :class:`~aiohttp.WSCloseCode`.

      :param message: optional payload of *close* message,
         :class:`str` (converted to *UTF-8* encoded bytes) or :class:`bytes`.

   .. method:: receive()
      :async:

      A :ref:`coroutine<coroutine>` that waits upcoming *data*
      message from peer and returns it.

      The coroutine implicitly handles
      :const:`~aiohttp.WSMsgType.PING`,
      :const:`~aiohttp.WSMsgType.PONG` and
      :const:`~aiohttp.WSMsgType.CLOSE` without returning the
      message.

      It process *ping-pong game* and performs *closing handshake* internally.

      :return: :class:`~aiohttp.WSMessage`

   .. method:: receive_str()
      :async:

      A :ref:`coroutine<coroutine>` that calls :meth:`receive` but
      also asserts the message type is
      :const:`~aiohttp.WSMsgType.TEXT`.

      :return str: peer's message content.

      :raise TypeError: if message is :const:`~aiohttp.WSMsgType.BINARY`.

   .. method:: receive_bytes()
      :async:

      A :ref:`coroutine<coroutine>` that calls :meth:`receive` but
      also asserts the message type is
      :const:`~aiohttp.WSMsgType.BINARY`.

      :return bytes: peer's message content.

      :raise TypeError: if message is :const:`~aiohttp.WSMsgType.TEXT`.

   .. method:: receive_json(*, loads=json.loads)
      :async:

      A :ref:`coroutine<coroutine>` that calls :meth:`receive_str` and loads
      the JSON string to a Python dict.

      :param collections.abc.Callable loads: any :term:`callable` that accepts
                              :class:`str` and returns :class:`dict`
                              with parsed JSON (:func:`json.loads` by
                              default).

      :return dict: loaded JSON content

      :raise TypeError: if message is :const:`~aiohttp.WSMsgType.BINARY`.
      :raise ValueError: if message is not valid JSON.

   The class supports ``async for`` statement for iterating over
   incoming messages::

      async for msg in ws:
        print(msg.data)

    .. warning::

        When using ``async for msg in ws:``, messages of type
        :attr:`~aiohttp.WSMsgType.CLOSE`, :attr:`~aiohttp.WSMsgType.CLOSED`,
        and :attr:`~aiohttp.WSMsgType.CLOSING` are swallowed. If you need to
        handle these messages, you should use the
        :meth:`~aiohttp.web.WebSocketResponse.receive` method instead.


Utilities
---------


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


.. class:: ClientWSTimeout(*, ws_receive=None, ws_close=None)

   A data class for websocket client timeout settings.

   .. attribute:: ws_receive

      A timeout for websocket to receive a complete message.

      :class:`float`, ``None`` by default.

   .. attribute:: ws_close

      A timeout for the websocket to close.

      :class:`float`, ``10.0`` by default.


   .. note::

      Timeouts of 5 seconds or more are rounded for scheduling on the next
      second boundary (an absolute time where microseconds part is zero) for the
      sake of performance.

      E.g., assume a timeout is ``10``, absolute time when timeout should expire
      is ``loop.time() + 5``, and it points to ``12345.67 + 10`` which is equal
      to ``12355.67``.

      The absolute time for the timeout cancellation is ``12356``.

      It leads to grouping all close scheduled timeout expirations to exactly
      the same time to reduce amount of loop wakeups.

      .. versionchanged:: 3.7

         Rounding to the next seconds boundary is disabled for timeouts smaller
         than 5 seconds for the sake of easy debugging.

         In turn, tiny timeouts can lead to significant performance degradation
         on production environment.


.. class:: ETag(name, is_weak=False)

   Represents `ETag` identifier.

   .. attribute:: value

      Value of corresponding etag without quotes.

   .. attribute:: is_weak

      Flag indicates that etag is weak (has `W/` prefix).

   .. versionadded:: 3.8


.. class:: ContentDisposition

    A data class to represent the Content-Disposition header,
    available as :attr:`ClientResponse.content_disposition` attribute.

    .. attribute:: type

    A :class:`str` instance. Value of Content-Disposition header
    itself, e.g. ``attachment``.

    .. attribute:: filename

    A :class:`str` instance. Content filename extracted from
    parameters. May be ``None``.

    .. attribute:: parameters

    Read-only mapping contains all parameters.


.. class:: RequestInfo()

   A data class with request URL and headers from :class:`~aiohttp.ClientRequest`
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


.. class:: BasicAuth(login, password='', encoding='latin1')

   HTTP basic authentication helper.

   :param str login: login
   :param str password: password
   :param str encoding: encoding (``'latin1'`` by default)


   Should be used for specifying authorization data in client API,
   e.g. *auth* parameter for :meth:`ClientSession.request() <aiohttp.ClientSession.request>`.


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


.. class:: CookieJar(*, unsafe=False, quote_cookie=True, treat_as_secure_origin = [])

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
   :class:`aiohttp.abc.AbstractCookieJar` interfaces.

   Implements cookie storage adhering to RFC 6265.

   :param bool unsafe: (optional) Whether to accept cookies from IPs.

   :param bool quote_cookie: (optional) Whether to quote cookies according to
                             :rfc:`2109`.  Some backend systems
                             (not compatible with RFC mentioned above)
                             does not support quoted cookies.

      .. versionadded:: 3.7

   :param treat_as_secure_origin: (optional) Mark origins as secure
                                  for cookies marked as Secured. Possible types are

                                  Possible types are:

                                  - :class:`tuple` or :class:`list` of
                                    :class:`str` or :class:`yarl.URL`
                                  - :class:`str`
                                  - :class:`yarl.URL`

      .. versionadded:: 3.8

   .. method:: update_cookies(cookies, response_url=None)

      Update cookies returned by server in ``Set-Cookie`` header.

      :param cookies: a :class:`collections.abc.Mapping`
         (e.g. :class:`dict`, :class:`~http.cookies.SimpleCookie`) or
         *iterable* of *pairs* with cookies returned by server's
         response.

      :param ~yarl.URL response_url: URL of response, ``None`` for *shared
         cookies*.  Regular cookies are coupled with server's URL and
         are sent only to this server, shared ones are sent in every
         client request.

   .. method:: filter_cookies(request_url)

      Return jar's cookies acceptable for URL and available in
      ``Cookie`` header for sending client requests for given URL.

      :param ~yarl.URL response_url: request's URL for which cookies are asked.

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

   .. method:: clear(predicate=None)

      Removes all cookies from the jar if the predicate is ``None``. Otherwise remove only those :class:`~http.cookies.Morsel` that ``predicate(morsel)`` returns ``True``.

      :param predicate: callable that gets :class:`~http.cookies.Morsel` as a parameter and returns ``True`` if this :class:`~http.cookies.Morsel` must be deleted from the jar.

          .. versionadded:: 4.0

   .. method:: clear_domain(domain)

      Remove all cookies from the jar that belongs to the specified domain or its subdomains.

      :param str domain: domain for which cookies must be deleted from the jar.

      .. versionadded:: 4.0


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

:class:`FormData` instances are callable and return a :class:`aiohttp.payload.Payload`
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
                    - :class:`bytes`, :class:`bytearray`, or :class:`memoryview`
                    - :class:`io.IOBase`, e.g. a file-like object

      :param str content_type: The field's content-type header (optional)

      :param str filename: The field's filename (optional)

                           If this is not set and ``value`` is a :class:`bytes`, :class:`bytearray`,
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

    .. attribute:: description

      Invalid URL description, :class:`str` instance or :data:`None`.

.. exception:: InvalidUrlClientError

   Base class for all errors related to client url.

   Derived from :exc:`InvalidURL`

.. exception:: RedirectClientError

   Base class for all errors related to client redirects.

   Derived from :exc:`ClientError`

.. exception:: NonHttpUrlClientError

   Base class for all errors related to non http client urls.

   Derived from :exc:`ClientError`

.. exception:: InvalidUrlRedirectClientError

   Redirect URL is malformed, e.g. it does not contain host part.

   Derived from :exc:`InvalidUrlClientError` and :exc:`RedirectClientError`

.. exception:: NonHttpUrlRedirectClientError

   Redirect URL does not contain http schema.

   Derived from :exc:`RedirectClientError` and :exc:`NonHttpUrlClientError`

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


.. class:: WSServerHandshakeError

   Web socket server response error.

   Derived from :exc:`ClientResponseError`

Connection errors
^^^^^^^^^^^^^^^^^

.. class:: ClientConnectionError

   These exceptions related to low-level connection problems.

   Derived from :exc:`ClientError`

.. class:: ClientConnectionResetError

   Derived from :exc:`ClientConnectionError` and :exc:`ConnectionResetError`

.. class:: ClientOSError

   Subset of connection errors that are initiated by an :exc:`OSError`
   exception.

   Derived from :exc:`ClientConnectionError` and :exc:`OSError`

.. class:: ClientConnectorError

   Connector related exceptions.

   Derived from :exc:`ClientOSError`

.. class:: ClientConnectorDNSError

   DNS resolution error.

   Derived from :exc:`ClientConnectorError`

.. class:: ClientProxyConnectionError

   Derived from :exc:`ClientConnectorError`

.. class:: ClientSSLError

   Derived from :exc:`ClientConnectorError`

.. class:: ClientConnectorSSLError

   Response ssl error.

   Derived from :exc:`ClientSSLError` and :exc:`ssl.SSLError`

.. class:: ClientConnectorCertificateError

   Response certificate error.

   Derived from :exc:`ClientSSLError` and :exc:`ssl.CertificateError`

.. class:: UnixClientConnectorError

   Derived from :exc:`ClientConnectorError`

.. class:: ServerConnectionError

   Derived from :exc:`ClientConnectionError`

.. class:: ServerDisconnectedError

   Server disconnected.

   Derived from :exc:`~aiohttp.ServerConnectionError`

   .. attribute:: message

      Partially parsed HTTP message (optional).


.. class:: ServerFingerprintMismatch

   Server fingerprint mismatch.

   Derived from :exc:`ServerConnectionError`

.. class:: ServerTimeoutError

   Server operation timeout: read timeout, etc.

   To catch all timeouts, including the ``total`` timeout, use
   :exc:`asyncio.TimeoutError`.

   Derived from :exc:`ServerConnectionError` and :exc:`asyncio.TimeoutError`

.. class:: ConnectionTimeoutError

   Connection timeout on ``connect`` and ``sock_connect`` timeouts.

   Derived from :exc:`ServerTimeoutError`

.. class:: SocketTimeoutError

   Reading from socket timeout on ``sock_read`` timeout.

   Derived from :exc:`ServerTimeoutError`

Hierarchy of exceptions
^^^^^^^^^^^^^^^^^^^^^^^

* :exc:`ClientError`

  * :exc:`ClientConnectionError`

    * :exc:`ClientConnectionResetError`

    * :exc:`ClientOSError`

      * :exc:`ClientConnectorError`

        * :exc:`ClientProxyConnectionError`

        * :exc:`ClientConnectorDNSError`

        * :exc:`ClientSSLError`

          * :exc:`ClientConnectorCertificateError`

          * :exc:`ClientConnectorSSLError`

        * :exc:`UnixClientConnectorError`

    * :exc:`ServerConnectionError`

      * :exc:`ServerDisconnectedError`

      * :exc:`ServerFingerprintMismatch`

      * :exc:`ServerTimeoutError`

        * :exc:`ConnectionTimeoutError`

        * :exc:`SocketTimeoutError`

  * :exc:`ClientPayloadError`

  * :exc:`ClientResponseError`

    * :exc:`~aiohttp.ClientHttpProxyError`

    * :exc:`ContentTypeError`

    * :exc:`TooManyRedirects`

    * :exc:`WSServerHandshakeError`

  * :exc:`InvalidURL`

    * :exc:`InvalidUrlClientError`

      * :exc:`InvalidUrlRedirectClientError`

  * :exc:`NonHttpUrlClientError`

    * :exc:`NonHttpUrlRedirectClientError`

  * :exc:`RedirectClientError`

    * :exc:`InvalidUrlRedirectClientError`

    * :exc:`NonHttpUrlRedirectClientError`
