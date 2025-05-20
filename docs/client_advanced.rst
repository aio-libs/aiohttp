.. _aiohttp-client-advanced:

Advanced Client Usage
=====================

.. currentmodule:: aiohttp

.. _aiohttp-client-session:

Client Session
--------------

:class:`ClientSession` is the heart and the main entry point for all
client API operations.

Create the session first, use the instance for performing HTTP
requests and initiating WebSocket connections.

The session contains a cookie storage and connection pool, thus
cookies and connections are shared between HTTP requests sent by the
same session.

Custom Request Headers
----------------------

If you need to add HTTP headers to a request, pass them in a
:class:`dict` to the *headers* parameter.

For example, if you want to specify the content-type directly::

    url = 'http://example.com/image'
    payload = b'GIF89a\x01\x00\x01\x00\x00\xff\x00,\x00\x00'
              b'\x00\x00\x01\x00\x01\x00\x00\x02\x00;'
    headers = {'content-type': 'image/gif'}

    await session.post(url,
                       data=payload,
                       headers=headers)

You also can set default headers for all session requests::

    headers={"Authorization": "Basic bG9naW46cGFzcw=="}
    async with aiohttp.ClientSession(headers=headers) as session:
        async with session.get("http://httpbin.org/headers") as r:
            json_body = await r.json()
            assert json_body['headers']['Authorization'] == \
                'Basic bG9naW46cGFzcw=='

Typical use case is sending JSON body. You can specify content type
directly as shown above, but it is more convenient to use special keyword
``json``::

    await session.post(url, json={'example': 'text'})

For *text/plain* ::

    await session.post(url, data='Привет, Мир!')

Authentication
--------------

Instead of setting the ``Authorization`` header directly,
:class:`ClientSession` and individual request methods provide an ``auth``
argument. An instance of :class:`BasicAuth` can be passed in like this::

    auth = BasicAuth(login="...", password="...")
    async with ClientSession(auth=auth) as session:
        ...

For HTTP digest authentication, use the :class:`DigestAuthMiddleware` client middleware::

    from aiohttp import ClientSession, DigestAuthMiddleware

    # Create the middleware with your credentials
    digest_auth = DigestAuthMiddleware(login="user", password="password")

    # Pass it to the ClientSession as a tuple
    async with ClientSession(middlewares=(digest_auth,)) as session:
        # The middleware will automatically handle auth challenges
        async with session.get("https://example.com/protected") as resp:
            print(await resp.text())

The :class:`DigestAuthMiddleware` implements HTTP Digest Authentication according to RFC 7616,
providing a more secure alternative to Basic Authentication. It supports all
standard hash algorithms including MD5, SHA, SHA-256, SHA-512 and their session
variants, as well as both 'auth' and 'auth-int' quality of protection (qop) options.
The middleware automatically handles the authentication flow by intercepting 401 responses
and retrying with proper credentials.

Note that if the request is redirected and the redirect URL contains
credentials, those credentials will supersede any previously set credentials.
In other words, if ``http://user@example.com`` redirects to
``http://other_user@example.com``, the second request will be authenticated
as ``other_user``. Providing both the ``auth`` parameter and authentication in
the *initial* URL will result in a :exc:`ValueError`.

For other authentication flows, the ``Authorization`` header can be set
directly::

    headers = {"Authorization": "Bearer eyJh...0M30"}
    async with ClientSession(headers=headers) as session:
        ...

The authentication header for a session may be updated as and when required.
For example::

    session.headers["Authorization"] = "Bearer eyJh...1OH0"

Note that a *copy* of the headers dictionary is set as an attribute when
creating a :class:`ClientSession` instance (as a :class:`multidict.CIMultiDict`
object). Updating the original dictionary does not have any effect.

In cases where the authentication header value expires periodically, an
:mod:`asyncio` task may be used to update the session's default headers in the
background.

.. note::
   ``Authorization`` header will be removed if you get redirected
   to a different host or protocol.

.. _aiohttp-client-middleware:

Client Middleware
-----------------

The client supports middleware to intercept requests and responses. This can be
useful for authentication, logging, request/response modification, and retries.

Creating Middleware
^^^^^^^^^^^^^^^^^^^

To create a middleware, define an async function (or callable class) that accepts a request
and a handler function, and returns a response. Middleware must follow the
:type:`ClientMiddlewareType` signature (see :ref:`aiohttp-client-reference` for details).

Using Middleware
^^^^^^^^^^^^^^^^

You can apply middleware to a client session or to individual requests::

    # Apply to all requests in a session
    async with ClientSession(middlewares=(my_middleware,)) as session:
        resp = await session.get('http://example.com')

    # Apply to a specific request
    async with ClientSession() as session:
        resp = await session.get('http://example.com', middlewares=(my_middleware,))

Middleware Chaining
^^^^^^^^^^^^^^^^^^^

Multiple middlewares are applied in the order they are listed::

    # Middlewares are applied in order: logging -> auth -> request
    async with ClientSession(middlewares=(logging_middleware, auth_middleware)) as session:
        resp = await session.get('http://example.com')

A key aspect to understand about the flat middleware structure is that the execution flow follows this pattern:

1. The first middleware in the list is called first and executes its code before calling the handler
2. The handler is the next middleware in the chain (or the actual request handler if there are no more middleware)
3. When the handler returns a response, execution continues in the first middleware after the handler call
4. This creates a nested "onion-like" pattern for execution

For example, with ``middlewares=(middleware1, middleware2)``, the execution order would be:

1. Enter ``middleware1`` (pre-request code)
2. Enter ``middleware2`` (pre-request code)
3. Execute the actual request handler
4. Exit ``middleware2`` (post-response code)
5. Exit ``middleware1`` (post-response code)

This flat structure means that middleware is applied on each retry attempt inside the client's retry loop, not just once before all retries. This allows middleware to modify requests freshly on each retry attempt.

.. note::

   Client middleware is a powerful feature but should be used judiciously.
   Each middleware adds overhead to request processing. For simple use cases
   like adding static headers, you can often use request parameters
   (e.g., ``headers``) or session configuration instead.

Common Middleware Patterns
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. _client-middleware-retry:

Authentication and Retry
""""""""""""""""""""""""

There are two recommended approaches for implementing retry logic:

1. **For Loop Pattern (Simple Cases)**

   Use a bounded ``for`` loop when the number of retry attempts is known and fixed::

       import hashlib
       from aiohttp import ClientSession, ClientRequest, ClientResponse, ClientHandlerType

       async def auth_retry_middleware(
           request: ClientRequest,
           handler: ClientHandlerType
       ) -> ClientResponse:
           # Try up to 3 authentication methods
           for attempt in range(3):
               if attempt == 0:
                   # First attempt: use API key
                   request.headers["X-API-Key"] = "my-api-key"
               elif attempt == 1:
                   # Second attempt: use Bearer token
                   request.headers["Authorization"] = "Bearer fallback-token"
               else:
                   # Third attempt: use hash-based signature
                   secret_key = "my-secret-key"
                   url_path = str(request.url.path)
                   signature = hashlib.sha256(f"{url_path}{secret_key}".encode()).hexdigest()
                   request.headers["X-Signature"] = signature

               # Send the request
               response = await handler(request)

               # If successful or not an auth error, return immediately
               if response.status != 401:
                   return response

           # Return the last response if all retries are exhausted
           return response

2. **While Loop Pattern (Complex Cases)**

   For more complex scenarios, use a ``while`` loop with strict exit conditions::

       import logging

       _LOGGER = logging.getLogger(__name__)

       class RetryMiddleware:
           def __init__(self, max_retries: int = 3):
               self.max_retries = max_retries

           async def __call__(
               self,
               request: ClientRequest,
               handler: ClientHandlerType
           ) -> ClientResponse:
               retry_count = 0

               # Always have clear exit conditions
               while retry_count <= self.max_retries:
                   # Send the request
                   response = await handler(request)

                   # Exit conditions
                   if 200 <= response.status < 400 or retry_count >= self.max_retries:
                       return response

                   # Retry logic for different status codes
                   if response.status in (401, 429, 500, 502, 503, 504):
                       retry_count += 1
                       _LOGGER.debug(f"Retrying request (attempt {retry_count}/{self.max_retries})")
                       continue

                   # For any other status code, don't retry
                   return response

               # Safety return (should never reach here)
               return response

Request Modification
""""""""""""""""""""

Modify request properties based on request content::

    async def content_type_middleware(
        request: ClientRequest,
        handler: ClientHandlerType
    ) -> ClientResponse:
        # Examine URL path to determine content-type
        if request.url.path.endswith('.json'):
            request.headers['Content-Type'] = 'application/json'
        elif request.url.path.endswith('.xml'):
            request.headers['Content-Type'] = 'application/xml'

        # Add custom headers based on HTTP method
        if request.method == 'POST':
            request.headers['X-Request-ID'] = f"post-{id(request)}"

        return await handler(request)

Avoiding Infinite Recursion
^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. warning::

   Using the same session from within middleware can cause infinite recursion if
   the middleware makes HTTP requests using the same session that has the middleware
   applied. This is especially risky in token refresh middleware or retry logic.

   When implementing retry or refresh logic, always use bounded loops
   (e.g., ``for _ in range(2):`` instead of ``while True:``) to prevent infinite recursion.

To avoid recursion when making requests inside middleware, use one of these approaches:

**Option 1:** Disable middleware for internal requests::

    async def log_middleware(
        request: ClientRequest,
        handler: ClientHandlerType
    ) -> ClientResponse:
        async with request.session.post(
            "https://logapi.example/log",
            json={"url": str(request.url)},
            middlewares=()  # This prevents infinite recursion
        ) as resp:
            pass

        return await handler(request)

**Option 2:** Check request details to avoid recursive application::

    async def log_middleware(
        request: ClientRequest,
        handler: ClientHandlerType
    ) -> ClientResponse:
        if request.url.host != "logapi.example":  # Avoid infinite recursion
            async with request.session.post(
                "https://logapi.example/log",
                json={"url": str(request.url)}
            ) as resp:
                pass

        return await handler(request)

Custom Cookies
--------------

To send your own cookies to the server, you can use the *cookies*
parameter of :class:`ClientSession` constructor::

    url = 'http://httpbin.org/cookies'
    cookies = {'cookies_are': 'working'}
    async with ClientSession(cookies=cookies) as session:
        async with session.get(url) as resp:
            assert await resp.json() == {
               "cookies": {"cookies_are": "working"}}

.. note::
   ``httpbin.org/cookies`` endpoint returns request cookies
   in JSON-encoded body.
   To access session cookies see :attr:`ClientSession.cookie_jar`.

:class:`~aiohttp.ClientSession` may be used for sharing cookies
between multiple requests::

    async with aiohttp.ClientSession() as session:
        async with session.get(
            "http://httpbin.org/cookies/set?my_cookie=my_value",
            allow_redirects=False
        ) as resp:
            assert resp.cookies["my_cookie"].value == "my_value"
        async with session.get("http://httpbin.org/cookies") as r:
            json_body = await r.json()
            assert json_body["cookies"]["my_cookie"] == "my_value"

Response Headers and Cookies
----------------------------

We can view the server's response :attr:`ClientResponse.headers` using
a :class:`~multidict.CIMultiDictProxy`::

    assert resp.headers == {
        'ACCESS-CONTROL-ALLOW-ORIGIN': '*',
        'CONTENT-TYPE': 'application/json',
        'DATE': 'Tue, 15 Jul 2014 16:49:51 GMT',
        'SERVER': 'gunicorn/18.0',
        'CONTENT-LENGTH': '331',
        'CONNECTION': 'keep-alive'}

The dictionary is special, though: it's made just for HTTP
headers. According to `RFC 7230
<http://tools.ietf.org/html/rfc7230#section-3.2>`_, HTTP Header names
are case-insensitive. It also supports multiple values for the same
key as HTTP protocol does.

So, we can access the headers using any capitalization we want::

    assert resp.headers['Content-Type'] == 'application/json'

    assert resp.headers.get('content-type') == 'application/json'

All headers are converted from binary data using UTF-8 with
``surrogateescape`` option. That works fine on most cases but
sometimes unconverted data is needed if a server uses nonstandard
encoding. While these headers are malformed from :rfc:`7230`
perspective they may be retrieved by using
:attr:`ClientResponse.raw_headers` property::

    assert resp.raw_headers == (
        (b'SERVER', b'nginx'),
        (b'DATE', b'Sat, 09 Jan 2016 20:28:40 GMT'),
        (b'CONTENT-TYPE', b'text/html; charset=utf-8'),
        (b'CONTENT-LENGTH', b'12150'),
        (b'CONNECTION', b'keep-alive'))


If a response contains some *HTTP Cookies*, you can quickly access them::

    url = 'http://example.com/some/cookie/setting/url'
    async with session.get(url) as resp:
        print(resp.cookies['example_cookie_name'])

.. note::

   Response cookies contain only values, that were in ``Set-Cookie`` headers
   of the **last** request in redirection chain. To gather cookies between all
   redirection requests please use :ref:`aiohttp.ClientSession
   <aiohttp-client-session>` object.


Redirection History
-------------------

If a request was redirected, it is possible to view previous responses using
the :attr:`~ClientResponse.history` attribute::

    resp = await session.get('http://example.com/some/redirect/')
    assert resp.status == 200
    assert resp.url = URL('http://example.com/some/other/url/')
    assert len(resp.history) == 1
    assert resp.history[0].status == 301
    assert resp.history[0].url = URL(
        'http://example.com/some/redirect/')

If no redirects occurred or ``allow_redirects`` is set to ``False``,
history will be an empty sequence.


Cookie Jar
----------

.. _aiohttp-client-cookie-safety:

Cookie Safety
^^^^^^^^^^^^^

By default :class:`~aiohttp.ClientSession` uses strict version of
:class:`aiohttp.CookieJar`. :rfc:`2109` explicitly forbids cookie
accepting from URLs with IP address instead of DNS name
(e.g. ``http://127.0.0.1:80/cookie``).

It's good but sometimes for testing we need to enable support for such
cookies. It should be done by passing ``unsafe=True`` to
:class:`aiohttp.CookieJar` constructor::


   jar = aiohttp.CookieJar(unsafe=True)
   session = aiohttp.ClientSession(cookie_jar=jar)


.. _aiohttp-client-cookie-quoting-routine:

Cookie Quoting Routine
^^^^^^^^^^^^^^^^^^^^^^

The client uses the :class:`~aiohttp.SimpleCookie` quoting routines
conform to the :rfc:`2109`, which in turn references the character definitions
from :rfc:`2068`. They provide a two-way quoting algorithm where any non-text
character is translated into a 4 character sequence: a forward-slash
followed by the three-digit octal equivalent of the character.
Any ``\`` or ``"`` is quoted with a preceding ``\`` slash.
Because of the way browsers really handle cookies (as opposed to what the RFC
says) we also encode ``,`` and ``;``.

Some backend systems does not support quoted cookies. You can skip this
quotation routine by passing ``quote_cookie=False`` to the
:class:`~aiohttp.CookieJar` constructor::

   jar = aiohttp.CookieJar(quote_cookie=False)
   session = aiohttp.ClientSession(cookie_jar=jar)


.. _aiohttp-client-dummy-cookie-jar:

Dummy Cookie Jar
^^^^^^^^^^^^^^^^

Sometimes cookie processing is not desirable. For this purpose it's
possible to pass :class:`aiohttp.DummyCookieJar` instance into client
session::

   jar = aiohttp.DummyCookieJar()
   session = aiohttp.ClientSession(cookie_jar=jar)


Uploading pre-compressed data
-----------------------------

To upload data that is already compressed before passing it to
aiohttp, call the request function with the used compression algorithm
name (usually ``deflate`` or ``gzip``) as the value of the
``Content-Encoding`` header::

    async def my_coroutine(session, headers, my_data):
        data = zlib.compress(my_data)
        headers = {'Content-Encoding': 'deflate'}
        async with session.post('http://httpbin.org/post',
                                data=data,
                                headers=headers)
            pass

Disabling content type validation for JSON responses
----------------------------------------------------

The standard explicitly restricts JSON ``Content-Type`` HTTP header to
``application/json`` or any extended form, e.g. ``application/vnd.custom-type+json``.
Unfortunately, some servers send a wrong type, like ``text/html``.

This can be worked around in two ways:

1. Pass the expected type explicitly (in this case checking will be strict, without the extended form support,
   so ``custom/xxx+type`` won't be accepted):

   ``await resp.json(content_type='custom/type')``.
2. Disable the check entirely:

   ``await resp.json(content_type=None)``.

.. _aiohttp-client-tracing:

Client Tracing
--------------

The execution flow of a specific request can be followed attaching
listeners coroutines to the signals provided by the
:class:`TraceConfig` instance, this instance will be used as a
parameter for the :class:`ClientSession` constructor having as a
result a client that triggers the different signals supported by the
:class:`TraceConfig`. By default any instance of
:class:`ClientSession` class comes with the signals ability
disabled. The following snippet shows how the start and the end
signals of a request flow can be followed::

    async def on_request_start(
            session, trace_config_ctx, params):
        print("Starting request")

    async def on_request_end(session, trace_config_ctx, params):
        print("Ending request")

    trace_config = aiohttp.TraceConfig()
    trace_config.on_request_start.append(on_request_start)
    trace_config.on_request_end.append(on_request_end)
    async with aiohttp.ClientSession(
            trace_configs=[trace_config]) as client:
        client.get('http://example.com/some/redirect/')

The ``trace_configs`` is a list that can contain instances of
:class:`TraceConfig` class that allow run the signals handlers coming
from different :class:`TraceConfig` instances.  The following example
shows how two different :class:`TraceConfig` that have a different
nature are installed to perform their job in each signal handle::

    from mylib.traceconfig import AuditRequest
    from mylib.traceconfig import XRay

    async with aiohttp.ClientSession(
            trace_configs=[AuditRequest(), XRay()]) as client:
        client.get('http://example.com/some/redirect/')


All signals take as a parameters first, the :class:`ClientSession`
instance used by the specific request related to that signals and
second, a :class:`~types.SimpleNamespace` instance called
``trace_config_ctx``. The ``trace_config_ctx`` object can be used to
share the state through to the different signals that belong to the
same request and to the same :class:`TraceConfig` class, perhaps::

    async def on_request_start(
            session, trace_config_ctx, params):
        trace_config_ctx.start = asyncio.get_event_loop().time()

    async def on_request_end(session, trace_config_ctx, params):
        elapsed = asyncio.get_event_loop().time() - trace_config_ctx.start
        print("Request took {}".format(elapsed))


The ``trace_config_ctx`` param is by default a
:class:`~types.SimpleNamespace` that is initialized at the beginning of the
request flow. However, the factory used to create this object can be
overwritten using the ``trace_config_ctx_factory`` constructor param of
the :class:`TraceConfig` class.

The ``trace_request_ctx`` param can given at the beginning of the
request execution, accepted by all of the HTTP verbs,  and will be
passed as a keyword argument for the ``trace_config_ctx_factory``
factory. This param is useful to pass data that is only available at
request time, perhaps::

    async def on_request_start(
            session, trace_config_ctx, params):
        print(trace_config_ctx.trace_request_ctx)


    session.get('http://example.com/some/redirect/',
                trace_request_ctx={'foo': 'bar'})


.. seealso:: :ref:`aiohttp-client-tracing-reference` section for
             more information about the different signals supported.

Connectors
----------

To tweak or change *transport* layer of requests you can pass a custom
*connector* to :class:`~aiohttp.ClientSession` and family. For example::

    conn = aiohttp.TCPConnector()
    session = aiohttp.ClientSession(connector=conn)

.. note::

   By default *session* object takes the ownership of the connector, among
   other things closing the connections once the *session* is closed. If
   you are keen on share the same *connector* through different *session*
   instances you must give the  *connector_owner* parameter as **False**
   for each *session* instance.

.. seealso:: :ref:`aiohttp-client-reference-connectors` section for
             more information about different connector types and
             configuration options.


Limiting connection pool size
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To limit amount of simultaneously opened connections you can pass *limit*
parameter to *connector*::

    conn = aiohttp.TCPConnector(limit=30)

The example limits total amount of parallel connections to `30`.

The default is `100`.

If you explicitly want not to have limits, pass `0`. For example::

    conn = aiohttp.TCPConnector(limit=0)

To limit amount of simultaneously opened connection to the same
endpoint (``(host, port, is_ssl)`` triple) you can pass *limit_per_host*
parameter to *connector*::

    conn = aiohttp.TCPConnector(limit_per_host=30)

The example limits amount of parallel connections to the same to `30`.

The default is `0` (no limit on per host bases).

Tuning the DNS cache
^^^^^^^^^^^^^^^^^^^^

By default :class:`~aiohttp.TCPConnector` comes with the DNS cache
table enabled, and resolutions will be cached by default for `10` seconds.
This behavior can be changed either to change of the TTL for a resolution,
as can be seen in the following example::

    conn = aiohttp.TCPConnector(ttl_dns_cache=300)

or disabling the use of the DNS cache table, meaning that all requests will
end up making a DNS resolution, as the following example shows::

    conn = aiohttp.TCPConnector(use_dns_cache=False)


Resolving using custom nameservers
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In order to specify the nameservers to when resolving the hostnames,
:term:`aiodns` is required::

    from aiohttp.resolver import AsyncResolver

    resolver = AsyncResolver(nameservers=["8.8.8.8", "8.8.4.4"])
    conn = aiohttp.TCPConnector(resolver=resolver)


Unix domain sockets
^^^^^^^^^^^^^^^^^^^

If your HTTP server uses UNIX domain sockets you can use
:class:`~aiohttp.UnixConnector`::

  conn = aiohttp.UnixConnector(path='/path/to/socket')
  session = aiohttp.ClientSession(connector=conn)


Custom socket creation
^^^^^^^^^^^^^^^^^^^^^^

If the default socket is insufficient for your use case, pass an optional
``socket_factory`` to the :class:`~aiohttp.TCPConnector`, which implements
:class:`SocketFactoryType`. This will be used to create all sockets for the
lifetime of the class object. For example, we may want to change the
conditions under which we consider a connection dead. The following would
make all sockets respect 9*7200 = 18 hours::

  import socket

  def socket_factory(addr_info):
      family, type_, proto, _, _, _ = addr_info
      sock = socket.socket(family=family, type=type_, proto=proto)
      sock.setsockopt(socket.SOL_SOCKET,  socket.SO_KEEPALIVE,  True)
      sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE,  7200)
      sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT,      9)
      return sock
  conn = aiohttp.TCPConnector(socket_factory=socket_factory)


Named pipes in Windows
^^^^^^^^^^^^^^^^^^^^^^

If your HTTP server uses Named pipes you can use
:class:`~aiohttp.NamedPipeConnector`::

  conn = aiohttp.NamedPipeConnector(path=r'\\.\pipe\<name-of-pipe>')
  session = aiohttp.ClientSession(connector=conn)

It will only work with the ProactorEventLoop

SSL control for TCP sockets
---------------------------

By default *aiohttp* uses strict checks for HTTPS protocol. Certification
checks can be relaxed by setting *ssl* to ``False``::

  r = await session.get('https://example.com', ssl=False)

If you need to setup custom ssl parameters (use own certification
files for example) you can create a :class:`ssl.SSLContext` instance and
pass it into the :meth:`ClientSession.request` methods or set it for the
entire session with ``ClientSession(connector=TCPConnector(ssl=ssl_context))``.

There are explicit errors when ssl verification fails

:class:`aiohttp.ClientConnectorSSLError`::

  try:
      await session.get('https://expired.badssl.com/')
  except aiohttp.ClientConnectorSSLError as e:
      assert isinstance(e, ssl.SSLError)

:class:`aiohttp.ClientConnectorCertificateError`::

  try:
      await session.get('https://wrong.host.badssl.com/')
  except aiohttp.ClientConnectorCertificateError as e:
      assert isinstance(e, ssl.CertificateError)

If you need to skip both ssl related errors

:class:`aiohttp.ClientSSLError`::

  try:
      await session.get('https://expired.badssl.com/')
  except aiohttp.ClientSSLError as e:
      assert isinstance(e, ssl.SSLError)

  try:
      await session.get('https://wrong.host.badssl.com/')
  except aiohttp.ClientSSLError as e:
      assert isinstance(e, ssl.CertificateError)

Example: Use certifi
^^^^^^^^^^^^^^^^^^^^

By default, Python uses the system CA certificates. In rare cases, these may not be
installed or Python is unable to find them, resulting in a error like
`ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate`

One way to work around this problem is to use the `certifi` package::

  ssl_context = ssl.create_default_context(cafile=certifi.where())
  async with ClientSession(connector=TCPConnector(ssl=ssl_context)) as sess:
      ...

Example: Use self-signed certificate
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you need to verify *self-signed* certificates, you need to add a call to
:meth:`ssl.SSLContext.load_cert_chain` with the key pair::

  ssl_context = ssl.create_default_context()
  ssl_context.load_cert_chain("/path/to/client/public/device.pem",
                              "/path/to/client/private/device.key")
  async with sess.get("https://example.com", ssl=ssl_context) as resp:
      ...

Example: Verify certificate fingerprint
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You may also verify certificates via *SHA256* fingerprint::

  # Attempt to connect to https://www.python.org
  # with a pin to a bogus certificate:
  bad_fp = b'0'*64
  exc = None
  try:
      r = await session.get('https://www.python.org',
                            ssl=aiohttp.Fingerprint(bad_fp))
  except aiohttp.FingerprintMismatch as e:
      exc = e
  assert exc is not None
  assert exc.expected == bad_fp

  # www.python.org cert's actual fingerprint
  assert exc.got == b'...'

Note that this is the fingerprint of the DER-encoded certificate.
If you have the certificate in PEM format, you can convert it to
DER with e.g::

   openssl x509 -in crt.pem -inform PEM -outform DER > crt.der

.. note::

   Tip: to convert from a hexadecimal digest to a binary byte-string,
   you can use :func:`binascii.unhexlify`.

   *ssl* parameter could be passed
   to :class:`TCPConnector` as default, the value from
   :meth:`ClientSession.get` and others override default.

.. _aiohttp-client-proxy-support:

Proxy support
-------------

aiohttp supports plain HTTP proxies and HTTP proxies that can be
upgraded to HTTPS via the HTTP CONNECT method. aiohttp has a limited
support for proxies that must be connected to via ``https://`` — see
the info box below for more details.
To connect, use the *proxy* parameter::

   async with aiohttp.ClientSession() as session:
       async with session.get("http://python.org",
                              proxy="http://proxy.com") as resp:
           print(resp.status)

It also supports proxy authorization::

   async with aiohttp.ClientSession() as session:
       proxy_auth = aiohttp.BasicAuth('user', 'pass')
       async with session.get("http://python.org",
                              proxy="http://proxy.com",
                              proxy_auth=proxy_auth) as resp:
           print(resp.status)

Authentication credentials can be passed in proxy URL::

   session.get("http://python.org",
               proxy="http://user:pass@some.proxy.com")

And you may set default proxy::

   proxy_auth = aiohttp.BasicAuth('user', 'pass')
   async with aiohttp.ClientSession(proxy="http://proxy.com", proxy_auth=proxy_auth) as session:
       async with session.get("http://python.org") as resp:
           print(resp.status)

Contrary to the ``requests`` library, it won't read environment
variables by default. But you can do so by passing
``trust_env=True`` into :class:`aiohttp.ClientSession`
constructor.::

   async with aiohttp.ClientSession(trust_env=True) as session:
       async with session.get("http://python.org") as resp:
           print(resp.status)

.. note::
    aiohttp uses :func:`urllib.request.getproxies`
    for reading the proxy configuration (e.g. from the *HTTP_PROXY* etc. environment variables) and applies them for the *HTTP*, *HTTPS*, *WS* and *WSS* schemes.

    Hosts defined in ``no_proxy`` will bypass the proxy.
.. versionadded:: 3.8

   *WS_PROXY* and *WSS_PROXY* are supported since aiohttp v3.8.

Proxy credentials are given from ``~/.netrc`` file if present (see
:class:`aiohttp.ClientSession` for more details).

.. attention::

   As of now (Python 3.10), support for TLS in TLS is disabled for the transports that
   :py:mod:`asyncio` uses. If the further release of Python (say v3.11)
   toggles one attribute, it'll *just work™*.

   aiohttp v3.8 and higher is ready for this to happen and has code in
   place supports TLS-in-TLS, hence sending HTTPS requests over HTTPS
   proxy tunnels.

   ⚠️ For as long as your Python runtime doesn't declare the support for
   TLS-in-TLS, please don't file bugs with aiohttp but rather try to
   help the CPython upstream enable this feature. Meanwhile, if you
   *really* need this to work, there's a patch that may help you make
   it happen, include it into your app's code base:
   https://github.com/aio-libs/aiohttp/discussions/6044#discussioncomment-1432443.

.. important::

   When supplying a custom :py:class:`ssl.SSLContext` instance, bear in
   mind that it will be used not only to establish a TLS session with
   the HTTPS endpoint you're hitting but also to establish a TLS tunnel
   to the HTTPS proxy. To avoid surprises, make sure to set up the trust
   chain that would recognize TLS certificates used by both the endpoint
   and the proxy.

Graceful Shutdown
-----------------

When :class:`ClientSession` closes at the end of an ``async with``
block (or through a direct :meth:`ClientSession.close` call), the
underlying connection remains open due to asyncio internal details. In
practice, the underlying connection will close after a short
while. However, if the event loop is stopped before the underlying
connection is closed, a ``ResourceWarning: unclosed transport``
warning is emitted (when warnings are enabled).

To avoid this situation, a small delay must be added before closing
the event loop to allow any open underlying connections to close.

For a :class:`ClientSession` without SSL, a simple zero-sleep (``await
asyncio.sleep(0)``) will suffice::

    async def read_website():
        async with aiohttp.ClientSession() as session:
            async with session.get('http://example.org/') as resp:
                await resp.read()
        # Zero-sleep to allow underlying connections to close
        await asyncio.sleep(0)

For a :class:`ClientSession` with SSL, the application must wait a
short duration before closing::

    ...
    # Wait 250 ms for the underlying SSL connections to close
    await asyncio.sleep(0.250)

Note that the appropriate amount of time to wait will vary from
application to application.

All if this will eventually become obsolete when the asyncio internals
are changed so that aiohttp itself can wait on the underlying
connection to close. Please follow issue `#1925
<https://github.com/aio-libs/aiohttp/issues/1925>`_ for the progress
on this.


Character Set Detection
-----------------------

If you encounter a :exc:`UnicodeDecodeError` when using :meth:`ClientResponse.text`
this may be because the response does not include the charset needed
to decode the body.

If you know the correct encoding for a request, you can simply specify
the encoding as a parameter (e.g. ``resp.text("windows-1252")``).

Alternatively, :class:`ClientSession` accepts a ``fallback_charset_resolver`` parameter which
can be used to introduce charset guessing functionality. When a charset is not found
in the Content-Type header, this function will be called to get the charset encoding. For
example, this can be used with the ``chardetng_py`` library.::

    from chardetng_py import detect

    def charset_resolver(resp: ClientResponse, body: bytes) -> str:
        tld = resp.url.host.rsplit(".", maxsplit=1)[-1]
        return detect(body, allow_utf8=True, tld=tld.encode())

    ClientSession(fallback_charset_resolver=charset_resolver)

Or, if ``chardetng_py`` doesn't work for you, then ``charset-normalizer`` is another option::

    from charset_normalizer import detect

    ClientSession(fallback_charset_resolver=lambda r, b: detect(b)["encoding"] or "utf-8")
