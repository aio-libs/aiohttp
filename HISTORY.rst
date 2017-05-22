1.3.5 (2017-03-16)
------------------

- Fixed None timeout support #1720


1.3.4 (2017-03-14)
------------------

- Revert timeout handling in client request

- Fix StreamResponse representation after eof

- Fix file_sender to not fall on bad request (range out of file size)

- Fix file_sender to correct stream video to Chromes

- Fix NotImplementedError server exception #1703

- Clearer error message for URL without a host name. #1691

- Silence deprecation warning in __repr__ #1690

- IDN + HTTPS = `ssl.CertificateError` #1685


1.3.3 (2017-02-19)
------------------

- Fixed memory leak in time service #1656


1.3.2 (2017-02-16)
------------------

- Awaiting on WebSocketResponse.send_* does not work #1645

- Fix multiple calls to client ws_connect when using a shared header dict #1643

- Make CookieJar.filter_cookies() accept plain string parameter. #1636


1.3.1 (2017-02-09)
------------------

- Handle CLOSING in WebSocketResponse.__anext__

- Fixed AttributeError 'drain' for server websocket handler #1613


1.3.0 (2017-02-08)
------------------

- Multipart writer validates the data on append instead of on a request send #920

- Multipart reader accepts multipart messages with or without their epilogue
  to consistently handle valid and legacy behaviors #1526 #1581

- Separate read + connect + request timeouts # 1523

- Do not swallow Upgrade header #1587

- Fix polls demo run application #1487

- Ignore unknown 1XX status codes in client #1353

- Fix sub-Multipart messages missing their headers on serialization #1525

- Do not use readline when reading the content of a part
  in the multipart reader #1535

- Add optional flag for quoting `FormData` fields #916

- 416 Range Not Satisfiable if requested range end > file size #1588

- Having a `:` or `@` in a route does not work #1552

- Added `receive_timeout` timeout for websocket to receive complete message. #1325

- Added `heartbeat` parameter for websocket to automatically send `ping` message. #1024 #777

- Remove `web.Application` dependency from `web.UrlDispatcher` #1510

- Accepting back-pressure from slow websocket clients #1367

- Do not pause transport during set_parser stage #1211

- Lingering close does not terminate before timeout #1559

- `setsockopt` may raise `OSError` exception if socket is closed already #1595

- Lots of CancelledError when requests are interrupted #1565

- Allow users to specify what should happen to decoding errors
  when calling a responses `text()` method #1542

- Back port std module `http.cookies` for python3.4.2 #1566

- Maintain url's fragment in client response #1314

- Allow concurrently close WebSocket connection #754

- Gzipped responses with empty body raises ContentEncodingError #609

- Return 504 if request handle raises TimeoutError.

- Refactor how we use keep-alive and close lingering timeouts.

- Close response connection if we can not consume whole http
  message during client response release

- Abort closed ssl client transports, broken servers can keep socket open un-limit time #1568

- Log warning instead of `RuntimeError` is websocket connection is closed.

- Deprecated: `aiohttp.protocol.HttpPrefixParser`
  will be removed in 1.4 #1590

- Deprecated: Servers response's `.started`, `.start()` and `.can_start()` method
  will be removed in 1.4 #1591

- Deprecated: Adding `sub app` via `app.router.add_subapp()` is deprecated
  use `app.add_subapp()` instead, will be removed in 1.4 #1592

- Deprecated: aiohttp.get(), aiohttp.options(), aiohttp.head(), aiohttp.post(),
  aiohttp.put(), aiohttp.patch(), aiohttp.delete(), and aiohttp.ws_connect()
  will be removed in 1.4 #1593

- Deprecated: `Application.finish()` and `Application.register_on_finish()`
  will be removed in 1.4 #1602


1.2.0 (2016-12-17)
------------------

- Extract `BaseRequest` from `web.Request`, introduce `web.Server`
  (former `RequestHandlerFactory`), introduce new low-level web server
  which is not coupled with `web.Application` and routing #1362

- Make `TestServer.make_url` compatible with `yarl.URL` #1389

- Implement range requests for static files #1382

- Support task attribute for StreamResponse #1410

- Drop `TestClient.app` property, use `TestClient.server.app` instead
  (BACKWARD INCOMPATIBLE)

- Drop `TestClient.handler` property, use `TestClient.server.handler` instead
  (BACKWARD INCOMPATIBLE)

- `TestClient.server` property returns a test server instance, was
  `asyncio.AbstractServer` (BACKWARD INCOMPATIBLE)

- Follow gunicorn's signal semantics in `Gunicorn[UVLoop]WebWorker` #1201

- Call worker_int and worker_abort callbacks in
  `Gunicorn[UVLoop]WebWorker` #1202

- Has functional tests for client proxy #1218

- Fix bugs with client proxy target path and proxy host with port #1413

- Fix bugs related to the use of unicode hostnames #1444

- Preserve cookie quoting/escaping #1453

- FileSender will send gzipped response if gzip version available #1426

- Don't override `Content-Length` header in `web.Response` if no body
  was set #1400

- Introduce `router.post_init()` for solving #1373

- Fix raise error in case of multiple calls of `TimeServive.stop()`

- Allow to raise web exceptions on router resolving stage #1460

- Add a warning for session creation outside of coroutine #1468

- Avoid a race when application might start accepting incoming requests
  but startup signals are not processed yet e98e8c6

- Raise a `RuntimeError` when trying to change the status of the HTTP response
  after the headers have been sent #1480

- Fix bug with https proxy acquired cleanup #1340

- Use UTF-8 as the default encoding for multipart text parts #1484


1.1.6 (2016-11-28)
------------------

- Fix `BodyPartReader.read_chunk` bug about returns zero bytes before
  `EOF` #1428

1.1.5 (2016-11-16)
------------------

- Fix static file serving in fallback mode #1401

1.1.4 (2016-11-14)
------------------

- Make `TestServer.make_url` compatible with `yarl.URL` #1389

- Generate informative exception on redirects from server which
  does not provide redirection headers #1396


1.1.3 (2016-11-10)
------------------

- Support *root* resources for sub-applications #1379


1.1.2 (2016-11-08)
------------------

- Allow starting variables with an underscore #1379

- Properly process UNIX sockets by gunicorn worker #1375

- Fix ordering for `FrozenList`

- Don't propagate pre and post signals to sub-application #1377

1.1.1 (2016-11-04)
------------------

- Fix documentation generation #1120

1.1.0 (2016-11-03)
------------------

- Drop deprecated `WSClientDisconnectedError` (BACKWARD INCOMPATIBLE)

- Use `yarl.URL` in client API. The change is 99% backward compatible
  but `ClientResponse.url` is an `yarl.URL` instance now. #1217

- Close idle keep-alive connections on shutdown #1222

- Modify regex in AccessLogger to accept underscore and numbers #1225

- Use `yarl.URL` in web server API. `web.Request.rel_url` and
  `web.Request.url` are added. URLs and templates are percent-encoded
  now. #1224

- Accept `yarl.URL` by server redirections #1278

- Return `yarl.URL` by `.make_url()` testing utility #1279

- Properly format IPv6 addresses by `aiohttp.web.run_app` #1139

- Use `yarl.URL` by server API #1288

  * Introduce `resource.url_for()`, deprecate `resource.url()`.

  * Implement `StaticResource`.

  * Inherit `SystemRoute` from `AbstractRoute`

  * Drop old-style routes: `Route`, `PlainRoute`, `DynamicRoute`,
    `StaticRoute`, `ResourceAdapter`.

- Revert `resp.url` back to `str`, introduce `resp.url_obj` #1292

- Raise ValueError if BasicAuth login has a ":" character #1307

- Fix bug when ClientRequest send payload file with opened as
  open('filename', 'r+b') #1306

- Enhancement to AccessLogger (pass *extra* dict) #1303

- Show more verbose message on import errors #1319

- Added save and load functionality for `CookieJar` #1219

- Added option on `StaticRoute` to follow symlinks #1299

- Force encoding of `application/json` content type to utf-8 #1339

- Fix invalid invocations of `errors.LineTooLong` #1335

- Websockets: Stop `async for` iteration when connection is closed #1144

- Ensure TestClient HTTP methods return a context manager #1318

- Raise `ClientDisconnectedError` to `FlowControlStreamReader` read function
  if `ClientSession` object is closed by client when reading data. #1323

- Document deployment without `Gunicorn` #1120

- Add deprecation warning for MD5 and SHA1 digests when used for fingerprint
  of site certs in TCPConnector. #1186

- Implement sub-applications #1301

- Don't inherit `web.Request` from `dict` but implement
  `MutableMapping` protocol.

- Implement frozen signals

- Don't inherit `web.Application` from `dict` but implement
  `MutableMapping` protocol.

- Support freezing for web applications

- Accept access_log parameter in `web.run_app`, use `None` to disable logging

- Don't flap `tcp_cork` and `tcp_nodelay` in regular request handling.
  `tcp_nodelay` is still enabled by default.

- Improve performance of web server by removing premature computing of
  Content-Type if the value was set by `web.Response` constructor.

  While the patch boosts speed of trivial `web.Response(text='OK',
  content_type='text/plain)` very well please don't expect significant
  boost of your application -- a couple DB requests and business logic
  is still the main bottleneck.

- Boost performance by adding a custom time service #1350

- Extend `ClientResponse` with `content_type` and `charset`
  properties like in `web.Request`. #1349

- Disable aiodns by default #559

- Don't flap `tcp_cork` in client code, use TCP_NODELAY mode by default.

- Implement `web.Request.clone()` #1361

1.0.5 (2016-10-11)
------------------

- Fix StreamReader._read_nowait to return all available
  data up to the requested amount #1297


1.0.4 (2016-09-22)
------------------

- Fix FlowControlStreamReader.read_nowait so that it checks
  whether the transport is paused #1206


1.0.2 (2016-09-22)
------------------

- Make CookieJar compatible with 32-bit systems #1188

- Add missing `WSMsgType` to `web_ws.__all__`, see #1200

- Fix `CookieJar` ctor when called with `loop=None` #1203

- Fix broken upper-casing in wsgi support #1197


1.0.1 (2016-09-16)
------------------

- Restore `aiohttp.web.MsgType` alias for `aiohttp.WSMsgType` for sake
  of backward compatibility #1178

- Tune alabaster schema.

- Use `text/html` content type for displaying index pages by static
  file handler.

- Fix `AssertionError` in static file handling #1177

- Fix access log formats `%O` and `%b` for static file handling

- Remove `debug` setting of GunicornWorker, use `app.debug`
  to control its debug-mode instead


1.0.0 (2016-09-16)
-------------------

- Change default size for client session's connection pool from
  unlimited to 20 #977

- Add IE support for cookie deletion. #994

- Remove deprecated `WebSocketResponse.wait_closed` method (BACKWARD
  INCOMPATIBLE)

- Remove deprecated `force` parameter for `ClientResponse.close`
  method (BACKWARD INCOMPATIBLE)

- Avoid using of mutable CIMultiDict kw param in make_mocked_request
  #997

- Make WebSocketResponse.close a little bit faster by avoiding new
  task creating just for timeout measurement

- Add `proxy` and `proxy_auth` params to `client.get()` and family,
  deprecate `ProxyConnector` #998

- Add support for websocket send_json and receive_json, synchronize
  server and client API for websockets #984

- Implement router shourtcuts for most useful HTTP methods, use
  `app.router.add_get()`, `app.router.add_post()` etc. instead of
  `app.router.add_route()` #986

- Support SSL connections for gunicorn worker #1003

- Move obsolete examples to legacy folder

- Switch to multidict 2.0 and title-cased strings #1015

- `{FOO}e` logger format is case-sensitive now

- Fix logger report for unix socket 8e8469b

- Rename aiohttp.websocket to aiohttp._ws_impl

- Rename aiohttp.MsgType tp aiohttp.WSMsgType

- Introduce aiohttp.WSMessage officially

- Rename Message -> WSMessage

- Remove deprecated decode param from resp.read(decode=True)

- Use 5min default client timeout #1028

- Relax HTTP method validation in UrlDispatcher #1037

- Pin minimal supported asyncio version to 3.4.2+ (`loop.is_close()`
  should be present)

- Remove aiohttp.websocket module (BACKWARD INCOMPATIBLE)
  Please use high-level client and server approaches

- Link header for 451 status code is mandatory

- Fix test_client fixture to allow multiple clients per test #1072

- make_mocked_request now accepts dict as headers #1073

- Add Python 3.5.2/3.6+ compatibility patch for async generator
  protocol change #1082

- Improvement test_client can accept instance object #1083

- Simplify ServerHttpProtocol implementation #1060

- Add a flag for optional showing directory index for static file
  handling #921

- Define `web.Application.on_startup()` signal handler #1103

- Drop ChunkedParser and LinesParser #1111

- Call `Application.startup` in GunicornWebWorker #1105

- Fix client handling hostnames with 63 bytes when a port is given in
  the url #1044

- Implement proxy support for ClientSession.ws_connect #1025

- Return named tuple from WebSocketResponse.can_prepare #1016

- Fix access_log_format in `GunicornWebWorker` #1117

- Setup Content-Type to application/octet-stream by default #1124

- Deprecate debug parameter from app.make_handler(), use
  `Application(debug=True)` instead #1121

- Remove fragment string in request path #846

- Use aiodns.DNSResolver.gethostbyname() if available #1136

- Fix static file sending on uvloop when sendfile is available #1093

- Make prettier urls if query is empty dict #1143

- Fix redirects for HEAD requests #1147

- Default value for `StreamReader.read_nowait` is -1 from now #1150

- `aiohttp.StreamReader` is not inherited from `asyncio.StreamReader` from now
  (BACKWARD INCOMPATIBLE) #1150

- Streams documentation added #1150

- Add `multipart` coroutine method for web Request object #1067

- Publish ClientSession.loop property #1149

- Fix static file with spaces #1140

- Fix piling up asyncio loop by cookie expiration callbacks #1061

- Drop `Timeout` class for sake of `async_timeout` external library.
  `aiohttp.Timeout` is an alias for `async_timeout.timeout`

- `use_dns_cache` parameter of `aiohttp.TCPConnector` is `True` by
  default (BACKWARD INCOMPATIBLE) #1152

- `aiohttp.TCPConnector` uses asynchronous DNS resolver if available by
  default (BACKWARD INCOMPATIBLE) #1152

- Conform to RFC3986 - do not include url fragments in client requests #1174

- Drop `ClientSession.cookies` (BACKWARD INCOMPATIBLE) #1173

- Refactor `AbstractCookieJar` public API (BACKWARD INCOMPATIBLE) #1173

- Fix clashing cookies with have the same name but belong to different
  domains (BACKWARD INCOMPATIBLE) #1125

- Support binary Content-Transfer-Encoding #1169


0.22.5 (08-02-2016)
-------------------

- Pin miltidict version to >=1.2.2

0.22.3 (07-26-2016)
-------------------

- Do not filter cookies if unsafe flag provided #1005


0.22.2 (07-23-2016)
-------------------

- Suppress CancelledError when Timeout raises TimeoutError #970

- Don't expose `aiohttp.__version__`

- Add unsafe parameter to CookieJar #968

- Use unsafe cookie jar in test client tools

- Expose aiohttp.CookieJar name


0.22.1 (07-16-2016)
-------------------

- Large cookie expiration/max-age does not break an event loop from now
  (fixes #967)


0.22.0 (07-15-2016)
-------------------

- Fix bug in serving static directory #803

- Fix command line arg parsing #797

- Fix a documentation chapter about cookie usage #790

- Handle empty body with gzipped encoding #758

- Support 451 Unavailable For Legal Reasons http status  #697

- Fix Cookie share example and few small typos in docs #817

- UrlDispatcher.add_route with partial coroutine handler #814

- Optional support for aiodns #728

- Add ServiceRestart and TryAgainLater websocket close codes #828

- Fix prompt message for `web.run_app` #832

- Allow to pass None as a timeout value to disable timeout logic #834

- Fix leak of connection slot during connection error #835

- Gunicorn worker with uvloop support
  `aiohttp.worker.GunicornUVLoopWebWorker` #878

- Don't send body in response to HEAD request #838

- Skip the preamble in MultipartReader #881

- Implement BasicAuth decode classmethod. #744

- Don't crash logger when transport is None #889

- Use a create_future compatibility wrapper instead of creating
  Futures directly #896

- Add test utilities to aiohttp #902

- Improve Request.__repr__ #875

- Skip DNS resolving if provided host is already an ip address #874

- Add headers to ClientSession.ws_connect #785

- Document that server can send pre-compressed data #906

- Don't add Content-Encoding and Transfer-Encoding if no body #891

- Add json() convenience methods to websocket message objects #897

- Add client_resp.raise_for_status() #908

- Implement cookie filter #799

- Include an example of middleware to handle error pages #909

- Fix error handling in StaticFileMixin #856

- Add mocked request helper #900

- Fix empty ALLOW Response header for cls based View #929

- Respect CONNECT method to implement a proxy server #847

- Add pytest_plugin #914

- Add tutorial

- Add backlog option to support more than 128 (default value in
  "create_server" function) concurrent connections #892

- Allow configuration of header size limits #912

- Separate sending file logic from StaticRoute dispatcher #901

- Drop deprecated share_cookies connector option (BACKWARD INCOMPATIBLE)

- Drop deprecated support for tuple as auth parameter.
  Use aiohttp.BasicAuth instead (BACKWARD INCOMPATIBLE)

- Remove deprecated `request.payload` property, use `content` instead.
  (BACKWARD INCOMPATIBLE)

- Drop all mentions about api changes in documentation for versions
  older than 0.16

- Allow to override default cookie jar #963

- Add manylinux wheel builds

- Dup a socket for sendfile usage #964

0.21.6 (05-05-2016)
-------------------

- Drop initial query parameters on redirects #853


0.21.5 (03-22-2016)
-------------------

- Fix command line arg parsing #797

0.21.4 (03-12-2016)
-------------------

- Fix ResourceAdapter: don't add method to allowed if resource is not
  match #826

- Fix Resource: append found method to returned allowed methods

0.21.2 (02-16-2016)
-------------------

- Fix a regression: support for handling ~/path in static file routes was
  broken #782

0.21.1 (02-10-2016)
-------------------

- Make new resources classes public #767

- Add `router.resources()` view

- Fix cmd-line parameter names in doc

0.21.0 (02-04-2016)
--------------------

- Introduce on_shutdown signal #722

- Implement raw input headers #726

- Implement web.run_app utility function #734

- Introduce on_cleanup signal

- Deprecate Application.finish() / Application.register_on_finish() in favor of
  on_cleanup.

- Get rid of bare aiohttp.request(), aiohttp.get() and family in docs #729

- Deprecate bare aiohttp.request(), aiohttp.get() and family #729

- Refactor keep-alive support #737:

  - Enable keepalive for HTTP 1.0 by default

  - Disable it for HTTP 0.9 (who cares about 0.9, BTW?)

  - For keepalived connections

      - Send `Connection: keep-alive` for HTTP 1.0 only

      - don't send `Connection` header for HTTP 1.1

  - For non-keepalived connections

      - Send `Connection: close` for HTTP 1.1 only

      - don't send `Connection` header for HTTP 1.0

- Add version parameter to ClientSession constructor,
  deprecate it for session.request() and family #736

- Enable access log by default #735

- Deprecate app.router.register_route() (the method was not documented
  intentionally BTW).

- Deprecate app.router.named_routes() in favor of app.router.named_resources()

- route.add_static accepts pathlib.Path now #743

- Add command line support: `$ python -m aiohttp.web package.main` #740

- FAQ section was added to docs. Enjoy and fill free to contribute new topics

- Add async context manager support to ClientSession

- Document ClientResponse's host, method, url properties

- Use CORK/NODELAY in client API #748

- ClientSession.close and Connector.close are coroutines now

- Close client connection on exception in ClientResponse.release()

- Allow to read multipart parts without content-length specified #750

- Add support for unix domain sockets to gunicorn worker #470

- Add test for default Expect handler #601

- Add the first demo project

- Rename `loader` keyword argument in `web.Request.json` method. #646

- Add local socket binding for TCPConnector #678

0.20.2 (01-07-2016)
--------------------

- Enable use of `await` for a class based view #717

- Check address family to fill wsgi env properly #718

- Fix memory leak in headers processing (thanks to Marco Paolini) #723

0.20.1 (12-30-2015)
-------------------

- Raise RuntimeError is Timeout context manager was used outside of
  task context.

- Add number of bytes to stream.read_nowait #700

- Use X-FORWARDED-PROTO for wsgi.url_scheme when available


0.20.0 (12-28-2015)
-------------------

- Extend list of web exceptions, add HTTPMisdirectedRequest,
  HTTPUpgradeRequired, HTTPPreconditionRequired, HTTPTooManyRequests,
  HTTPRequestHeaderFieldsTooLarge, HTTPVariantAlsoNegotiates,
  HTTPNotExtended, HTTPNetworkAuthenticationRequired status codes #644

- Do not remove AUTHORIZATION header by WSGI handler #649

- Fix broken support for https proxies with authentication #617

- Get REMOTE_* and SEVER_* http vars from headers when listening on
  unix socket #654

- Add HTTP 308 support #663

- Add Tf format (time to serve request in seconds, %06f format) to
  access log #669

- Remove one and a half years long deprecated
  ClientResponse.read_and_close() method

- Optimize chunked encoding: use a single syscall instead of 3 calls
  on sending chunked encoded data

- Use TCP_CORK and TCP_NODELAY to optimize network latency and
  throughput #680

- Websocket XOR performance improved #687

- Avoid sending cookie attributes in Cookie header #613

- Round server timeouts to seconds for grouping pending calls.  That
  leads to less amount of poller syscalls e.g. epoll.poll(). #702

- Close connection on websocket handshake error #703

- Implement class based views #684

- Add *headers* parameter to ws_connect() #709

- Drop unused function `parse_remote_addr()` #708

- Close session on exception #707

- Store http code and headers in WSServerHandshakeError #706

- Make some low-level message properties readonly #710


0.19.0 (11-25-2015)
-------------------

- Memory leak in ParserBuffer #579

- Support gunicorn's `max_requests` settings in gunicorn worker

- Fix wsgi environment building #573

- Improve access logging #572

- Drop unused host and port from low-level server #586

- Add Python 3.5 `async for` implementation to server websocket #543

- Add Python 3.5 `async for` implementation to client websocket

- Add Python 3.5 `async with` implementation to client websocket

- Add charset parameter to web.Response constructor #593

- Forbid passing both Content-Type header and content_type or charset
  params into web.Response constructor

- Forbid duplicating of web.Application and web.Request #602

- Add an option to pass Origin header in ws_connect #607

- Add json_response function #592

- Make concurrent connections respect limits #581

- Collect history of responses if redirects occur #614

- Enable passing pre-compressed data in requests #621

- Expose named routes via UrlDispatcher.named_routes() #622

- Allow disabling sendfile by environment variable AIOHTTP_NOSENDFILE #629

- Use ensure_future if available

- Always quote params for Content-Disposition #641

- Support async for in multipart reader #640

- Add Timeout context manager #611

0.18.4 (13-11-2015)
-------------------

- Relax rule for router names again by adding dash to allowed
  characters: they may contain identifiers, dashes, dots and columns

0.18.3 (25-10-2015)
-------------------

- Fix formatting for _RequestContextManager helper #590

0.18.2 (22-10-2015)
-------------------

- Fix regression for OpenSSL < 1.0.0 #583

0.18.1 (20-10-2015)
-------------------

- Relax rule for router names: they may contain dots and columns
  starting from now

0.18.0 (19-10-2015)
-------------------

- Use errors.HttpProcessingError.message as HTTP error reason and
  message #459

- Optimize cythonized multidict a bit

- Change repr's of multidicts and multidict views

- default headers in ClientSession are now case-insensitive

- Make '=' char and 'wss://' schema safe in urls #477

- `ClientResponse.close()` forces connection closing by default from now #479

  N.B. Backward incompatible change: was `.close(force=False) Using
  `force` parameter for the method is deprecated: use `.release()`
  instead.

- Properly requote URL's path #480

- add `skip_auto_headers` parameter for client API #486

- Properly parse URL path in aiohttp.web.Request #489

- Raise RuntimeError when chunked enabled and HTTP is 1.0 #488

- Fix a bug with processing io.BytesIO as data parameter for client API #500

- Skip auto-generation of Content-Type header #507

- Use sendfile facility for static file handling #503

- Default `response_factory` in `app.router.add_static` now is
  `StreamResponse`, not `None`. The functionality is not changed if
  default is not specified.

- Drop `ClientResponse.message` attribute, it was always implementation detail.

- Streams are optimized for speed and mostly memory in case of a big
  HTTP message sizes #496

- Fix a bug for server-side cookies for dropping cookie and setting it
  again without Max-Age parameter.

- Don't trim redirect URL in client API #499

- Extend precision of access log "D" to milliseconds #527

- Deprecate `StreamResponse.start()` method in favor of
  `StreamResponse.prepare()` coroutine #525

  `.start()` is still supported but responses begun with `.start()`
  does not call signal for response preparing to be sent.

- Add `StreamReader.__repr__`

- Drop Python 3.3 support, from now minimal required version is Python
  3.4.1 #541

- Add `async with` support for `ClientSession.request()` and family #536

- Ignore message body on 204 and 304 responses #505

- `TCPConnector` processed both IPv4 and IPv6 by default #559

- Add `.routes()` view for urldispatcher #519

- Route name should be a valid identifier name from now #567

- Implement server signals #562

- Drop a year-old deprecated *files* parameter from client API.

- Added `async for` support for aiohttp stream #542

0.17.4 (09-29-2015)
-------------------

- Properly parse URL path in aiohttp.web.Request #489

- Add missing coroutine decorator, the client api is await-compatible now

0.17.3 (08-28-2015)
---------------------

- Remove Content-Length header on compressed responses #450

- Support Python 3.5

- Improve performance of transport in-use list #472

- Fix connection pooling #473

0.17.2 (08-11-2015)
---------------------

- Don't forget to pass `data` argument forward #462

- Fix multipart read bytes count #463

0.17.1 (08-10-2015)
---------------------

- Fix multidict comparison to arbitrary abc.Mapping

0.17.0 (08-04-2015)
---------------------

- Make StaticRoute support Last-Modified and If-Modified-Since headers #386

- Add Request.if_modified_since and Stream.Response.last_modified properties

- Fix deflate compression when writing a chunked response #395

- Request`s content-length header is cleared now after redirect from
  POST method #391

- Return a 400 if server received a non HTTP content #405

- Fix keep-alive support for aiohttp clients #406

- Allow gzip compression in high-level server response interface #403

- Rename TCPConnector.resolve and family to dns_cache #415

- Make UrlDispatcher ignore quoted characters during url matching #414
  Backward-compatibility warning: this may change the url matched by
  your queries if they send quoted character (like %2F for /) #414

- Use optional cchardet accelerator if present #418

- Borrow loop from Connector in ClientSession if loop is not set

- Add context manager support to ClientSession for session closing.

- Add toplevel get(), post(), put(), head(), delete(), options(),
  patch() coroutines.

- Fix IPv6 support for client API #425

- Pass SSL context through proxy connector #421

- Make the rule: path for add_route should start with slash

- Don't process request finishing by low-level server on closed event loop

- Don't override data if multiple files are uploaded with same key #433

- Ensure multipart.BodyPartReader.read_chunk read all the necessary data
  to avoid false assertions about malformed multipart payload

- Don't send body for 204, 205 and 304 http exceptions #442

- Correctly skip Cython compilation in MSVC not found #453

- Add response factory to StaticRoute #456

- Don't append trailing CRLF for multipart.BodyPartReader #454


0.16.6 (07-15-2015)
-------------------

- Skip compilation on Windows if vcvarsall.bat cannot be found #438

0.16.5 (06-13-2015)
-------------------

- Get rid of all comprehensions and yielding in _multidict #410


0.16.4 (06-13-2015)
-------------------

- Don't clear current exception in multidict's `__repr__` (cythonized
  versions) #410


0.16.3 (05-30-2015)
-------------------

- Fix StaticRoute vulnerability to directory traversal attacks #380


0.16.2 (05-27-2015)
-------------------

- Update python version required for `__del__` usage: it's actually
  3.4.1 instead of 3.4.0

- Add check for presence of loop.is_closed() method before call the
  former #378


0.16.1 (05-27-2015)
-------------------

- Fix regression in static file handling #377

0.16.0 (05-26-2015)
-------------------

- Unset waiter future after cancellation #363

- Update request url with query parameters #372

- Support new `fingerprint` param of TCPConnector to enable verifying
  SSL certificates via MD5, SHA1, or SHA256 digest #366

- Setup uploaded filename if field value is binary and transfer
  encoding is not specified #349

- Implement `ClientSession.close()` method

- Implement `connector.closed` readonly property

- Implement `ClientSession.closed` readonly property

- Implement `ClientSession.connector` readonly property

- Implement `ClientSession.detach` method

- Add `__del__` to client-side objects: sessions, connectors,
  connections, requests, responses.

- Refactor connections cleanup by connector #357

- Add `limit` parameter to connector constructor #358

- Add `request.has_body` property #364

- Add `response_class` parameter to `ws_connect()` #367

- `ProxyConnector` does not support keep-alive requests by default
  starting from now #368

- Add `connector.force_close` property

- Add ws_connect to ClientSession #374

- Support optional `chunk_size` parameter in `router.add_static()`


0.15.3 (04-22-2015)
-------------------

- Fix graceful shutdown handling

- Fix `Expect` header handling for not found and not allowed routes #340


0.15.2 (04-19-2015)
-------------------

- Flow control subsystem refactoring

- HTTP server performance optimizations

- Allow to match any request method with `*`

- Explicitly call drain on transport #316

- Make chardet module dependency mandatory #318

- Support keep-alive for HTTP 1.0 #325

- Do not chunk single file during upload #327

- Add ClientSession object for cookie storage and default headers #328

- Add `keep_alive_on` argument for HTTP server handler.


0.15.1 (03-31-2015)
-------------------

- Pass Autobahn Testsuite tests

- Fixed websocket fragmentation

- Fixed websocket close procedure

- Fixed parser buffer limits

- Added `timeout` parameter to WebSocketResponse ctor

- Added `WebSocketResponse.close_code` attribute


0.15.0 (03-27-2015)
-------------------

- Client WebSockets support

- New Multipart system #273

- Support for "Except" header #287 #267

- Set default Content-Type for post requests #184

- Fix issue with construction dynamic route with regexps and trailing slash #266

- Add repr to web.Request

- Add repr to web.Response

- Add repr for NotFound and NotAllowed match infos

- Add repr for web.Application

- Add repr to UrlMappingMatchInfo #217

- Gunicorn 19.2.x compatibility


0.14.4 (01-29-2015)
-------------------

- Fix issue with error during constructing of url with regex parts #264


0.14.3 (01-28-2015)
-------------------

- Use path='/' by default for cookies #261


0.14.2 (01-23-2015)
-------------------

- Connections leak in BaseConnector #253

- Do not swallow websocket reader exceptions #255

- web.Request's read, text, json are memorized #250


0.14.1 (01-15-2015)
-------------------

- HttpMessage._add_default_headers does not overwrite existing headers #216

- Expose multidict classes at package level

- add `aiohttp.web.WebSocketResponse`

- According to RFC 6455 websocket subprotocol preference order is
  provided by client, not by server

- websocket's ping and pong accept optional message parameter

- multidict views do not accept `getall` parameter anymore, it
  returns the full body anyway.

- multidicts have optional Cython optimization, cythonized version of
  multidicts is about 5 times faster than pure Python.

- multidict.getall() returns `list`, not `tuple`.

- Backward incompatible change: now there are two mutable multidicts
  (`MultiDict`, `CIMultiDict`) and two immutable multidict proxies
  (`MultiDictProxy` and `CIMultiDictProxy`). Previous edition of
  multidicts was not a part of public API BTW.

- Router refactoring to push Not Allowed and Not Found in middleware processing

- Convert `ConnectionError` to `aiohttp.DisconnectedError` and don't
  eat `ConnectionError` exceptions from web handlers.

- Remove hop headers from Response class, wsgi response still uses hop headers.

- Allow to send raw chunked encoded response.

- Allow to encode output bytes stream into chunked encoding.

- Allow to compress output bytes stream with `deflate` encoding.

- Server has 75 seconds keepalive timeout now, was non-keepalive by default.

- Application does not accept `**kwargs` anymore (#243).

- Request is inherited from dict now for making per-request storage to
  middlewares (#242).


0.13.1 (12-31-2014)
--------------------

- Add `aiohttp.web.StreamResponse.started` property #213

- HTML escape traceback text in `ServerHttpProtocol.handle_error`

- Mention handler and middlewares in `aiohttp.web.RequestHandler.handle_request`
  on error (#218)


0.13.0 (12-29-2014)
-------------------

- `StreamResponse.charset` converts value to lower-case on assigning.

- Chain exceptions when raise `ClientRequestError`.

- Support custom regexps in route variables #204

- Fixed graceful shutdown, disable keep-alive on connection closing.

- Decode HTTP message with `utf-8` encoding, some servers send headers
  in utf-8 encoding #207

- Support `aiohtt.web` middlewares #209

- Add ssl_context to TCPConnector #206


0.12.0 (12-12-2014)
-------------------

- Deep refactoring of `aiohttp.web` in backward-incompatible manner.
  Sorry, we have to do this.

- Automatically force aiohttp.web handlers to coroutines in
  `UrlDispatcher.add_route()` #186

- Rename `Request.POST()` function to `Request.post()`

- Added POST attribute

- Response processing refactoring: constructor does not accept Request
  instance anymore.

- Pass application instance to finish callback

- Exceptions refactoring

- Do not unquote query string in `aiohttp.web.Request`

- Fix concurrent access to payload in `RequestHandle.handle_request()`

- Add access logging to `aiohttp.web`

- Gunicorn worker for `aiohttp.web`

- Removed deprecated `AsyncGunicornWorker`

- Removed deprecated HttpClient


0.11.0 (11-29-2014)
-------------------

- Support named routes in `aiohttp.web.UrlDispatcher` #179

- Make websocket subprotocols conform to spec #181


0.10.2 (11-19-2014)
-------------------

- Don't unquote `environ['PATH_INFO']` in wsgi.py #177


0.10.1 (11-17-2014)
-------------------

- aiohttp.web.HTTPException and descendants now files response body
  with string like `404: NotFound`

- Fix multidict `__iter__`, the method should iterate over keys, not
  (key, value) pairs.


0.10.0 (11-13-2014)
-------------------

- Add aiohttp.web subpackage for highlevel HTTP server support.

- Add *reason* optional parameter to aiohttp.protocol.Response ctor.

- Fix aiohttp.client bug for sending file without content-type.

- Change error text for connection closed between server responses
  from 'Can not read status line' to explicit 'Connection closed by
  server'

- Drop closed connections from connector #173

- Set server.transport to None on .closing() #172


0.9.3 (10-30-2014)
------------------

- Fix compatibility with asyncio 3.4.1+ #170


0.9.2 (10-16-2014)
------------------

- Improve redirect handling #157

- Send raw files as is #153

- Better websocket support #150


0.9.1 (08-30-2014)
------------------

- Added MultiDict support for client request params and data #114.

- Fixed parameter type for IncompleteRead exception #118.

- Strictly require ASCII headers names and values #137

- Keep port in ProxyConnector #128.

- Python 3.4.1 compatibility #131.


0.9.0 (07-08-2014)
------------------

- Better client basic authentication support #112.

- Fixed incorrect line splitting in HttpRequestParser #97.

- Support StreamReader and DataQueue as request data.

- Client files handling refactoring #20.

- Backward incompatible: Replace DataQueue with StreamReader for
  request payload #87.


0.8.4 (07-04-2014)
------------------

- Change ProxyConnector authorization parameters.


0.8.3 (07-03-2014)
------------------

- Publish TCPConnector properties: verify_ssl, family, resolve, resolved_hosts.

- Don't parse message body for HEAD responses.

- Refactor client response decoding.


0.8.2 (06-22-2014)
------------------

- Make ProxyConnector.proxy immutable property.

- Make UnixConnector.path immutable property.

- Fix resource leak for aiohttp.request() with implicit connector.

- Rename Connector's reuse_timeout to keepalive_timeout.


0.8.1 (06-18-2014)
------------------

- Use case insensitive multidict for server request/response headers.

- MultiDict.getall() accepts default value.

- Catch server ConnectionError.

- Accept MultiDict (and derived) instances in aiohttp.request header argument.

- Proxy 'CONNECT' support.


0.8.0 (06-06-2014)
------------------

- Add support for utf-8 values in HTTP headers

- Allow to use custom response class instead of HttpResponse

- Use MultiDict for client request headers

- Use MultiDict for server request/response headers

- Store response headers in ClientResponse.headers attribute

- Get rid of timeout parameter in aiohttp.client API

- Exceptions refactoring


0.7.3 (05-20-2014)
------------------

- Simple HTTP proxy support.


0.7.2 (05-14-2014)
------------------

- Get rid of `__del__` methods

- Use ResourceWarning instead of logging warning record.


0.7.1 (04-28-2014)
------------------

- Do not unquote client request urls.

- Allow multiple waiters on transport drain.

- Do not return client connection to pool in case of exceptions.

- Rename SocketConnector to TCPConnector and UnixSocketConnector to
  UnixConnector.


0.7.0 (04-16-2014)
------------------

- Connection flow control.

- HTTP client session/connection pool refactoring.

- Better handling for bad server requests.


0.6.5 (03-29-2014)
------------------

- Added client session reuse timeout.

- Better client request cancellation support.

- Better handling responses without content length.

- Added HttpClient verify_ssl parameter support.


0.6.4 (02-27-2014)
------------------

- Log content-length missing warning only for put and post requests.


0.6.3 (02-27-2014)
------------------

- Better support for server exit.

- Read response body until EOF if content-length is not defined #14


0.6.2 (02-18-2014)
------------------

- Fix trailing char in allowed_methods.

- Start slow request timer for first request.


0.6.1 (02-17-2014)
------------------

- Added utility method HttpResponse.read_and_close()

- Added slow request timeout.

- Enable socket SO_KEEPALIVE if available.


0.6.0 (02-12-2014)
------------------

- Better handling for process exit.


0.5.0 (01-29-2014)
------------------

- Allow to use custom HttpRequest client class.

- Use gunicorn keepalive setting for asynchronous worker.

- Log leaking responses.

- python 3.4 compatibility


0.4.4 (11-15-2013)
------------------

- Resolve only AF_INET family, because it is not clear how to pass
  extra info to asyncio.


0.4.3 (11-15-2013)
------------------

- Allow to wait completion of request with `HttpResponse.wait_for_close()`


0.4.2 (11-14-2013)
------------------

- Handle exception in client request stream.

- Prevent host resolving for each client request.


0.4.1 (11-12-2013)
------------------

- Added client support for `expect: 100-continue` header.


0.4 (11-06-2013)
----------------

- Added custom wsgi application close procedure

- Fixed concurrent host failure in HttpClient


0.3 (11-04-2013)
----------------

- Added PortMapperWorker

- Added HttpClient

- Added TCP connection timeout to HTTP client

- Better client connection errors handling

- Gracefully handle process exit


0.2
---

- Fix packaging
