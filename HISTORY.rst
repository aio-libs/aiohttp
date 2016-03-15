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
  leads to less amount of poller syscalls e.g epoll.poll(). #702

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

- Suppport gunicorn's `max_requests` settings in gunicorn worker

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
  doesn't call signal for response preparing to be sent.

- Add `StreamReader.__repr__`

- Drop Python 3.3 support, from now minimal required version is Python
  3.4.1 #541

- Add `async with` support for `ClientSession.request()` and family #536

- Ignore message body on 204 and 304 responses #505

- `TCPConnector` processed both IPv4 and IPv6 by default #559

- Add `.routes()` view for urldispatcher #519

- Route name should be a valid identifier name from now #567

- Implement server signals #562

- Drop an year-old deprecated *files* parameter from client API.

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

- Fix multidict comparsion to arbitrary abc.Mapping

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

- Dont sent body for 204, 205 and 304 http exceptions #442

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

- `ProxyConnector` doesn't support keep-alive requests by default
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

- HTTP server performace optimizations

- Allow to match any request method with `*`

- Explicitly call drain on transport #316

- Make chardet module dependency mandatory #318

- Support keep-alive for HTTP 1.0 #325

- Do not chunk single file during upload #327

- Add ClientSession object for cookie storage and default headers #328

- Add `keep_alive_on` argument for HTTP server handler.


0.15.1 (03-31-2015)
-------------------

- Pass Autobahn Testsuit tests

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

- Backward imcompatible change: now there are two mutable multidicts
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

- Application doesn't accept `**kwargs` anymore (#243).

- Request is inherited from dict now for making per-request storage to
  middlewares (#242).


0.13.1 (12-31-2014)
--------------------

- Add `aiohttp.web.StreamResponse.started` property #213

- Html escape traceback text in `ServerHttpProtocol.handle_error`

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

- Response processing refactoring: constructor does't accept Request
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
