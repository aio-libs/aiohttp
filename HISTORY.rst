0.17.3 (XX-XX-XXXX)
---------------------

- Remove Content-Length header on compressed responses #450

- Support Python 3.5

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
