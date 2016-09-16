CHANGES
=======

1.0.0 (XX-XX-XXXX)
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

- Remove aiohttp.websocket module (BACKWARD IMCOMPATIBLE)
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
  (BACKWARD INCOMPATIBLE CHANGE) #1150

- Streams documentation added #1150

- Add `multipart` coroutine method for web Request object #1067

- Publish ClientSession.loop property #1149

- Fix static file with spaces #1140

- Fix piling up asyncio loop by cookie expiration callbacks #1061

- Drop `Timeout` class for sake of `async_timeout` external library.
  `aiohttp.Timeout` is an alias for `async_timeout.timeout`

- `use_dns_cache` parameter of `aiohttp.TCPConnector` is `True` by
  default #1152

- `aiohttp.TCPConnector` uses asynchronous DNS resolver if available by
  default #1152

- Conform to RFC3986 - do not include url fragments in client requests #1174

- Drop `ClientSession.cookies` (BACKWARD INCOMPATIBLE CHANGE) #1173

- Refactor `AbstractCookieJar` public API (BACKWARD INCOMPATIBLE) #1173

- Fix clashing cookies with have the same name but belong to different
  domains #1125

- Support binaryContent-Transfer-Encoding #1169

-

-

-

-

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

- Large cookie expiration/max-age doesn't break an event loop from now
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

- Gunicorn worker with uvloop support `aiohttp.worker.GunicornUVLoopWebWorker` #878

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
