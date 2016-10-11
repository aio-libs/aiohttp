CHANGES
=======

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
