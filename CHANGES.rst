Changes
=======

2.2.0 (2017-06-20)
------------------

- Add doc for add_head, update doc for add_get. #1944

- Fixed consecutive calls for `Response.write_eof`.

- Retain method attributes (e.g. :code:`__doc__`) when registering synchronous
  handlers for resources. #1953

- Added signal TERM handling in `run_app` to gracefully exit #1932

- Fix websocket issues caused by frame fragmentation. #1962

- Raise RuntimeError is you try to set the Content Length and enable
  chunked encoding at the same time #1941

- Small update for `unittest_run_loop`

- Use CIMultiDict for ClientRequest.skip_auto_headers #1970

- Fix wrong startup sequence: test server and `run_app()` are not raise
  `DeprecationWarning` now #1947

- Make sure cleanup signal is sent if startup signal has been sent #1959

- Fixed server keep-alive handler, could cause 100% cpu utilization #1955

- Connection can be destroyed before response get processed if
  `await aiohttp.request(..)` is used #1981

- MultipartReader does not work with -OO #1969

- Fixed `ClientPayloadError` with blank `Content-Encoding` header #1931

- Support `deflate` encoding implemented in `httpbin.org/deflate` #1918

- Fix BadStatusLine caused by extra `CRLF` after `POST` data #1792

- Keep a reference to `ClientSession` in response object #1985

- Deprecate undocumented `app.on_loop_available` signal #1978



2.1.0 (2017-05-26)
------------------

- Added support for experimental `async-tokio` event loop written in Rust
  https://github.com/PyO3/tokio

- Write to transport ``\r\n`` before closing after keepalive timeout,
  otherwise client can not detect socket disconnection. #1883

- Only call `loop.close` in `run_app` if the user did *not* supply a loop.
  Useful for allowing clients to specify their own cleanup before closing the
  asyncio loop if they wish to tightly control loop behavior

- Content disposition with semicolon in filename #917

- Added `request_info` to response object and `ClientResponseError`. #1733

- Added `history` to `ClientResponseError`. #1741

- Allow to disable redirect url re-quoting #1474

- Handle RuntimeError from transport #1790

- Dropped "%O" in access logger #1673

- Added `args` and `kwargs` to `unittest_run_loop`. Useful with other
  decorators, for example `@patch`. #1803

- Added `iter_chunks` to response.content object. #1805

- Avoid creating TimerContext when there is no timeout to allow
  compatibility with Tornado. #1817 #1180

- Add `proxy_from_env` to `ClientRequest` to read from environment
  variables. #1791

- Add DummyCookieJar helper. #1830

- Fix assertion errors in Python 3.4 from noop helper. #1847

- Do not unquote `+` in match_info values #1816

- Use Forwarded, X-Forwarded-Scheme and X-Forwarded-Host for better scheme and
  host resolution. #1134

- Fix sub-application middlewares resolution order #1853

- Fix applications comparison #1866

- Fix static location in index when prefix is used #1662

- Make test server more reliable #1896

- Extend list of web exceptions, add HTTPUnprocessableEntity,
  HTTPFailedDependency, HTTPInsufficientStorage status codes #1920


2.0.7 (2017-04-12)
------------------
- Fix *pypi* distribution

- Fix exception description #1807

- Handle socket error in FileResponse #1773

- Cancel websocket heartbeat on close #1793


2.0.6 (2017-04-04)
------------------

- Keeping blank values for `request.post()` and `multipart.form()` #1765

- TypeError in data_received of ResponseHandler #1770

- Fix ``web.run_app`` not to bind to default host-port pair if only socket is
  passed #1786


2.0.5 (2017-03-29)
------------------

- Memory leak with aiohttp.request #1756

- Disable cleanup closed ssl transports by default.

- Exception in request handling if the server responds before the body
  is sent #1761


2.0.4 (2017-03-27)
------------------

- Memory leak with aiohttp.request #1756

- Encoding is always UTF-8 in POST data #1750

- Do not add "Content-Disposition" header by default #1755


2.0.3 (2017-03-24)
------------------

- Call https website through proxy will cause error #1745

- Fix exception on multipart/form-data post if content-type is not set #1743


2.0.2 (2017-03-21)
------------------

- Fixed Application.on_loop_available signal #1739

- Remove debug code


2.0.1 (2017-03-21)
------------------

- Fix allow-head to include name on route #1737

- Fixed AttributeError in WebSocketResponse.can_prepare #1736


2.0.0 (2017-03-20)
------------------

- Added `json` to `ClientSession.request()` method #1726

- Added session's `raise_for_status` parameter, automatically calls
  raise_for_status() on any request. #1724

- `response.json()` raises `ClientReponseError` exception if response's
  content type does not match #1723

  - Cleanup timer and loop handle on any client exception.

- Deprecate `loop` parameter for Application's constructor


`2.0.0rc1` (2017-03-15)
-----------------------

- Properly handle payload errors #1710

- Added `ClientWebSocketResponse.get_extra_info()` #1717

- It is not possible to combine Transfer-Encoding and chunked parameter,
  same for compress and Content-Encoding #1655

- Connector's `limit` parameter indicates total concurrent connections.
  New `limit_per_host` added, indicates total connections per endpoint. #1601

- Use url's `raw_host` for name resolution #1685

- Change `ClientResponse.url` to `yarl.URL` instance #1654

- Add max_size parameter to web.Request reading methods #1133

- Web Request.post() stores data in temp files #1469

- Add the `allow_head=True` keyword argument for `add_get` #1618

- `run_app` and the Command Line Interface now support serving over
  Unix domain sockets for faster inter-process communication.

- `run_app` now supports passing a preexisting socket object. This can be useful
  e.g. for socket-based activated applications, when binding of a socket is
  done by the parent process.

- Implementation for Trailer headers parser is broken #1619

- Fix FileResponse to not fall on bad request (range out of file size)

- Fix FileResponse to correct stream video to Chromes

- Deprecate public low-level api #1657

- Deprecate `encoding` parameter for ClientSession.request() method

- Dropped aiohttp.wsgi #1108

- Dropped `version` from ClientSession.request() method

- Dropped websocket version 76 support #1160

- Dropped: `aiohttp.protocol.HttpPrefixParser`  #1590

- Dropped: Servers response's `.started`, `.start()` and
  `.can_start()` method #1591

- Dropped:  Adding `sub app` via `app.router.add_subapp()` is deprecated
  use `app.add_subapp()` instead #1592

- Dropped: `Application.finish()` and `Application.register_on_finish()`  #1602

- Dropped: `web.Request.GET` and `web.Request.POST`

- Dropped: aiohttp.get(), aiohttp.options(), aiohttp.head(),
  aiohttp.post(), aiohttp.put(), aiohttp.patch(), aiohttp.delete(), and
  aiohttp.ws_connect() #1593

- Dropped: `aiohttp.web.WebSocketResponse.receive_msg()` #1605

- Dropped: `ServerHttpProtocol.keep_alive_timeout` attribute and
  `keep-alive`, `keep_alive_on`, `timeout`, `log` constructor parameters #1606

- Dropped: `TCPConnector's`` `.resolve`, `.resolved_hosts`,
  `.clear_resolved_hosts()` attributes and `resolve` constructor
  parameter #1607

- Dropped `ProxyConnector` #1609
