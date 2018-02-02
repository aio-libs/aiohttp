=========
Changelog
=========

..
    You should *NOT* be adding new change log entries to this file, this
    file is managed by towncrier. You *may* edit previous change logs to
    fix problems like typo corrections or such.
    To add a new change log entry, please see
    https://pip.pypa.io/en/latest/development/#adding-a-news-entry
    we named the news folder "changes".

    WARNING: Don't drop the next directive!

.. towncrier release notes start


2.3.10 (2018-02-02)
===================

- Fix 100% CPU usage on HTTP GET and websocket connection just after it (#1955)

- Patch broken `ssl.match_hostname()` on Python<3.7 (#2674)

2.3.9 (2018-01-16)
==================

- Fix colon handing in path for dynamic resources (#2670)

2.3.8 (2018-01-15)
==================

- Do not use `yarl.unquote` internal function in aiohttp.  Fix
  incorrectly unquoted path part in URL dispatcher (#2662)

- Fix compatibility with `yarl==1.0.0` (#2662)

2.3.7 (2017-12-27)
==================

- Fixed race-condition for iterating addresses from the DNSCache. (#2620)
- Fix docstring for request.host (#2591)
- Fix docstring for request.remote (#2592)


2.3.6 (2017-12-04)
==================

- Correct `request.app` context (for handlers not just middlewares). (#2577)


2.3.5 (2017-11-30)
==================

- Fix compatibility with `pytest` 3.3+ (#2565)


2.3.4 (2017-11-29)
==================

- Make `request.app` point to proper application instance when using nested
  applications (with middlewares). (#2550)
- Change base class of ClientConnectorSSLError to ClientSSLError from
  ClientConnectorError. (#2563)
- Return client connection back to free pool on error in `connector.connect()`.
  (#2567)


2.3.3 (2017-11-17)
==================

- Having a `;` in Response content type does not assume it contains a charset
  anymore. (#2197)
- Use `getattr(asyncio, 'async')` for keeping compatibility with Python 3.7.
  (#2476)
- Ignore `NotImplementedError` raised by `set_child_watcher` from `uvloop`.
  (#2491)
- Fix warning in `ClientSession.__del__` by stopping to try to close it.
  (#2523)
- Fixed typo's in Third-party libraries page. And added async-v20 to the list
  (#2510)


2.3.2 (2017-11-01)
==================

- Fix passing client max size on cloning request obj. (#2385)
- Fix ClientConnectorSSLError and ClientProxyConnectionError for proxy
  connector. (#2408)
- Drop generated `_http_parser` shared object from tarball distribution. (#2414)
- Fix connector convert OSError to ClientConnectorError. (#2423)
- Fix connection attempts for multiple dns hosts. (#2424)
- Fix ValueError for AF_INET6 sockets if a preexisting INET6 socket to the
  `aiohttp.web.run_app` function. (#2431)
- `_SessionRequestContextManager` closes the session properly now. (#2441)
- Rename `from_env` to `trust_env` in client reference. (#2451)


2.3.1 (2017-10-18)
==================

- Relax attribute lookup in warning about old-styled middleware (#2340)


2.3.0 (2017-10-18)
==================

Features
--------

- Add SSL related params to `ClientSession.request` (#1128)
- Make enable_compression work on HTTP/1.0 (#1828)
- Deprecate registering synchronous web handlers (#1993)
- Switch to `multidict 3.0`. All HTTP headers preserve casing now but compared
  in case-insensitive way. (#1994)
- Improvement for `normalize_path_middleware`. Added possibility to handle URLs
  with query string. (#1995)
- Use towncrier for CHANGES.txt build (#1997)
- Implement `trust_env=True` param in `ClientSession`. (#1998)
- Added variable to customize proxy headers (#2001)
- Implement `router.add_routes` and router decorators. (#2004)
- Deprecated `BaseRequest.has_body` in favor of
  `BaseRequest.can_read_body` Added `BaseRequest.body_exists`
  attribute that stays static for the lifetime of the request (#2005)
- Provide `BaseRequest.loop` attribute (#2024)
- Make `_CoroGuard` awaitable and fix `ClientSession.close` warning message
  (#2026)
- Responses to redirects without Location header are returned instead of
  raising a RuntimeError (#2030)
- Added `get_client`, `get_server`, `setUpAsync` and `tearDownAsync` methods to
  AioHTTPTestCase (#2032)
- Add automatically a SafeChildWatcher to the test loop (#2058)
- add ability to disable automatic response decompression (#2110)
- Add support for throttling DNS request, avoiding the requests saturation when
  there is a miss in the DNS cache and many requests getting into the connector
  at the same time. (#2111)
- Use request for getting access log information instead of message/transport
  pair. Add `RequestBase.remote` property for accessing to IP of client
  initiated HTTP request. (#2123)
- json() raises a ContentTypeError exception if the content-type does not meet
  the requirements instead of raising a generic ClientResponseError. (#2136)
- Make the HTTP client able to return HTTP chunks when chunked transfer
  encoding is used. (#2150)
- add `append_version` arg into `StaticResource.url` and
  `StaticResource.url_for` methods for getting an url with hash (version) of
  the file. (#2157)
- Fix parsing the Forwarded header. * commas and semicolons are allowed inside
  quoted-strings; * empty forwarded-pairs (as in for=_1;;by=_2) are allowed; *
  non-standard parameters are allowed (although this alone could be easily done
  in the previous parser). (#2173)
- Don't require ssl module to run. aiohttp does not require SSL to function.
  The code paths involved with SSL will only be hit upon SSL usage. Raise
  `RuntimeError` if HTTPS protocol is required but ssl module is not present.
  (#2221)
- Accept coroutine fixtures in pytest plugin (#2223)
- Call `shutdown_asyncgens` before event loop closing on Python 3.6. (#2227)
- Speed up Signals when there are no receivers (#2229)
- Raise `InvalidURL` instead of `ValueError` on fetches with invalid URL.
  (#2241)
- Move `DummyCookieJar` into `cookiejar.py` (#2242)
- `run_app`: Make `print=None` disable printing (#2260)
- Support `brotli` encoding (generic-purpose lossless compression algorithm)
  (#2270)
- Add server support for WebSockets Per-Message Deflate. Add client option to
  add deflate compress header in WebSockets request header. If calling
  ClientSession.ws_connect() with `compress=15` the client will support deflate
  compress negotiation. (#2273)
- Support `verify_ssl`, `fingerprint`, `ssl_context` and `proxy_headers` by
  `client.ws_connect`. (#2292)
- Added `aiohttp.ClientConnectorSSLError` when connection fails due
  `ssl.SSLError` (#2294)
- `aiohttp.web.Application.make_handler` support `access_log_class` (#2315)
- Build HTTP parser extension in non-strict mode by default. (#2332)


Bugfixes
--------

- Clear auth information on redirecting to other domain (#1699)
- Fix missing app.loop on startup hooks during tests (#2060)
- Fix issue with synchronous session closing when using `ClientSession` as an
  asynchronous context manager. (#2063)
- Fix issue with `CookieJar` incorrectly expiring cookies in some edge cases.
  (#2084)
- Force use of IPv4 during test, this will make tests run in a Docker container
  (#2104)
- Warnings about unawaited coroutines now correctly point to the user's code.
  (#2106)
- Fix issue with `IndexError` being raised by the `StreamReader.iter_chunks()`
  generator. (#2112)
- Support HTTP 308 Permanent redirect in client class. (#2114)
- Fix `FileResponse` sending empty chunked body on 304. (#2143)
- Do not add `Content-Length: 0` to GET/HEAD/TRACE/OPTIONS requests by default.
  (#2167)
- Fix parsing the Forwarded header according to RFC 7239. (#2170)
- Securely determining remote/scheme/host #2171 (#2171)
- Fix header name parsing, if name is split into multiple lines (#2183)
- Handle session close during connection, `KeyError:
  <aiohttp.connector._TransportPlaceholder>` (#2193)
- Fixes uncaught `TypeError` in `helpers.guess_filename` if `name` is not a
  string (#2201)
- Raise OSError on async DNS lookup if resolved domain is an alias for another
  one, which does not have an A or CNAME record. (#2231)
- Fix incorrect warning in `StreamReader`. (#2251)
- Properly clone state of web request (#2284)
- Fix C HTTP parser for cases when status line is split into different TCP
  packets. (#2311)
- Fix `web.FileResponse` overriding user supplied Content-Type (#2317)


Improved Documentation
----------------------

- Add a note about possible performance degradation in `await resp.text()` if
  charset was not provided by `Content-Type` HTTP header. Pass explicit
  encoding to solve it. (#1811)
- Drop `disqus` widget from documentation pages. (#2018)
- Add a graceful shutdown section to the client usage documentation. (#2039)
- Document `connector_owner` parameter. (#2072)
- Update the doc of web.Application (#2081)
- Fix mistake about access log disabling. (#2085)
- Add example usage of on_startup and on_shutdown signals by creating and
  disposing an aiopg connection engine. (#2131)
- Document `encoded=True` for `yarl.URL`, it disables all yarl transformations.
  (#2198)
- Document that all app's middleware factories are run for every request.
  (#2225)
- Reflect the fact that default resolver is threaded one starting from aiohttp
  1.1 (#2228)


Deprecations and Removals
-------------------------

- Drop deprecated `Server.finish_connections` (#2006)
- Drop %O format from logging, use %b instead. Drop %e format from logging,
  environment variables are not supported anymore. (#2123)
- Drop deprecated secure_proxy_ssl_header support (#2171)
- Removed TimeService in favor of simple caching. TimeService also had a bug
  where it lost about 0.5 seconds per second. (#2176)
- Drop unused response_factory from static files API (#2290)


Misc
----

- #2013, #2014, #2048, #2094, #2149, #2187, #2214, #2225, #2243, #2248


2.2.5 (2017-08-03)
==================

- Don't raise deprecation warning on
  `loop.run_until_complete(client.close())` (#2065)

2.2.4 (2017-08-02)
==================

- Fix issue with synchronous session closing when using ClientSession
  as an asynchronous context manager.  (#2063)

2.2.3 (2017-07-04)
==================

- Fix `_CoroGuard` for python 3.4

2.2.2 (2017-07-03)
==================

- Allow `await session.close()` along with `yield from session.close()`


2.2.1 (2017-07-02)
==================

- Relax `yarl` requirement to 0.11+

- Backport #2026: `session.close` *is* a coroutine (#2029)


2.2.0 (2017-06-20)
==================

- Add doc for add_head, update doc for add_get. (#1944)

- Fixed consecutive calls for `Response.write_eof`.

- Retain method attributes (e.g. :code:`__doc__`) when registering synchronous
  handlers for resources. (#1953)

- Added signal TERM handling in `run_app` to gracefully exit (#1932)

- Fix websocket issues caused by frame fragmentation. (#1962)

- Raise RuntimeError is you try to set the Content Length and enable
  chunked encoding at the same time (#1941)

- Small update for `unittest_run_loop`

- Use CIMultiDict for ClientRequest.skip_auto_headers (#1970)

- Fix wrong startup sequence: test server and `run_app()` are not raise
  `DeprecationWarning` now (#1947)

- Make sure cleanup signal is sent if startup signal has been sent (#1959)

- Fixed server keep-alive handler, could cause 100% cpu utilization (#1955)

- Connection can be destroyed before response get processed if
  `await aiohttp.request(..)` is used (#1981)

- MultipartReader does not work with -OO (#1969)

- Fixed `ClientPayloadError` with blank `Content-Encoding` header (#1931)

- Support `deflate` encoding implemented in `httpbin.org/deflate` (#1918)

- Fix BadStatusLine caused by extra `CRLF` after `POST` data (#1792)

- Keep a reference to `ClientSession` in response object (#1985)

- Deprecate undocumented `app.on_loop_available` signal (#1978)



2.1.0 (2017-05-26)
==================

- Added support for experimental `async-tokio` event loop written in Rust
  https://github.com/PyO3/tokio

- Write to transport ``\r\n`` before closing after keepalive timeout,
  otherwise client can not detect socket disconnection. (#1883)

- Only call `loop.close` in `run_app` if the user did *not* supply a loop.
  Useful for allowing clients to specify their own cleanup before closing the
  asyncio loop if they wish to tightly control loop behavior

- Content disposition with semicolon in filename (#917)

- Added `request_info` to response object and `ClientResponseError`. (#1733)

- Added `history` to `ClientResponseError`. (#1741)

- Allow to disable redirect url re-quoting (#1474)

- Handle RuntimeError from transport (#1790)

- Dropped "%O" in access logger (#1673)

- Added `args` and `kwargs` to `unittest_run_loop`. Useful with other
  decorators, for example `@patch`. (#1803)

- Added `iter_chunks` to response.content object. (#1805)

- Avoid creating TimerContext when there is no timeout to allow
  compatibility with Tornado. (#1817) (#1180)

- Add `proxy_from_env` to `ClientRequest` to read from environment
  variables. (#1791)

- Add DummyCookieJar helper. (#1830)

- Fix assertion errors in Python 3.4 from noop helper. (#1847)

- Do not unquote `+` in match_info values (#1816)

- Use Forwarded, X-Forwarded-Scheme and X-Forwarded-Host for better scheme and
  host resolution. (#1134)

- Fix sub-application middlewares resolution order (#1853)

- Fix applications comparison (#1866)

- Fix static location in index when prefix is used (#1662)

- Make test server more reliable (#1896)

- Extend list of web exceptions, add HTTPUnprocessableEntity,
  HTTPFailedDependency, HTTPInsufficientStorage status codes (#1920)


2.0.7 (2017-04-12)
==================

- Fix *pypi* distribution

- Fix exception description (#1807)

- Handle socket error in FileResponse (#1773)

- Cancel websocket heartbeat on close (#1793)


2.0.6 (2017-04-04)
==================

- Keeping blank values for `request.post()` and `multipart.form()` (#1765)

- TypeError in data_received of ResponseHandler (#1770)

- Fix ``web.run_app`` not to bind to default host-port pair if only socket is
  passed (#1786)


2.0.5 (2017-03-29)
==================

- Memory leak with aiohttp.request (#1756)

- Disable cleanup closed ssl transports by default.

- Exception in request handling if the server responds before the body
  is sent (#1761)


2.0.4 (2017-03-27)
==================

- Memory leak with aiohttp.request (#1756)

- Encoding is always UTF-8 in POST data (#1750)

- Do not add "Content-Disposition" header by default (#1755)


2.0.3 (2017-03-24)
==================

- Call https website through proxy will cause error (#1745)

- Fix exception on multipart/form-data post if content-type is not set (#1743)


2.0.2 (2017-03-21)
==================

- Fixed Application.on_loop_available signal (#1739)

- Remove debug code


2.0.1 (2017-03-21)
==================

- Fix allow-head to include name on route (#1737)

- Fixed AttributeError in WebSocketResponse.can_prepare (#1736)


2.0.0 (2017-03-20)
==================

- Added `json` to `ClientSession.request()` method (#1726)

- Added session's `raise_for_status` parameter, automatically calls
  raise_for_status() on any request. (#1724)

- `response.json()` raises `ClientReponseError` exception if response's
  content type does not match (#1723)

  - Cleanup timer and loop handle on any client exception.

- Deprecate `loop` parameter for Application's constructor


`2.0.0rc1` (2017-03-15)
=======================

- Properly handle payload errors (#1710)

- Added `ClientWebSocketResponse.get_extra_info()` (#1717)

- It is not possible to combine Transfer-Encoding and chunked parameter,
  same for compress and Content-Encoding (#1655)

- Connector's `limit` parameter indicates total concurrent connections.
  New `limit_per_host` added, indicates total connections per endpoint. (#1601)

- Use url's `raw_host` for name resolution (#1685)

- Change `ClientResponse.url` to `yarl.URL` instance (#1654)

- Add max_size parameter to web.Request reading methods (#1133)

- Web Request.post() stores data in temp files (#1469)

- Add the `allow_head=True` keyword argument for `add_get` (#1618)

- `run_app` and the Command Line Interface now support serving over
  Unix domain sockets for faster inter-process communication.

- `run_app` now supports passing a preexisting socket object. This can be useful
  e.g. for socket-based activated applications, when binding of a socket is
  done by the parent process.

- Implementation for Trailer headers parser is broken (#1619)

- Fix FileResponse to not fall on bad request (range out of file size)

- Fix FileResponse to correct stream video to Chromes

- Deprecate public low-level api (#1657)

- Deprecate `encoding` parameter for ClientSession.request() method

- Dropped aiohttp.wsgi (#1108)

- Dropped `version` from ClientSession.request() method

- Dropped websocket version 76 support (#1160)

- Dropped: `aiohttp.protocol.HttpPrefixParser`  (#1590)

- Dropped: Servers response's `.started`, `.start()` and
  `.can_start()` method (#1591)

- Dropped:  Adding `sub app` via `app.router.add_subapp()` is deprecated
  use `app.add_subapp()` instead (#1592)

- Dropped: `Application.finish()` and `Application.register_on_finish()` (#1602)

- Dropped: `web.Request.GET` and `web.Request.POST`

- Dropped: aiohttp.get(), aiohttp.options(), aiohttp.head(),
  aiohttp.post(), aiohttp.put(), aiohttp.patch(), aiohttp.delete(), and
  aiohttp.ws_connect() (#1593)

- Dropped: `aiohttp.web.WebSocketResponse.receive_msg()` (#1605)

- Dropped: `ServerHttpProtocol.keep_alive_timeout` attribute and
  `keep-alive`, `keep_alive_on`, `timeout`, `log` constructor parameters (#1606)

- Dropped: `TCPConnector's`` `.resolve`, `.resolved_hosts`,
  `.clear_resolved_hosts()` attributes and `resolve` constructor
  parameter (#1607)

- Dropped `ProxyConnector` (#1609)
