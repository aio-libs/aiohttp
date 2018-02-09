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

3.0.0b3 (2018-02-09)
====================

Features
--------

- Speed up the `PayloadWriter.write` method for large request bodies. (#2126)
- StreamResponse and Response are now MutableMappings. (#2246)
- ClientSession publishes a set of signals to track the HTTP request execution.
  (#2313)
- Content-Disposition fast access in ClientResponse (#2455)
- Added support to Flask-style decorators with class-based Views. (#2472)
- Signal handlers (registered callbacks) should be coroutines. (#2480)
- Support ``async with test_client.ws_connect(...)`` (#2525)
- Introduce *site* and *application runner* as underlying API for `web.run_app`
  implementation. (#2530)
- Only quote multipart boundary when necessary and sanitize input (#2544)
- Make the `aiohttp.ClientResponse.get_encoding` method public with the
  processing of invalid charset while detecting content encoding. (#2549)
- Add optional configurable per message compression for
  `ClientWebSocketResponse` and `WebSocketResponse`. (#2551)
- Add hysteresis to `StreamReader` to prevent flipping between paused and
  resumed states too often. (#2555)
- Support `.netrc` by `trust_env` (#2581)
- Avoid to create a new resource when adding a route with the same name and
  path of the last added resource (#2586)
- `MultipartWriter.boundary` is `str` now. (#2589)
- Allow a custom port to be used by `TestServer` (and associated pytest
  fixtures) (#2613)
- Add param access_log_class to web.run_app function (#2615)
- Add ``ssl`` parameter to client API (#2626)
- Fixes performance issue introduced by #2577. When there are no middlewares
  installed by the user, no additional and useless code is executed. (#2629)
- Rename PayloadWriter to StreamWriter (#2654)
- New options *reuse_port*, *reuse_address* are added to `run_app` and
  `TCPSite`. (#2679)
- Use custom classes to pass client signals parameters (#2686)
- Use ``attrs`` library for data classes, replace `namedtuple`. (#2690)
- Pytest fixtures renaming (#2578)

Bugfixes
--------

- Correctly process upgrade request from server to HTTP2. ``aiohttp`` does not
  support HTTP2 yet, the protocol is not upgraded but response is handled
  correctly. (#2277)
- Fix ClientConnectorSSLError and ClientProxyConnectionError for proxy
  connector (#2408)
- Fix connector convert OSError to ClientConnectorError (#2423)
- Fix connection attempts for multiple dns hosts (#2424)
- Fix writing to closed transport by raising `asyncio.CancelledError` (#2499)
- Fix warning in `ClientSession.__del__` by stopping to try to close it.
  (#2523)
- Fixed race-condition for iterating addresses from the DNSCache. (#2620)
- Fix default value of `access_log_format` argument in `web.run_app` (#2649)
- Freeze sub-application on adding to parent app (#2656)
- Do percent encoding for `.url_for()` parameters (#2668)
- Correctly process request start time and multiple request/response
  headers in access log extra (#2641)

Improved Documentation
----------------------

- Improve tutorial docs, using `literalinclude` to link to the actual files.
  (#2396)
- Small improvement docs: better example for file uploads. (#2401)
- Rename `from_env` to `trust_env` in client reference. (#2451)
- ﻿Fixed mistype in `Proxy Support` section where `trust_env` parameter was
  used in `session.get("http://python.org", trust_env=True)` method instead of
  aiohttp.ClientSession constructor as follows:
  `aiohttp.ClientSession(trust_env=True)`. (#2688)


Deprecations and Removals
-------------------------

- Simplify HTTP pipelining implementation (#2109)
- Drop `StreamReaderPayload` and `DataQueuePayload`. (#2257)
- Drop `md5` and `sha1` finger-prints (#2267)
- Drop WSMessage.tp (#2321)
- Drop Python 3.4 and Python 3.5.0, 3.5.1, 3.5.2. Minimal supported Python
  versions are 3.5.3 and 3.6.0. `yield from` is gone, use `async/await` syntax.
  (#2343)
- Drop `aiohttp.Timeout` and use `async_timeout.timeout` instead. (#2348)
- Drop `resolve` param from TCPConnector. (#2377)
- Add DeprecationWarning for returning HTTPException (#2415)
- `send_str()`, `send_bytes()`, `send_json()`, `ping()` and `pong()` are
  genuine async functions now. (#2475)
- Drop undocumented `app.on_pre_signal` and `app.on_post_signal`. Signal
  handlers should be coroutines, support for regular functions is dropped.
  (#2480)
- `StreamResponse.drain()` is not a part of public API anymore, just use `await
  StreamResponse.write()`. `StreamResponse.write` is converted to async
  function. (#2483)
- Drop deprecated `slow_request_timeout` param and `**kwargs`` from
  `RequestHandler`. (#2500)
- Drop deprecated `resource.url()`. (#2501)
- Remove `%u` and `%l` format specifiers from access log format. (#2506)
- Drop deprecated `request.GET` property. (#2547)
- Simplify stream classes: drop `ChunksQueue` and `FlowControlChunksQueue`,
  merge `FlowControlStreamReader` functionality into `StreamReader`, drop
  `FlowControlStreamReader` name. (#2555)
- Do not create a new resource on `router.add_get(..., allow_head=True)`
  (#2585)
- Drop access to TCP tuning options from PayloadWriter and Response classes
  (#2604)
- Drop deprecated `encoding` parameter from client API (#2606)
- Deprecate ``verify_ssl``, ``ssl_context`` and ``fingerprint`` parameters in
  client API (#2626)
- Get rid of the legacy class StreamWriter. (#2651)
- Forbid non-strings in `resource.url_for()` parameters. (#2668)
- Deprecate inheritance from ``ClientSession`` and ``web.Application`` and
  custom user attributes for ``ClientSession``, ``web.Request`` and
  ``web.Application`` (#2691)
- Drop `resp = await aiohttp.request(...)` syntax for sake of `async with
  aiohttp.request(...) as resp:`. (#2540)
- Forbid synchronous context managers for `ClientSession` and test
  server/client. (#2362)


Misc
----

- #2552
