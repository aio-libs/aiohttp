3.4.4 (2018-09-05)
==================

- Fix installation from sources when compiling toolkit is not available (`#3241 <https://github.com/aio-libs/aiohttp/pull/3241>`_)

3.4.3 (2018-09-04)
==================

- Add ``app.pre_frozen`` state to properly handle startup signals in sub-applications. (`#3237 <https://github.com/aio-libs/aiohttp/pull/3237>`_)


3.4.2 (2018-09-01)
==================

- Fix ``iter_chunks`` type annotation (`#3230 <https://github.com/aio-libs/aiohttp/pull/3230>`_)

3.4.1 (2018-08-28)
==================

- Fix empty header parsing regression. (`#3218 <https://github.com/aio-libs/aiohttp/pull/3218>`_)
- Fix BaseRequest.raw_headers doc. (`#3215 <https://github.com/aio-libs/aiohttp/pull/3215>`_)
- Fix documentation building on ReadTheDocs (`#3221 <https://github.com/aio-libs/aiohttp/pull/3221>`_)


3.4.0 (2018-08-25)
==================

Features
--------

- Add type hints (`#3049 <https://github.com/aio-libs/aiohttp/pull/3049>`_)
- Add ``raise_for_status`` request parameter (`#3073 <https://github.com/aio-libs/aiohttp/pull/3073>`_)
- Add type hints to HTTP client (`#3092 <https://github.com/aio-libs/aiohttp/pull/3092>`_)
- Minor server optimizations (`#3095 <https://github.com/aio-libs/aiohttp/pull/3095>`_)
- Preserve the cause when `HTTPException` is raised from another exception. (`#3096 <https://github.com/aio-libs/aiohttp/pull/3096>`_)
- Add `close_boundary` option in `MultipartWriter.write` method. Support streaming (`#3104 <https://github.com/aio-libs/aiohttp/pull/3104>`_)
- Added a ``remove_slash`` option to the ``normalize_path_middleware`` factory. (`#3173 <https://github.com/aio-libs/aiohttp/pull/3173>`_)
- The class `AbstractRouteDef` is importable from `aiohttp.web`. (`#3183 <https://github.com/aio-libs/aiohttp/pull/3183>`_)


Bugfixes
--------

- Prevent double closing when client connection is released before the
  last ``data_received()`` callback. (`#3031 <https://github.com/aio-libs/aiohttp/pull/3031>`_)
- Make redirect with `normalize_path_middleware` work when using url encoded paths. (`#3051 <https://github.com/aio-libs/aiohttp/pull/3051>`_)
- Postpone web task creation to connection establishment. (`#3052 <https://github.com/aio-libs/aiohttp/pull/3052>`_)
- Fix ``sock_read`` timeout. (`#3053 <https://github.com/aio-libs/aiohttp/pull/3053>`_)
- When using a server-request body as the `data=` argument of a client request, iterate over the content with `readany` instead of `readline` to avoid `Line too long` errors. (`#3054 <https://github.com/aio-libs/aiohttp/pull/3054>`_)
- fix `UrlDispatcher` has no attribute `add_options`, add `web.options` (`#3062 <https://github.com/aio-libs/aiohttp/pull/3062>`_)
- correct filename in content-disposition with multipart body (`#3064 <https://github.com/aio-libs/aiohttp/pull/3064>`_)
- Many HTTP proxies has buggy keepalive support.
  Let's not reuse connection but close it after processing every response. (`#3070 <https://github.com/aio-libs/aiohttp/pull/3070>`_)
- raise 413 "Payload Too Large" rather than raising ValueError in request.post()
  Add helpful debug message to 413 responses (`#3087 <https://github.com/aio-libs/aiohttp/pull/3087>`_)
- Fix `StreamResponse` equality, now that they are `MutableMapping` objects. (`#3100 <https://github.com/aio-libs/aiohttp/pull/3100>`_)
- Fix server request objects comparison (`#3116 <https://github.com/aio-libs/aiohttp/pull/3116>`_)
- Do not hang on `206 Partial Content` response with `Content-Encoding: gzip` (`#3123 <https://github.com/aio-libs/aiohttp/pull/3123>`_)
- Fix timeout precondition checkers (`#3145 <https://github.com/aio-libs/aiohttp/pull/3145>`_)


Improved Documentation
----------------------

- Add a new FAQ entry that clarifies that you should not reuse response
  objects in middleware functions. (`#3020 <https://github.com/aio-libs/aiohttp/pull/3020>`_)
- Add FAQ section "Why is creating a ClientSession outside of an event loop dangerous?" (`#3072 <https://github.com/aio-libs/aiohttp/pull/3072>`_)
- Fix link to Rambler (`#3115 <https://github.com/aio-libs/aiohttp/pull/3115>`_)
- Fix TCPSite documentation on the Server Reference page. (`#3146 <https://github.com/aio-libs/aiohttp/pull/3146>`_)
- Fix documentation build configuration file for Windows. (`#3147 <https://github.com/aio-libs/aiohttp/pull/3147>`_)
- Remove no longer existing lingering_timeout parameter of Application.make_handler from documentation. (`#3151 <https://github.com/aio-libs/aiohttp/pull/3151>`_)
- Mention that ``app.make_handler`` is deprecated, recommend to use runners
  API instead. (`#3157 <https://github.com/aio-libs/aiohttp/pull/3157>`_)


Deprecations and Removals
-------------------------

- Drop ``loop.current_task()`` from ``helpers.current_task()`` (`#2826 <https://github.com/aio-libs/aiohttp/pull/2826>`_)
- Drop ``reader`` parameter from ``request.multipart()``. (`#3090 <https://github.com/aio-libs/aiohttp/pull/3090>`_)


3.3.2 (2018-06-12)
==================

- Many HTTP proxies has buggy keepalive support. Let's not reuse connection but
  close it after processing every response. (`#3070 <https://github.com/aio-libs/aiohttp/pull/3070>`_)

- Provide vendor source files in tarball (`#3076 <https://github.com/aio-libs/aiohttp/pull/3076>`_)


3.3.1 (2018-06-05)
==================

- Fix ``sock_read`` timeout. (`#3053 <https://github.com/aio-libs/aiohttp/pull/3053>`_)
- When using a server-request body as the ``data=`` argument of a client request,
  iterate over the content with ``readany`` instead of ``readline`` to avoid ``Line
  too long`` errors. (`#3054 <https://github.com/aio-libs/aiohttp/pull/3054>`_)


3.3.0 (2018-06-01)
==================

Features
--------

- Raise ``ConnectionResetError`` instead of ``CancelledError`` on trying to
  write to a closed stream. (`#2499 <https://github.com/aio-libs/aiohttp/pull/2499>`_)
- Implement ``ClientTimeout`` class and support socket read timeout. (`#2768 <https://github.com/aio-libs/aiohttp/pull/2768>`_)
- Enable logging when ``aiohttp.web`` is used as a program (`#2956 <https://github.com/aio-libs/aiohttp/pull/2956>`_)
- Add canonical property to resources (`#2968 <https://github.com/aio-libs/aiohttp/pull/2968>`_)
- Forbid reading response BODY after release (`#2983 <https://github.com/aio-libs/aiohttp/pull/2983>`_)
- Implement base protocol class to avoid a dependency from internal
  ``asyncio.streams.FlowControlMixin`` (`#2986 <https://github.com/aio-libs/aiohttp/pull/2986>`_)
- Cythonize ``@helpers.reify``, 5% boost on macro benchmark (`#2995 <https://github.com/aio-libs/aiohttp/pull/2995>`_)
- Optimize HTTP parser (`#3015 <https://github.com/aio-libs/aiohttp/pull/3015>`_)
- Implement ``runner.addresses`` property. (`#3036 <https://github.com/aio-libs/aiohttp/pull/3036>`_)
- Use ``bytearray`` instead of a list of ``bytes`` in websocket reader. It
  improves websocket message reading a little. (`#3039 <https://github.com/aio-libs/aiohttp/pull/3039>`_)
- Remove heartbeat on closing connection on keepalive timeout. The used hack
  violates HTTP protocol. (`#3041 <https://github.com/aio-libs/aiohttp/pull/3041>`_)
- Limit websocket message size on reading to 4 MB by default. (`#3045 <https://github.com/aio-libs/aiohttp/pull/3045>`_)


Bugfixes
--------

- Don't reuse a connection with the same URL but different proxy/TLS settings
  (`#2981 <https://github.com/aio-libs/aiohttp/pull/2981>`_)
- When parsing the Forwarded header, the optional port number is now preserved.
  (`#3009 <https://github.com/aio-libs/aiohttp/pull/3009>`_)


Improved Documentation
----------------------

- Make Change Log more visible in docs (`#3029 <https://github.com/aio-libs/aiohttp/pull/3029>`_)
- Make style and grammar improvements on the FAQ page. (`#3030 <https://github.com/aio-libs/aiohttp/pull/3030>`_)
- Document that signal handlers should be async functions since aiohttp 3.0
  (`#3032 <https://github.com/aio-libs/aiohttp/pull/3032>`_)


Deprecations and Removals
-------------------------

- Deprecate custom application's router. (`#3021 <https://github.com/aio-libs/aiohttp/pull/3021>`_)


Misc
----

- #3008, #3011


3.2.1 (2018-05-10)
==================

- Don't reuse a connection with the same URL but different proxy/TLS settings
  (`#2981 <https://github.com/aio-libs/aiohttp/pull/2981>`_)


3.2.0 (2018-05-06)
==================

Features
--------

- Raise ``TooManyRedirects`` exception when client gets redirected too many
  times instead of returning last response. (`#2631 <https://github.com/aio-libs/aiohttp/pull/2631>`_)
- Extract route definitions into separate ``web_routedef.py`` file (`#2876 <https://github.com/aio-libs/aiohttp/pull/2876>`_)
- Raise an exception on request body reading after sending response. (`#2895 <https://github.com/aio-libs/aiohttp/pull/2895>`_)
- ClientResponse and RequestInfo now have real_url property, which is request
  url without fragment part being stripped (`#2925 <https://github.com/aio-libs/aiohttp/pull/2925>`_)
- Speed up connector limiting (`#2937 <https://github.com/aio-libs/aiohttp/pull/2937>`_)
- Added and links property for ClientResponse object (`#2948 <https://github.com/aio-libs/aiohttp/pull/2948>`_)
- Add ``request.config_dict`` for exposing nested applications data. (`#2949 <https://github.com/aio-libs/aiohttp/pull/2949>`_)
- Speed up HTTP headers serialization, server micro-benchmark runs 5% faster
  now. (`#2957 <https://github.com/aio-libs/aiohttp/pull/2957>`_)
- Apply assertions in debug mode only (`#2966 <https://github.com/aio-libs/aiohttp/pull/2966>`_)


Bugfixes
--------

- expose property `app` for TestClient (`#2891 <https://github.com/aio-libs/aiohttp/pull/2891>`_)
- Call on_chunk_sent when write_eof takes as a param the last chunk (`#2909 <https://github.com/aio-libs/aiohttp/pull/2909>`_)
- A closing bracket was added to `__repr__` of resources (`#2935 <https://github.com/aio-libs/aiohttp/pull/2935>`_)
- Fix compression of FileResponse (`#2942 <https://github.com/aio-libs/aiohttp/pull/2942>`_)
- Fixes some bugs in the limit connection feature (`#2964 <https://github.com/aio-libs/aiohttp/pull/2964>`_)


Improved Documentation
----------------------

- Drop ``async_timeout`` usage from documentation for client API in favor of
  ``timeout`` parameter. (`#2865 <https://github.com/aio-libs/aiohttp/pull/2865>`_)
- Improve Gunicorn logging documentation (`#2921 <https://github.com/aio-libs/aiohttp/pull/2921>`_)
- Replace multipart writer `.serialize()` method with `.write()` in
  documentation. (`#2965 <https://github.com/aio-libs/aiohttp/pull/2965>`_)


Deprecations and Removals
-------------------------

- Deprecate Application.make_handler() (`#2938 <https://github.com/aio-libs/aiohttp/pull/2938>`_)


Misc
----

- #2958


3.1.3 (2018-04-12)
==================

- Fix cancellation broadcast during DNS resolve (`#2910 <https://github.com/aio-libs/aiohttp/pull/2910>`_)


3.1.2 (2018-04-05)
==================

- Make ``LineTooLong`` exception more detailed about actual data size (`#2863 <https://github.com/aio-libs/aiohttp/pull/2863>`_)
- Call ``on_chunk_sent`` when write_eof takes as a param the last chunk (`#2909 <https://github.com/aio-libs/aiohttp/pull/2909>`_)


3.1.1 (2018-03-27)
==================

- Support *asynchronous iterators* (and *asynchronous generators* as
  well) in both client and server API as request / response BODY
  payloads. (`#2802 <https://github.com/aio-libs/aiohttp/pull/2802>`_)


3.1.0 (2018-03-21)
==================

Welcome to aiohttp 3.1 release.

This is an *incremental* release, fully backward compatible with *aiohttp 3.0*.

But we have added several new features.

The most visible one is ``app.add_routes()`` (an alias for existing
``app.router.add_routes()``. The addition is very important because
all *aiohttp* docs now uses ``app.add_routes()`` call in code
snippets. All your existing code still do register routes / resource
without any warning but you've got the idea for a favorite way: noisy
``app.router.add_get()`` is replaced by ``app.add_routes()``.

The library does not make a preference between decorators::

   routes = web.RouteTableDef()

   @routes.get('/')
   async def hello(request):
       return web.Response(text="Hello, world")

   app.add_routes(routes)

and route tables as a list::

   async def hello(request):
       return web.Response(text="Hello, world")

   app.add_routes([web.get('/', hello)])

Both ways are equal, user may decide basing on own code taste.

Also we have a lot of minor features, bug fixes and documentation
updates, see below.

Features
--------

- Relax JSON content-type checking in the ``ClientResponse.json()`` to allow
  "application/xxx+json" instead of strict "application/json". (`#2206 <https://github.com/aio-libs/aiohttp/pull/2206>`_)
- Bump C HTTP parser to version 2.8 (`#2730 <https://github.com/aio-libs/aiohttp/pull/2730>`_)
- Accept a coroutine as an application factory in ``web.run_app`` and gunicorn
  worker. (`#2739 <https://github.com/aio-libs/aiohttp/pull/2739>`_)
- Implement application cleanup context (``app.cleanup_ctx`` property). (`#2747 <https://github.com/aio-libs/aiohttp/pull/2747>`_)
- Make ``writer.write_headers`` a coroutine. (`#2762 <https://github.com/aio-libs/aiohttp/pull/2762>`_)
- Add tracking signals for getting request/response bodies. (`#2767 <https://github.com/aio-libs/aiohttp/pull/2767>`_)
- Deprecate ClientResponseError.code in favor of .status to keep similarity
  with response classes. (`#2781 <https://github.com/aio-libs/aiohttp/pull/2781>`_)
- Implement ``app.add_routes()`` method. (`#2787 <https://github.com/aio-libs/aiohttp/pull/2787>`_)
- Implement ``web.static()`` and ``RouteTableDef.static()`` API. (`#2795 <https://github.com/aio-libs/aiohttp/pull/2795>`_)
- Install a test event loop as default by ``asyncio.set_event_loop()``. The
  change affects aiohttp test utils but backward compatibility is not broken
  for 99.99% of use cases. (`#2804 <https://github.com/aio-libs/aiohttp/pull/2804>`_)
- Refactor ``ClientResponse`` constructor: make logically required constructor
  arguments mandatory, drop ``_post_init()`` method. (`#2820 <https://github.com/aio-libs/aiohttp/pull/2820>`_)
- Use ``app.add_routes()`` in server docs everywhere (`#2830 <https://github.com/aio-libs/aiohttp/pull/2830>`_)
- Websockets refactoring, all websocket writer methods are converted into
  coroutines. (`#2836 <https://github.com/aio-libs/aiohttp/pull/2836>`_)
- Provide ``Content-Range`` header for ``Range`` requests (`#2844 <https://github.com/aio-libs/aiohttp/pull/2844>`_)


Bugfixes
--------

- Fix websocket client return EofStream. (`#2784 <https://github.com/aio-libs/aiohttp/pull/2784>`_)
- Fix websocket demo. (`#2789 <https://github.com/aio-libs/aiohttp/pull/2789>`_)
- Property ``BaseRequest.http_range`` now returns a python-like slice when
  requesting the tail of the range. It's now indicated by a negative value in
  ``range.start`` rather then in ``range.stop`` (`#2805 <https://github.com/aio-libs/aiohttp/pull/2805>`_)
- Close a connection if an unexpected exception occurs while sending a request
  (`#2827 <https://github.com/aio-libs/aiohttp/pull/2827>`_)
- Fix firing DNS tracing events. (`#2841 <https://github.com/aio-libs/aiohttp/pull/2841>`_)


Improved Documentation
----------------------

- Document behavior when cchardet detects encodings that are unknown to Python.
  (`#2732 <https://github.com/aio-libs/aiohttp/pull/2732>`_)
- Add diagrams for tracing request life style. (`#2748 <https://github.com/aio-libs/aiohttp/pull/2748>`_)
- Drop removed functionality for passing ``StreamReader`` as data at client
  side. (`#2793 <https://github.com/aio-libs/aiohttp/pull/2793>`_)

3.0.9 (2018-03-14)
==================

- Close a connection if an unexpected exception occurs while sending a request
  (`#2827 <https://github.com/aio-libs/aiohttp/pull/2827>`_)


3.0.8 (2018-03-12)
==================

- Use ``asyncio.current_task()`` on Python 3.7 (`#2825 <https://github.com/aio-libs/aiohttp/pull/2825>`_)

3.0.7 (2018-03-08)
==================

- Fix SSL proxy support by client. (`#2810 <https://github.com/aio-libs/aiohttp/pull/2810>`_)
- Restore an imperative check in ``setup.py`` for python version. The check
  works in parallel to environment marker. As effect an error about unsupported
  Python versions is raised even on outdated systems with very old
  ``setuptools`` version installed. (`#2813 <https://github.com/aio-libs/aiohttp/pull/2813>`_)


3.0.6 (2018-03-05)
==================

- Add ``_reuse_address`` and ``_reuse_port`` to
  ``web_runner.TCPSite.__slots__``. (`#2792 <https://github.com/aio-libs/aiohttp/pull/2792>`_)

3.0.5 (2018-02-27)
==================

- Fix ``InvalidStateError`` on processing a sequence of two
  ``RequestHandler.data_received`` calls on web server. (`#2773 <https://github.com/aio-libs/aiohttp/pull/2773>`_)

3.0.4 (2018-02-26)
==================

- Fix ``IndexError`` in HTTP request handling by server. (`#2752 <https://github.com/aio-libs/aiohttp/pull/2752>`_)
- Fix MultipartWriter.append* no longer returning part/payload. (`#2759 <https://github.com/aio-libs/aiohttp/pull/2759>`_)


3.0.3 (2018-02-25)
==================

- Relax ``attrs`` dependency to minimal actually supported version
  17.0.3 The change allows to avoid version conflicts with currently
  existing test tools.

3.0.2 (2018-02-23)
==================

Security Fix
------------

- Prevent Windows absolute URLs in static files.  Paths like
  ``/static/D:\path`` and ``/static/\\hostname\drive\path`` are
  forbidden.

3.0.1
=====

- Technical release for fixing distribution problems.

3.0.0 (2018-02-12)
==================

Features
--------

- Speed up the `PayloadWriter.write` method for large request bodies. (`#2126 <https://github.com/aio-libs/aiohttp/pull/2126>`_)
- StreamResponse and Response are now MutableMappings. (`#2246 <https://github.com/aio-libs/aiohttp/pull/2246>`_)
- ClientSession publishes a set of signals to track the HTTP request execution.
  (`#2313 <https://github.com/aio-libs/aiohttp/pull/2313>`_)
- Content-Disposition fast access in ClientResponse (`#2455 <https://github.com/aio-libs/aiohttp/pull/2455>`_)
- Added support to Flask-style decorators with class-based Views. (`#2472 <https://github.com/aio-libs/aiohttp/pull/2472>`_)
- Signal handlers (registered callbacks) should be coroutines. (`#2480 <https://github.com/aio-libs/aiohttp/pull/2480>`_)
- Support ``async with test_client.ws_connect(...)`` (`#2525 <https://github.com/aio-libs/aiohttp/pull/2525>`_)
- Introduce *site* and *application runner* as underlying API for `web.run_app`
  implementation. (`#2530 <https://github.com/aio-libs/aiohttp/pull/2530>`_)
- Only quote multipart boundary when necessary and sanitize input (`#2544 <https://github.com/aio-libs/aiohttp/pull/2544>`_)
- Make the `aiohttp.ClientResponse.get_encoding` method public with the
  processing of invalid charset while detecting content encoding. (`#2549 <https://github.com/aio-libs/aiohttp/pull/2549>`_)
- Add optional configurable per message compression for
  `ClientWebSocketResponse` and `WebSocketResponse`. (`#2551 <https://github.com/aio-libs/aiohttp/pull/2551>`_)
- Add hysteresis to `StreamReader` to prevent flipping between paused and
  resumed states too often. (`#2555 <https://github.com/aio-libs/aiohttp/pull/2555>`_)
- Support `.netrc` by `trust_env` (`#2581 <https://github.com/aio-libs/aiohttp/pull/2581>`_)
- Avoid to create a new resource when adding a route with the same name and
  path of the last added resource (`#2586 <https://github.com/aio-libs/aiohttp/pull/2586>`_)
- `MultipartWriter.boundary` is `str` now. (`#2589 <https://github.com/aio-libs/aiohttp/pull/2589>`_)
- Allow a custom port to be used by `TestServer` (and associated pytest
  fixtures) (`#2613 <https://github.com/aio-libs/aiohttp/pull/2613>`_)
- Add param access_log_class to web.run_app function (`#2615 <https://github.com/aio-libs/aiohttp/pull/2615>`_)
- Add ``ssl`` parameter to client API (`#2626 <https://github.com/aio-libs/aiohttp/pull/2626>`_)
- Fixes performance issue introduced by #2577. When there are no middlewares
  installed by the user, no additional and useless code is executed. (`#2629 <https://github.com/aio-libs/aiohttp/pull/2629>`_)
- Rename PayloadWriter to StreamWriter (`#2654 <https://github.com/aio-libs/aiohttp/pull/2654>`_)
- New options *reuse_port*, *reuse_address* are added to `run_app` and
  `TCPSite`. (`#2679 <https://github.com/aio-libs/aiohttp/pull/2679>`_)
- Use custom classes to pass client signals parameters (`#2686 <https://github.com/aio-libs/aiohttp/pull/2686>`_)
- Use ``attrs`` library for data classes, replace `namedtuple`. (`#2690 <https://github.com/aio-libs/aiohttp/pull/2690>`_)
- Pytest fixtures renaming, add ``aiohttp_`` prefix (`#2578 <https://github.com/aio-libs/aiohttp/pull/2578>`_)
- Add ``aiohttp-`` prefix for ``pytest-aiohttp`` command line
  parameters (`#2578 <https://github.com/aio-libs/aiohttp/pull/2578>`_)

Bugfixes
--------

- Correctly process upgrade request from server to HTTP2. ``aiohttp`` does not
  support HTTP2 yet, the protocol is not upgraded but response is handled
  correctly. (`#2277 <https://github.com/aio-libs/aiohttp/pull/2277>`_)
- Fix ClientConnectorSSLError and ClientProxyConnectionError for proxy
  connector (`#2408 <https://github.com/aio-libs/aiohttp/pull/2408>`_)
- Fix connector convert OSError to ClientConnectorError (`#2423 <https://github.com/aio-libs/aiohttp/pull/2423>`_)
- Fix connection attempts for multiple dns hosts (`#2424 <https://github.com/aio-libs/aiohttp/pull/2424>`_)
- Fix writing to closed transport by raising `asyncio.CancelledError` (`#2499 <https://github.com/aio-libs/aiohttp/pull/2499>`_)
- Fix warning in `ClientSession.__del__` by stopping to try to close it.
  (`#2523 <https://github.com/aio-libs/aiohttp/pull/2523>`_)
- Fixed race-condition for iterating addresses from the DNSCache. (`#2620 <https://github.com/aio-libs/aiohttp/pull/2620>`_)
- Fix default value of `access_log_format` argument in `web.run_app` (`#2649 <https://github.com/aio-libs/aiohttp/pull/2649>`_)
- Freeze sub-application on adding to parent app (`#2656 <https://github.com/aio-libs/aiohttp/pull/2656>`_)
- Do percent encoding for `.url_for()` parameters (`#2668 <https://github.com/aio-libs/aiohttp/pull/2668>`_)
- Correctly process request start time and multiple request/response
  headers in access log extra (`#2641 <https://github.com/aio-libs/aiohttp/pull/2641>`_)

Improved Documentation
----------------------

- Improve tutorial docs, using `literalinclude` to link to the actual files.
  (`#2396 <https://github.com/aio-libs/aiohttp/pull/2396>`_)
- Small improvement docs: better example for file uploads. (`#2401 <https://github.com/aio-libs/aiohttp/pull/2401>`_)
- Rename `from_env` to `trust_env` in client reference. (`#2451 <https://github.com/aio-libs/aiohttp/pull/2451>`_)
- ﻿Fixed mistype in `Proxy Support` section where `trust_env` parameter was
  used in `session.get("http://python.org", trust_env=True)` method instead of
  aiohttp.ClientSession constructor as follows:
  `aiohttp.ClientSession(trust_env=True)`. (`#2688 <https://github.com/aio-libs/aiohttp/pull/2688>`_)
- Fix issue with unittest example not compiling in testing docs. (`#2717 <https://github.com/aio-libs/aiohttp/pull/2717>`_)

Deprecations and Removals
-------------------------

- Simplify HTTP pipelining implementation (`#2109 <https://github.com/aio-libs/aiohttp/pull/2109>`_)
- Drop `StreamReaderPayload` and `DataQueuePayload`. (`#2257 <https://github.com/aio-libs/aiohttp/pull/2257>`_)
- Drop `md5` and `sha1` finger-prints (`#2267 <https://github.com/aio-libs/aiohttp/pull/2267>`_)
- Drop WSMessage.tp (`#2321 <https://github.com/aio-libs/aiohttp/pull/2321>`_)
- Drop Python 3.4 and Python 3.5.0, 3.5.1, 3.5.2. Minimal supported Python
  versions are 3.5.3 and 3.6.0. `yield from` is gone, use `async/await` syntax.
  (`#2343 <https://github.com/aio-libs/aiohttp/pull/2343>`_)
- Drop `aiohttp.Timeout` and use `async_timeout.timeout` instead. (`#2348 <https://github.com/aio-libs/aiohttp/pull/2348>`_)
- Drop `resolve` param from TCPConnector. (`#2377 <https://github.com/aio-libs/aiohttp/pull/2377>`_)
- Add DeprecationWarning for returning HTTPException (`#2415 <https://github.com/aio-libs/aiohttp/pull/2415>`_)
- `send_str()`, `send_bytes()`, `send_json()`, `ping()` and `pong()` are
  genuine async functions now. (`#2475 <https://github.com/aio-libs/aiohttp/pull/2475>`_)
- Drop undocumented `app.on_pre_signal` and `app.on_post_signal`. Signal
  handlers should be coroutines, support for regular functions is dropped.
  (`#2480 <https://github.com/aio-libs/aiohttp/pull/2480>`_)
- `StreamResponse.drain()` is not a part of public API anymore, just use `await
  StreamResponse.write()`. `StreamResponse.write` is converted to async
  function. (`#2483 <https://github.com/aio-libs/aiohttp/pull/2483>`_)
- Drop deprecated `slow_request_timeout` param and `**kwargs`` from
  `RequestHandler`. (`#2500 <https://github.com/aio-libs/aiohttp/pull/2500>`_)
- Drop deprecated `resource.url()`. (`#2501 <https://github.com/aio-libs/aiohttp/pull/2501>`_)
- Remove `%u` and `%l` format specifiers from access log format. (`#2506 <https://github.com/aio-libs/aiohttp/pull/2506>`_)
- Drop deprecated `request.GET` property. (`#2547 <https://github.com/aio-libs/aiohttp/pull/2547>`_)
- Simplify stream classes: drop `ChunksQueue` and `FlowControlChunksQueue`,
  merge `FlowControlStreamReader` functionality into `StreamReader`, drop
  `FlowControlStreamReader` name. (`#2555 <https://github.com/aio-libs/aiohttp/pull/2555>`_)
- Do not create a new resource on `router.add_get(..., allow_head=True)`
  (`#2585 <https://github.com/aio-libs/aiohttp/pull/2585>`_)
- Drop access to TCP tuning options from PayloadWriter and Response classes
  (`#2604 <https://github.com/aio-libs/aiohttp/pull/2604>`_)
- Drop deprecated `encoding` parameter from client API (`#2606 <https://github.com/aio-libs/aiohttp/pull/2606>`_)
- Deprecate ``verify_ssl``, ``ssl_context`` and ``fingerprint`` parameters in
  client API (`#2626 <https://github.com/aio-libs/aiohttp/pull/2626>`_)
- Get rid of the legacy class StreamWriter. (`#2651 <https://github.com/aio-libs/aiohttp/pull/2651>`_)
- Forbid non-strings in `resource.url_for()` parameters. (`#2668 <https://github.com/aio-libs/aiohttp/pull/2668>`_)
- Deprecate inheritance from ``ClientSession`` and ``web.Application`` and
  custom user attributes for ``ClientSession``, ``web.Request`` and
  ``web.Application`` (`#2691 <https://github.com/aio-libs/aiohttp/pull/2691>`_)
- Drop `resp = await aiohttp.request(...)` syntax for sake of `async with
  aiohttp.request(...) as resp:`. (`#2540 <https://github.com/aio-libs/aiohttp/pull/2540>`_)
- Forbid synchronous context managers for `ClientSession` and test
  server/client. (`#2362 <https://github.com/aio-libs/aiohttp/pull/2362>`_)


Misc
----

- #2552


2.3.10 (2018-02-02)
===================

- Fix 100% CPU usage on HTTP GET and websocket connection just after it (`#1955 <https://github.com/aio-libs/aiohttp/pull/1955>`_)

- Patch broken `ssl.match_hostname()` on Python<3.7 (`#2674 <https://github.com/aio-libs/aiohttp/pull/2674>`_)

2.3.9 (2018-01-16)
==================

- Fix colon handing in path for dynamic resources (`#2670 <https://github.com/aio-libs/aiohttp/pull/2670>`_)

2.3.8 (2018-01-15)
==================

- Do not use `yarl.unquote` internal function in aiohttp.  Fix
  incorrectly unquoted path part in URL dispatcher (`#2662 <https://github.com/aio-libs/aiohttp/pull/2662>`_)

- Fix compatibility with `yarl==1.0.0` (`#2662 <https://github.com/aio-libs/aiohttp/pull/2662>`_)

2.3.7 (2017-12-27)
==================

- Fixed race-condition for iterating addresses from the DNSCache. (`#2620 <https://github.com/aio-libs/aiohttp/pull/2620>`_)
- Fix docstring for request.host (`#2591 <https://github.com/aio-libs/aiohttp/pull/2591>`_)
- Fix docstring for request.remote (`#2592 <https://github.com/aio-libs/aiohttp/pull/2592>`_)


2.3.6 (2017-12-04)
==================

- Correct `request.app` context (for handlers not just middlewares). (`#2577 <https://github.com/aio-libs/aiohttp/pull/2577>`_)


2.3.5 (2017-11-30)
==================

- Fix compatibility with `pytest` 3.3+ (`#2565 <https://github.com/aio-libs/aiohttp/pull/2565>`_)


2.3.4 (2017-11-29)
==================

- Make `request.app` point to proper application instance when using nested
  applications (with middlewares). (`#2550 <https://github.com/aio-libs/aiohttp/pull/2550>`_)
- Change base class of ClientConnectorSSLError to ClientSSLError from
  ClientConnectorError. (`#2563 <https://github.com/aio-libs/aiohttp/pull/2563>`_)
- Return client connection back to free pool on error in `connector.connect()`.
  (`#2567 <https://github.com/aio-libs/aiohttp/pull/2567>`_)


2.3.3 (2017-11-17)
==================

- Having a `;` in Response content type does not assume it contains a charset
  anymore. (`#2197 <https://github.com/aio-libs/aiohttp/pull/2197>`_)
- Use `getattr(asyncio, 'async')` for keeping compatibility with Python 3.7.
  (`#2476 <https://github.com/aio-libs/aiohttp/pull/2476>`_)
- Ignore `NotImplementedError` raised by `set_child_watcher` from `uvloop`.
  (`#2491 <https://github.com/aio-libs/aiohttp/pull/2491>`_)
- Fix warning in `ClientSession.__del__` by stopping to try to close it.
  (`#2523 <https://github.com/aio-libs/aiohttp/pull/2523>`_)
- Fixed typo's in Third-party libraries page. And added async-v20 to the list
  (`#2510 <https://github.com/aio-libs/aiohttp/pull/2510>`_)


2.3.2 (2017-11-01)
==================

- Fix passing client max size on cloning request obj. (`#2385 <https://github.com/aio-libs/aiohttp/pull/2385>`_)
- Fix ClientConnectorSSLError and ClientProxyConnectionError for proxy
  connector. (`#2408 <https://github.com/aio-libs/aiohttp/pull/2408>`_)
- Drop generated `_http_parser` shared object from tarball distribution. (`#2414 <https://github.com/aio-libs/aiohttp/pull/2414>`_)
- Fix connector convert OSError to ClientConnectorError. (`#2423 <https://github.com/aio-libs/aiohttp/pull/2423>`_)
- Fix connection attempts for multiple dns hosts. (`#2424 <https://github.com/aio-libs/aiohttp/pull/2424>`_)
- Fix ValueError for AF_INET6 sockets if a preexisting INET6 socket to the
  `aiohttp.web.run_app` function. (`#2431 <https://github.com/aio-libs/aiohttp/pull/2431>`_)
- `_SessionRequestContextManager` closes the session properly now. (`#2441 <https://github.com/aio-libs/aiohttp/pull/2441>`_)
- Rename `from_env` to `trust_env` in client reference. (`#2451 <https://github.com/aio-libs/aiohttp/pull/2451>`_)


2.3.1 (2017-10-18)
==================

- Relax attribute lookup in warning about old-styled middleware (`#2340 <https://github.com/aio-libs/aiohttp/pull/2340>`_)


2.3.0 (2017-10-18)
==================

Features
--------

- Add SSL related params to `ClientSession.request` (`#1128 <https://github.com/aio-libs/aiohttp/pull/1128>`_)
- Make enable_compression work on HTTP/1.0 (`#1828 <https://github.com/aio-libs/aiohttp/pull/1828>`_)
- Deprecate registering synchronous web handlers (`#1993 <https://github.com/aio-libs/aiohttp/pull/1993>`_)
- Switch to `multidict 3.0`. All HTTP headers preserve casing now but compared
  in case-insensitive way. (`#1994 <https://github.com/aio-libs/aiohttp/pull/1994>`_)
- Improvement for `normalize_path_middleware`. Added possibility to handle URLs
  with query string. (`#1995 <https://github.com/aio-libs/aiohttp/pull/1995>`_)
- Use towncrier for CHANGES.txt build (`#1997 <https://github.com/aio-libs/aiohttp/pull/1997>`_)
- Implement `trust_env=True` param in `ClientSession`. (`#1998 <https://github.com/aio-libs/aiohttp/pull/1998>`_)
- Added variable to customize proxy headers (`#2001 <https://github.com/aio-libs/aiohttp/pull/2001>`_)
- Implement `router.add_routes` and router decorators. (`#2004 <https://github.com/aio-libs/aiohttp/pull/2004>`_)
- Deprecated `BaseRequest.has_body` in favor of
  `BaseRequest.can_read_body` Added `BaseRequest.body_exists`
  attribute that stays static for the lifetime of the request (`#2005 <https://github.com/aio-libs/aiohttp/pull/2005>`_)
- Provide `BaseRequest.loop` attribute (`#2024 <https://github.com/aio-libs/aiohttp/pull/2024>`_)
- Make `_CoroGuard` awaitable and fix `ClientSession.close` warning message
  (`#2026 <https://github.com/aio-libs/aiohttp/pull/2026>`_)
- Responses to redirects without Location header are returned instead of
  raising a RuntimeError (`#2030 <https://github.com/aio-libs/aiohttp/pull/2030>`_)
- Added `get_client`, `get_server`, `setUpAsync` and `tearDownAsync` methods to
  AioHTTPTestCase (`#2032 <https://github.com/aio-libs/aiohttp/pull/2032>`_)
- Add automatically a SafeChildWatcher to the test loop (`#2058 <https://github.com/aio-libs/aiohttp/pull/2058>`_)
- add ability to disable automatic response decompression (`#2110 <https://github.com/aio-libs/aiohttp/pull/2110>`_)
- Add support for throttling DNS request, avoiding the requests saturation when
  there is a miss in the DNS cache and many requests getting into the connector
  at the same time. (`#2111 <https://github.com/aio-libs/aiohttp/pull/2111>`_)
- Use request for getting access log information instead of message/transport
  pair. Add `RequestBase.remote` property for accessing to IP of client
  initiated HTTP request. (`#2123 <https://github.com/aio-libs/aiohttp/pull/2123>`_)
- json() raises a ContentTypeError exception if the content-type does not meet
  the requirements instead of raising a generic ClientResponseError. (`#2136 <https://github.com/aio-libs/aiohttp/pull/2136>`_)
- Make the HTTP client able to return HTTP chunks when chunked transfer
  encoding is used. (`#2150 <https://github.com/aio-libs/aiohttp/pull/2150>`_)
- add `append_version` arg into `StaticResource.url` and
  `StaticResource.url_for` methods for getting an url with hash (version) of
  the file. (`#2157 <https://github.com/aio-libs/aiohttp/pull/2157>`_)
- Fix parsing the Forwarded header. * commas and semicolons are allowed inside
  quoted-strings; * empty forwarded-pairs (as in for=_1;;by=_2) are allowed; *
  non-standard parameters are allowed (although this alone could be easily done
  in the previous parser). (`#2173 <https://github.com/aio-libs/aiohttp/pull/2173>`_)
- Don't require ssl module to run. aiohttp does not require SSL to function.
  The code paths involved with SSL will only be hit upon SSL usage. Raise
  `RuntimeError` if HTTPS protocol is required but ssl module is not present.
  (`#2221 <https://github.com/aio-libs/aiohttp/pull/2221>`_)
- Accept coroutine fixtures in pytest plugin (`#2223 <https://github.com/aio-libs/aiohttp/pull/2223>`_)
- Call `shutdown_asyncgens` before event loop closing on Python 3.6. (`#2227 <https://github.com/aio-libs/aiohttp/pull/2227>`_)
- Speed up Signals when there are no receivers (`#2229 <https://github.com/aio-libs/aiohttp/pull/2229>`_)
- Raise `InvalidURL` instead of `ValueError` on fetches with invalid URL.
  (`#2241 <https://github.com/aio-libs/aiohttp/pull/2241>`_)
- Move `DummyCookieJar` into `cookiejar.py` (`#2242 <https://github.com/aio-libs/aiohttp/pull/2242>`_)
- `run_app`: Make `print=None` disable printing (`#2260 <https://github.com/aio-libs/aiohttp/pull/2260>`_)
- Support `brotli` encoding (generic-purpose lossless compression algorithm)
  (`#2270 <https://github.com/aio-libs/aiohttp/pull/2270>`_)
- Add server support for WebSockets Per-Message Deflate. Add client option to
  add deflate compress header in WebSockets request header. If calling
  ClientSession.ws_connect() with `compress=15` the client will support deflate
  compress negotiation. (`#2273 <https://github.com/aio-libs/aiohttp/pull/2273>`_)
- Support `verify_ssl`, `fingerprint`, `ssl_context` and `proxy_headers` by
  `client.ws_connect`. (`#2292 <https://github.com/aio-libs/aiohttp/pull/2292>`_)
- Added `aiohttp.ClientConnectorSSLError` when connection fails due
  `ssl.SSLError` (`#2294 <https://github.com/aio-libs/aiohttp/pull/2294>`_)
- `aiohttp.web.Application.make_handler` support `access_log_class` (`#2315 <https://github.com/aio-libs/aiohttp/pull/2315>`_)
- Build HTTP parser extension in non-strict mode by default. (`#2332 <https://github.com/aio-libs/aiohttp/pull/2332>`_)


Bugfixes
--------

- Clear auth information on redirecting to other domain (`#1699 <https://github.com/aio-libs/aiohttp/pull/1699>`_)
- Fix missing app.loop on startup hooks during tests (`#2060 <https://github.com/aio-libs/aiohttp/pull/2060>`_)
- Fix issue with synchronous session closing when using `ClientSession` as an
  asynchronous context manager. (`#2063 <https://github.com/aio-libs/aiohttp/pull/2063>`_)
- Fix issue with `CookieJar` incorrectly expiring cookies in some edge cases.
  (`#2084 <https://github.com/aio-libs/aiohttp/pull/2084>`_)
- Force use of IPv4 during test, this will make tests run in a Docker container
  (`#2104 <https://github.com/aio-libs/aiohttp/pull/2104>`_)
- Warnings about unawaited coroutines now correctly point to the user's code.
  (`#2106 <https://github.com/aio-libs/aiohttp/pull/2106>`_)
- Fix issue with `IndexError` being raised by the `StreamReader.iter_chunks()`
  generator. (`#2112 <https://github.com/aio-libs/aiohttp/pull/2112>`_)
- Support HTTP 308 Permanent redirect in client class. (`#2114 <https://github.com/aio-libs/aiohttp/pull/2114>`_)
- Fix `FileResponse` sending empty chunked body on 304. (`#2143 <https://github.com/aio-libs/aiohttp/pull/2143>`_)
- Do not add `Content-Length: 0` to GET/HEAD/TRACE/OPTIONS requests by default.
  (`#2167 <https://github.com/aio-libs/aiohttp/pull/2167>`_)
- Fix parsing the Forwarded header according to RFC 7239. (`#2170 <https://github.com/aio-libs/aiohttp/pull/2170>`_)
- Securely determining remote/scheme/host #2171 (`#2171 <https://github.com/aio-libs/aiohttp/pull/2171>`_)
- Fix header name parsing, if name is split into multiple lines (`#2183 <https://github.com/aio-libs/aiohttp/pull/2183>`_)
- Handle session close during connection, `KeyError:
  <aiohttp.connector._TransportPlaceholder>` (`#2193 <https://github.com/aio-libs/aiohttp/pull/2193>`_)
- Fixes uncaught `TypeError` in `helpers.guess_filename` if `name` is not a
  string (`#2201 <https://github.com/aio-libs/aiohttp/pull/2201>`_)
- Raise OSError on async DNS lookup if resolved domain is an alias for another
  one, which does not have an A or CNAME record. (`#2231 <https://github.com/aio-libs/aiohttp/pull/2231>`_)
- Fix incorrect warning in `StreamReader`. (`#2251 <https://github.com/aio-libs/aiohttp/pull/2251>`_)
- Properly clone state of web request (`#2284 <https://github.com/aio-libs/aiohttp/pull/2284>`_)
- Fix C HTTP parser for cases when status line is split into different TCP
  packets. (`#2311 <https://github.com/aio-libs/aiohttp/pull/2311>`_)
- Fix `web.FileResponse` overriding user supplied Content-Type (`#2317 <https://github.com/aio-libs/aiohttp/pull/2317>`_)


Improved Documentation
----------------------

- Add a note about possible performance degradation in `await resp.text()` if
  charset was not provided by `Content-Type` HTTP header. Pass explicit
  encoding to solve it. (`#1811 <https://github.com/aio-libs/aiohttp/pull/1811>`_)
- Drop `disqus` widget from documentation pages. (`#2018 <https://github.com/aio-libs/aiohttp/pull/2018>`_)
- Add a graceful shutdown section to the client usage documentation. (`#2039 <https://github.com/aio-libs/aiohttp/pull/2039>`_)
- Document `connector_owner` parameter. (`#2072 <https://github.com/aio-libs/aiohttp/pull/2072>`_)
- Update the doc of web.Application (`#2081 <https://github.com/aio-libs/aiohttp/pull/2081>`_)
- Fix mistake about access log disabling. (`#2085 <https://github.com/aio-libs/aiohttp/pull/2085>`_)
- Add example usage of on_startup and on_shutdown signals by creating and
  disposing an aiopg connection engine. (`#2131 <https://github.com/aio-libs/aiohttp/pull/2131>`_)
- Document `encoded=True` for `yarl.URL`, it disables all yarl transformations.
  (`#2198 <https://github.com/aio-libs/aiohttp/pull/2198>`_)
- Document that all app's middleware factories are run for every request.
  (`#2225 <https://github.com/aio-libs/aiohttp/pull/2225>`_)
- Reflect the fact that default resolver is threaded one starting from aiohttp
  1.1 (`#2228 <https://github.com/aio-libs/aiohttp/pull/2228>`_)


Deprecations and Removals
-------------------------

- Drop deprecated `Server.finish_connections` (`#2006 <https://github.com/aio-libs/aiohttp/pull/2006>`_)
- Drop %O format from logging, use %b instead. Drop %e format from logging,
  environment variables are not supported anymore. (`#2123 <https://github.com/aio-libs/aiohttp/pull/2123>`_)
- Drop deprecated secure_proxy_ssl_header support (`#2171 <https://github.com/aio-libs/aiohttp/pull/2171>`_)
- Removed TimeService in favor of simple caching. TimeService also had a bug
  where it lost about 0.5 seconds per second. (`#2176 <https://github.com/aio-libs/aiohttp/pull/2176>`_)
- Drop unused response_factory from static files API (`#2290 <https://github.com/aio-libs/aiohttp/pull/2290>`_)


Misc
----

- #2013, #2014, #2048, #2094, #2149, #2187, #2214, #2225, #2243, #2248


2.2.5 (2017-08-03)
==================

- Don't raise deprecation warning on
  `loop.run_until_complete(client.close())` (`#2065 <https://github.com/aio-libs/aiohttp/pull/2065>`_)

2.2.4 (2017-08-02)
==================

- Fix issue with synchronous session closing when using ClientSession
  as an asynchronous context manager.  (`#2063 <https://github.com/aio-libs/aiohttp/pull/2063>`_)

2.2.3 (2017-07-04)
==================

- Fix `_CoroGuard` for python 3.4

2.2.2 (2017-07-03)
==================

- Allow `await session.close()` along with `yield from session.close()`


2.2.1 (2017-07-02)
==================

- Relax `yarl` requirement to 0.11+

- Backport #2026: `session.close` *is* a coroutine (`#2029 <https://github.com/aio-libs/aiohttp/pull/2029>`_)


2.2.0 (2017-06-20)
==================

- Add doc for add_head, update doc for add_get. (`#1944 <https://github.com/aio-libs/aiohttp/pull/1944>`_)

- Fixed consecutive calls for `Response.write_eof`.

- Retain method attributes (e.g. :code:`__doc__`) when registering synchronous
  handlers for resources. (`#1953 <https://github.com/aio-libs/aiohttp/pull/1953>`_)

- Added signal TERM handling in `run_app` to gracefully exit (`#1932 <https://github.com/aio-libs/aiohttp/pull/1932>`_)

- Fix websocket issues caused by frame fragmentation. (`#1962 <https://github.com/aio-libs/aiohttp/pull/1962>`_)

- Raise RuntimeError is you try to set the Content Length and enable
  chunked encoding at the same time (`#1941 <https://github.com/aio-libs/aiohttp/pull/1941>`_)

- Small update for `unittest_run_loop`

- Use CIMultiDict for ClientRequest.skip_auto_headers (`#1970 <https://github.com/aio-libs/aiohttp/pull/1970>`_)

- Fix wrong startup sequence: test server and `run_app()` are not raise
  `DeprecationWarning` now (`#1947 <https://github.com/aio-libs/aiohttp/pull/1947>`_)

- Make sure cleanup signal is sent if startup signal has been sent (`#1959 <https://github.com/aio-libs/aiohttp/pull/1959>`_)

- Fixed server keep-alive handler, could cause 100% cpu utilization (`#1955 <https://github.com/aio-libs/aiohttp/pull/1955>`_)

- Connection can be destroyed before response get processed if
  `await aiohttp.request(..)` is used (`#1981 <https://github.com/aio-libs/aiohttp/pull/1981>`_)

- MultipartReader does not work with -OO (`#1969 <https://github.com/aio-libs/aiohttp/pull/1969>`_)

- Fixed `ClientPayloadError` with blank `Content-Encoding` header (`#1931 <https://github.com/aio-libs/aiohttp/pull/1931>`_)

- Support `deflate` encoding implemented in `httpbin.org/deflate` (`#1918 <https://github.com/aio-libs/aiohttp/pull/1918>`_)

- Fix BadStatusLine caused by extra `CRLF` after `POST` data (`#1792 <https://github.com/aio-libs/aiohttp/pull/1792>`_)

- Keep a reference to `ClientSession` in response object (`#1985 <https://github.com/aio-libs/aiohttp/pull/1985>`_)

- Deprecate undocumented `app.on_loop_available` signal (`#1978 <https://github.com/aio-libs/aiohttp/pull/1978>`_)



2.1.0 (2017-05-26)
==================

- Added support for experimental `async-tokio` event loop written in Rust
  https://github.com/PyO3/tokio

- Write to transport ``\r\n`` before closing after keepalive timeout,
  otherwise client can not detect socket disconnection. (`#1883 <https://github.com/aio-libs/aiohttp/pull/1883>`_)

- Only call `loop.close` in `run_app` if the user did *not* supply a loop.
  Useful for allowing clients to specify their own cleanup before closing the
  asyncio loop if they wish to tightly control loop behavior

- Content disposition with semicolon in filename (`#917 <https://github.com/aio-libs/aiohttp/pull/917>`_)

- Added `request_info` to response object and `ClientResponseError`. (`#1733 <https://github.com/aio-libs/aiohttp/pull/1733>`_)

- Added `history` to `ClientResponseError`. (`#1741 <https://github.com/aio-libs/aiohttp/pull/1741>`_)

- Allow to disable redirect url re-quoting (`#1474 <https://github.com/aio-libs/aiohttp/pull/1474>`_)

- Handle RuntimeError from transport (`#1790 <https://github.com/aio-libs/aiohttp/pull/1790>`_)

- Dropped "%O" in access logger (`#1673 <https://github.com/aio-libs/aiohttp/pull/1673>`_)

- Added `args` and `kwargs` to `unittest_run_loop`. Useful with other
  decorators, for example `@patch`. (`#1803 <https://github.com/aio-libs/aiohttp/pull/1803>`_)

- Added `iter_chunks` to response.content object. (`#1805 <https://github.com/aio-libs/aiohttp/pull/1805>`_)

- Avoid creating TimerContext when there is no timeout to allow
  compatibility with Tornado. (`#1817 <https://github.com/aio-libs/aiohttp/pull/1817>`_) (`#1180 <https://github.com/aio-libs/aiohttp/pull/1180>`_)

- Add `proxy_from_env` to `ClientRequest` to read from environment
  variables. (`#1791 <https://github.com/aio-libs/aiohttp/pull/1791>`_)

- Add DummyCookieJar helper. (`#1830 <https://github.com/aio-libs/aiohttp/pull/1830>`_)

- Fix assertion errors in Python 3.4 from noop helper. (`#1847 <https://github.com/aio-libs/aiohttp/pull/1847>`_)

- Do not unquote `+` in match_info values (`#1816 <https://github.com/aio-libs/aiohttp/pull/1816>`_)

- Use Forwarded, X-Forwarded-Scheme and X-Forwarded-Host for better scheme and
  host resolution. (`#1134 <https://github.com/aio-libs/aiohttp/pull/1134>`_)

- Fix sub-application middlewares resolution order (`#1853 <https://github.com/aio-libs/aiohttp/pull/1853>`_)

- Fix applications comparison (`#1866 <https://github.com/aio-libs/aiohttp/pull/1866>`_)

- Fix static location in index when prefix is used (`#1662 <https://github.com/aio-libs/aiohttp/pull/1662>`_)

- Make test server more reliable (`#1896 <https://github.com/aio-libs/aiohttp/pull/1896>`_)

- Extend list of web exceptions, add HTTPUnprocessableEntity,
  HTTPFailedDependency, HTTPInsufficientStorage status codes (`#1920 <https://github.com/aio-libs/aiohttp/pull/1920>`_)


2.0.7 (2017-04-12)
==================

- Fix *pypi* distribution

- Fix exception description (`#1807 <https://github.com/aio-libs/aiohttp/pull/1807>`_)

- Handle socket error in FileResponse (`#1773 <https://github.com/aio-libs/aiohttp/pull/1773>`_)

- Cancel websocket heartbeat on close (`#1793 <https://github.com/aio-libs/aiohttp/pull/1793>`_)


2.0.6 (2017-04-04)
==================

- Keeping blank values for `request.post()` and `multipart.form()` (`#1765 <https://github.com/aio-libs/aiohttp/pull/1765>`_)

- TypeError in data_received of ResponseHandler (`#1770 <https://github.com/aio-libs/aiohttp/pull/1770>`_)

- Fix ``web.run_app`` not to bind to default host-port pair if only socket is
  passed (`#1786 <https://github.com/aio-libs/aiohttp/pull/1786>`_)


2.0.5 (2017-03-29)
==================

- Memory leak with aiohttp.request (`#1756 <https://github.com/aio-libs/aiohttp/pull/1756>`_)

- Disable cleanup closed ssl transports by default.

- Exception in request handling if the server responds before the body
  is sent (`#1761 <https://github.com/aio-libs/aiohttp/pull/1761>`_)


2.0.4 (2017-03-27)
==================

- Memory leak with aiohttp.request (`#1756 <https://github.com/aio-libs/aiohttp/pull/1756>`_)

- Encoding is always UTF-8 in POST data (`#1750 <https://github.com/aio-libs/aiohttp/pull/1750>`_)

- Do not add "Content-Disposition" header by default (`#1755 <https://github.com/aio-libs/aiohttp/pull/1755>`_)


2.0.3 (2017-03-24)
==================

- Call https website through proxy will cause error (`#1745 <https://github.com/aio-libs/aiohttp/pull/1745>`_)

- Fix exception on multipart/form-data post if content-type is not set (`#1743 <https://github.com/aio-libs/aiohttp/pull/1743>`_)


2.0.2 (2017-03-21)
==================

- Fixed Application.on_loop_available signal (`#1739 <https://github.com/aio-libs/aiohttp/pull/1739>`_)

- Remove debug code


2.0.1 (2017-03-21)
==================

- Fix allow-head to include name on route (`#1737 <https://github.com/aio-libs/aiohttp/pull/1737>`_)

- Fixed AttributeError in WebSocketResponse.can_prepare (`#1736 <https://github.com/aio-libs/aiohttp/pull/1736>`_)


2.0.0 (2017-03-20)
==================

- Added `json` to `ClientSession.request()` method (`#1726 <https://github.com/aio-libs/aiohttp/pull/1726>`_)

- Added session's `raise_for_status` parameter, automatically calls
  raise_for_status() on any request. (`#1724 <https://github.com/aio-libs/aiohttp/pull/1724>`_)

- `response.json()` raises `ClientResponseError` exception if response's
  content type does not match (`#1723 <https://github.com/aio-libs/aiohttp/pull/1723>`_)

  - Cleanup timer and loop handle on any client exception.

- Deprecate `loop` parameter for Application's constructor


`2.0.0rc1` (2017-03-15)
=======================

- Properly handle payload errors (`#1710 <https://github.com/aio-libs/aiohttp/pull/1710>`_)

- Added `ClientWebSocketResponse.get_extra_info()` (`#1717 <https://github.com/aio-libs/aiohttp/pull/1717>`_)

- It is not possible to combine Transfer-Encoding and chunked parameter,
  same for compress and Content-Encoding (`#1655 <https://github.com/aio-libs/aiohttp/pull/1655>`_)

- Connector's `limit` parameter indicates total concurrent connections.
  New `limit_per_host` added, indicates total connections per endpoint. (`#1601 <https://github.com/aio-libs/aiohttp/pull/1601>`_)

- Use url's `raw_host` for name resolution (`#1685 <https://github.com/aio-libs/aiohttp/pull/1685>`_)

- Change `ClientResponse.url` to `yarl.URL` instance (`#1654 <https://github.com/aio-libs/aiohttp/pull/1654>`_)

- Add max_size parameter to web.Request reading methods (`#1133 <https://github.com/aio-libs/aiohttp/pull/1133>`_)

- Web Request.post() stores data in temp files (`#1469 <https://github.com/aio-libs/aiohttp/pull/1469>`_)

- Add the `allow_head=True` keyword argument for `add_get` (`#1618 <https://github.com/aio-libs/aiohttp/pull/1618>`_)

- `run_app` and the Command Line Interface now support serving over
  Unix domain sockets for faster inter-process communication.

- `run_app` now supports passing a preexisting socket object. This can be useful
  e.g. for socket-based activated applications, when binding of a socket is
  done by the parent process.

- Implementation for Trailer headers parser is broken (`#1619 <https://github.com/aio-libs/aiohttp/pull/1619>`_)

- Fix FileResponse to not fall on bad request (range out of file size)

- Fix FileResponse to correct stream video to Chromes

- Deprecate public low-level api (`#1657 <https://github.com/aio-libs/aiohttp/pull/1657>`_)

- Deprecate `encoding` parameter for ClientSession.request() method

- Dropped aiohttp.wsgi (`#1108 <https://github.com/aio-libs/aiohttp/pull/1108>`_)

- Dropped `version` from ClientSession.request() method

- Dropped websocket version 76 support (`#1160 <https://github.com/aio-libs/aiohttp/pull/1160>`_)

- Dropped: `aiohttp.protocol.HttpPrefixParser`  (`#1590 <https://github.com/aio-libs/aiohttp/pull/1590>`_)

- Dropped: Servers response's `.started`, `.start()` and
  `.can_start()` method (`#1591 <https://github.com/aio-libs/aiohttp/pull/1591>`_)

- Dropped:  Adding `sub app` via `app.router.add_subapp()` is deprecated
  use `app.add_subapp()` instead (`#1592 <https://github.com/aio-libs/aiohttp/pull/1592>`_)

- Dropped: `Application.finish()` and `Application.register_on_finish()` (`#1602 <https://github.com/aio-libs/aiohttp/pull/1602>`_)

- Dropped: `web.Request.GET` and `web.Request.POST`

- Dropped: aiohttp.get(), aiohttp.options(), aiohttp.head(),
  aiohttp.post(), aiohttp.put(), aiohttp.patch(), aiohttp.delete(), and
  aiohttp.ws_connect() (`#1593 <https://github.com/aio-libs/aiohttp/pull/1593>`_)

- Dropped: `aiohttp.web.WebSocketResponse.receive_msg()` (`#1605 <https://github.com/aio-libs/aiohttp/pull/1605>`_)

- Dropped: `ServerHttpProtocol.keep_alive_timeout` attribute and
  `keep-alive`, `keep_alive_on`, `timeout`, `log` constructor parameters (`#1606 <https://github.com/aio-libs/aiohttp/pull/1606>`_)

- Dropped: `TCPConnector's`` `.resolve`, `.resolved_hosts`,
  `.clear_resolved_hosts()` attributes and `resolve` constructor
  parameter (`#1607 <https://github.com/aio-libs/aiohttp/pull/1607>`_)

- Dropped `ProxyConnector` (`#1609 <https://github.com/aio-libs/aiohttp/pull/1609>`_)


1.3.5 (2017-03-16)
==================

- Fixed None timeout support (`#1720 <https://github.com/aio-libs/aiohttp/pull/1720>`_)


1.3.4 (2017-03-14)
==================

- Revert timeout handling in client request

- Fix StreamResponse representation after eof

- Fix file_sender to not fall on bad request (range out of file size)

- Fix file_sender to correct stream video to Chromes

- Fix NotImplementedError server exception (`#1703 <https://github.com/aio-libs/aiohttp/pull/1703>`_)

- Clearer error message for URL without a host name. (`#1691 <https://github.com/aio-libs/aiohttp/pull/1691>`_)

- Silence deprecation warning in __repr__ (`#1690 <https://github.com/aio-libs/aiohttp/pull/1690>`_)

- IDN + HTTPS = `ssl.CertificateError` (`#1685 <https://github.com/aio-libs/aiohttp/pull/1685>`_)


1.3.3 (2017-02-19)
==================

- Fixed memory leak in time service (`#1656 <https://github.com/aio-libs/aiohttp/pull/1656>`_)


1.3.2 (2017-02-16)
==================

- Awaiting on WebSocketResponse.send_* does not work (`#1645 <https://github.com/aio-libs/aiohttp/pull/1645>`_)

- Fix multiple calls to client ws_connect when using a shared header
  dict (`#1643 <https://github.com/aio-libs/aiohttp/pull/1643>`_)

- Make CookieJar.filter_cookies() accept plain string parameter. (`#1636 <https://github.com/aio-libs/aiohttp/pull/1636>`_)


1.3.1 (2017-02-09)
==================

- Handle CLOSING in WebSocketResponse.__anext__

- Fixed AttributeError 'drain' for server websocket handler (`#1613 <https://github.com/aio-libs/aiohttp/pull/1613>`_)


1.3.0 (2017-02-08)
==================

- Multipart writer validates the data on append instead of on a
  request send (`#920 <https://github.com/aio-libs/aiohttp/pull/920>`_)

- Multipart reader accepts multipart messages with or without their epilogue
  to consistently handle valid and legacy behaviors (`#1526 <https://github.com/aio-libs/aiohttp/pull/1526>`_) (`#1581 <https://github.com/aio-libs/aiohttp/pull/1581>`_)

- Separate read + connect + request timeouts # 1523

- Do not swallow Upgrade header (`#1587 <https://github.com/aio-libs/aiohttp/pull/1587>`_)

- Fix polls demo run application (`#1487 <https://github.com/aio-libs/aiohttp/pull/1487>`_)

- Ignore unknown 1XX status codes in client (`#1353 <https://github.com/aio-libs/aiohttp/pull/1353>`_)

- Fix sub-Multipart messages missing their headers on serialization (`#1525 <https://github.com/aio-libs/aiohttp/pull/1525>`_)

- Do not use readline when reading the content of a part
  in the multipart reader (`#1535 <https://github.com/aio-libs/aiohttp/pull/1535>`_)

- Add optional flag for quoting `FormData` fields (`#916 <https://github.com/aio-libs/aiohttp/pull/916>`_)

- 416 Range Not Satisfiable if requested range end > file size (`#1588 <https://github.com/aio-libs/aiohttp/pull/1588>`_)

- Having a `:` or `@` in a route does not work (`#1552 <https://github.com/aio-libs/aiohttp/pull/1552>`_)

- Added `receive_timeout` timeout for websocket to receive complete
  message. (`#1325 <https://github.com/aio-libs/aiohttp/pull/1325>`_)

- Added `heartbeat` parameter for websocket to automatically send
  `ping` message. (`#1024 <https://github.com/aio-libs/aiohttp/pull/1024>`_) (`#777 <https://github.com/aio-libs/aiohttp/pull/777>`_)

- Remove `web.Application` dependency from `web.UrlDispatcher` (`#1510 <https://github.com/aio-libs/aiohttp/pull/1510>`_)

- Accepting back-pressure from slow websocket clients (`#1367 <https://github.com/aio-libs/aiohttp/pull/1367>`_)

- Do not pause transport during set_parser stage (`#1211 <https://github.com/aio-libs/aiohttp/pull/1211>`_)

- Lingering close does not terminate before timeout (`#1559 <https://github.com/aio-libs/aiohttp/pull/1559>`_)

- `setsockopt` may raise `OSError` exception if socket is closed already (`#1595 <https://github.com/aio-libs/aiohttp/pull/1595>`_)

- Lots of CancelledError when requests are interrupted (`#1565 <https://github.com/aio-libs/aiohttp/pull/1565>`_)

- Allow users to specify what should happen to decoding errors
  when calling a responses `text()` method (`#1542 <https://github.com/aio-libs/aiohttp/pull/1542>`_)

- Back port std module `http.cookies` for python3.4.2 (`#1566 <https://github.com/aio-libs/aiohttp/pull/1566>`_)

- Maintain url's fragment in client response (`#1314 <https://github.com/aio-libs/aiohttp/pull/1314>`_)

- Allow concurrently close WebSocket connection (`#754 <https://github.com/aio-libs/aiohttp/pull/754>`_)

- Gzipped responses with empty body raises ContentEncodingError (`#609 <https://github.com/aio-libs/aiohttp/pull/609>`_)

- Return 504 if request handle raises TimeoutError.

- Refactor how we use keep-alive and close lingering timeouts.

- Close response connection if we can not consume whole http
  message during client response release

- Abort closed ssl client transports, broken servers can keep socket
  open un-limit time (`#1568 <https://github.com/aio-libs/aiohttp/pull/1568>`_)

- Log warning instead of `RuntimeError` is websocket connection is closed.

- Deprecated: `aiohttp.protocol.HttpPrefixParser`
  will be removed in 1.4 (`#1590 <https://github.com/aio-libs/aiohttp/pull/1590>`_)

- Deprecated: Servers response's `.started`, `.start()` and
  `.can_start()` method will be removed in 1.4 (`#1591 <https://github.com/aio-libs/aiohttp/pull/1591>`_)

- Deprecated: Adding `sub app` via `app.router.add_subapp()` is deprecated
  use `app.add_subapp()` instead, will be removed in 1.4 (`#1592 <https://github.com/aio-libs/aiohttp/pull/1592>`_)

- Deprecated: aiohttp.get(), aiohttp.options(), aiohttp.head(), aiohttp.post(),
  aiohttp.put(), aiohttp.patch(), aiohttp.delete(), and aiohttp.ws_connect()
  will be removed in 1.4 (`#1593 <https://github.com/aio-libs/aiohttp/pull/1593>`_)

- Deprecated: `Application.finish()` and `Application.register_on_finish()`
  will be removed in 1.4 (`#1602 <https://github.com/aio-libs/aiohttp/pull/1602>`_)


1.2.0 (2016-12-17)
==================

- Extract `BaseRequest` from `web.Request`, introduce `web.Server`
  (former `RequestHandlerFactory`), introduce new low-level web server
  which is not coupled with `web.Application` and routing (`#1362 <https://github.com/aio-libs/aiohttp/pull/1362>`_)

- Make `TestServer.make_url` compatible with `yarl.URL` (`#1389 <https://github.com/aio-libs/aiohttp/pull/1389>`_)

- Implement range requests for static files (`#1382 <https://github.com/aio-libs/aiohttp/pull/1382>`_)

- Support task attribute for StreamResponse (`#1410 <https://github.com/aio-libs/aiohttp/pull/1410>`_)

- Drop `TestClient.app` property, use `TestClient.server.app` instead
  (BACKWARD INCOMPATIBLE)

- Drop `TestClient.handler` property, use `TestClient.server.handler` instead
  (BACKWARD INCOMPATIBLE)

- `TestClient.server` property returns a test server instance, was
  `asyncio.AbstractServer` (BACKWARD INCOMPATIBLE)

- Follow gunicorn's signal semantics in `Gunicorn[UVLoop]WebWorker` (`#1201 <https://github.com/aio-libs/aiohttp/pull/1201>`_)

- Call worker_int and worker_abort callbacks in
  `Gunicorn[UVLoop]WebWorker` (`#1202 <https://github.com/aio-libs/aiohttp/pull/1202>`_)

- Has functional tests for client proxy (`#1218 <https://github.com/aio-libs/aiohttp/pull/1218>`_)

- Fix bugs with client proxy target path and proxy host with port (`#1413 <https://github.com/aio-libs/aiohttp/pull/1413>`_)

- Fix bugs related to the use of unicode hostnames (`#1444 <https://github.com/aio-libs/aiohttp/pull/1444>`_)

- Preserve cookie quoting/escaping (`#1453 <https://github.com/aio-libs/aiohttp/pull/1453>`_)

- FileSender will send gzipped response if gzip version available (`#1426 <https://github.com/aio-libs/aiohttp/pull/1426>`_)

- Don't override `Content-Length` header in `web.Response` if no body
  was set (`#1400 <https://github.com/aio-libs/aiohttp/pull/1400>`_)

- Introduce `router.post_init()` for solving (`#1373 <https://github.com/aio-libs/aiohttp/pull/1373>`_)

- Fix raise error in case of multiple calls of `TimeServive.stop()`

- Allow to raise web exceptions on router resolving stage (`#1460 <https://github.com/aio-libs/aiohttp/pull/1460>`_)

- Add a warning for session creation outside of coroutine (`#1468 <https://github.com/aio-libs/aiohttp/pull/1468>`_)

- Avoid a race when application might start accepting incoming requests
  but startup signals are not processed yet e98e8c6

- Raise a `RuntimeError` when trying to change the status of the HTTP response
  after the headers have been sent (`#1480 <https://github.com/aio-libs/aiohttp/pull/1480>`_)

- Fix bug with https proxy acquired cleanup (`#1340 <https://github.com/aio-libs/aiohttp/pull/1340>`_)

- Use UTF-8 as the default encoding for multipart text parts (`#1484 <https://github.com/aio-libs/aiohttp/pull/1484>`_)


1.1.6 (2016-11-28)
==================

- Fix `BodyPartReader.read_chunk` bug about returns zero bytes before
  `EOF` (`#1428 <https://github.com/aio-libs/aiohttp/pull/1428>`_)

1.1.5 (2016-11-16)
==================

- Fix static file serving in fallback mode (`#1401 <https://github.com/aio-libs/aiohttp/pull/1401>`_)

1.1.4 (2016-11-14)
==================

- Make `TestServer.make_url` compatible with `yarl.URL` (`#1389 <https://github.com/aio-libs/aiohttp/pull/1389>`_)

- Generate informative exception on redirects from server which
  does not provide redirection headers (`#1396 <https://github.com/aio-libs/aiohttp/pull/1396>`_)


1.1.3 (2016-11-10)
==================

- Support *root* resources for sub-applications (`#1379 <https://github.com/aio-libs/aiohttp/pull/1379>`_)


1.1.2 (2016-11-08)
==================

- Allow starting variables with an underscore (`#1379 <https://github.com/aio-libs/aiohttp/pull/1379>`_)

- Properly process UNIX sockets by gunicorn worker (`#1375 <https://github.com/aio-libs/aiohttp/pull/1375>`_)

- Fix ordering for `FrozenList`

- Don't propagate pre and post signals to sub-application (`#1377 <https://github.com/aio-libs/aiohttp/pull/1377>`_)

1.1.1 (2016-11-04)
==================

- Fix documentation generation (`#1120 <https://github.com/aio-libs/aiohttp/pull/1120>`_)

1.1.0 (2016-11-03)
==================

- Drop deprecated `WSClientDisconnectedError` (BACKWARD INCOMPATIBLE)

- Use `yarl.URL` in client API. The change is 99% backward compatible
  but `ClientResponse.url` is an `yarl.URL` instance now. (`#1217 <https://github.com/aio-libs/aiohttp/pull/1217>`_)

- Close idle keep-alive connections on shutdown (`#1222 <https://github.com/aio-libs/aiohttp/pull/1222>`_)

- Modify regex in AccessLogger to accept underscore and numbers (`#1225 <https://github.com/aio-libs/aiohttp/pull/1225>`_)

- Use `yarl.URL` in web server API. `web.Request.rel_url` and
  `web.Request.url` are added. URLs and templates are percent-encoded
  now. (`#1224 <https://github.com/aio-libs/aiohttp/pull/1224>`_)

- Accept `yarl.URL` by server redirections (`#1278 <https://github.com/aio-libs/aiohttp/pull/1278>`_)

- Return `yarl.URL` by `.make_url()` testing utility (`#1279 <https://github.com/aio-libs/aiohttp/pull/1279>`_)

- Properly format IPv6 addresses by `aiohttp.web.run_app` (`#1139 <https://github.com/aio-libs/aiohttp/pull/1139>`_)

- Use `yarl.URL` by server API (`#1288 <https://github.com/aio-libs/aiohttp/pull/1288>`_)

  * Introduce `resource.url_for()`, deprecate `resource.url()`.

  * Implement `StaticResource`.

  * Inherit `SystemRoute` from `AbstractRoute`

  * Drop old-style routes: `Route`, `PlainRoute`, `DynamicRoute`,
    `StaticRoute`, `ResourceAdapter`.

- Revert `resp.url` back to `str`, introduce `resp.url_obj` (`#1292 <https://github.com/aio-libs/aiohttp/pull/1292>`_)

- Raise ValueError if BasicAuth login has a ":" character (`#1307 <https://github.com/aio-libs/aiohttp/pull/1307>`_)

- Fix bug when ClientRequest send payload file with opened as
  open('filename', 'r+b') (`#1306 <https://github.com/aio-libs/aiohttp/pull/1306>`_)

- Enhancement to AccessLogger (pass *extra* dict) (`#1303 <https://github.com/aio-libs/aiohttp/pull/1303>`_)

- Show more verbose message on import errors (`#1319 <https://github.com/aio-libs/aiohttp/pull/1319>`_)

- Added save and load functionality for `CookieJar` (`#1219 <https://github.com/aio-libs/aiohttp/pull/1219>`_)

- Added option on `StaticRoute` to follow symlinks (`#1299 <https://github.com/aio-libs/aiohttp/pull/1299>`_)

- Force encoding of `application/json` content type to utf-8 (`#1339 <https://github.com/aio-libs/aiohttp/pull/1339>`_)

- Fix invalid invocations of `errors.LineTooLong` (`#1335 <https://github.com/aio-libs/aiohttp/pull/1335>`_)

- Websockets: Stop `async for` iteration when connection is closed (`#1144 <https://github.com/aio-libs/aiohttp/pull/1144>`_)

- Ensure TestClient HTTP methods return a context manager (`#1318 <https://github.com/aio-libs/aiohttp/pull/1318>`_)

- Raise `ClientDisconnectedError` to `FlowControlStreamReader` read function
  if `ClientSession` object is closed by client when reading data. (`#1323 <https://github.com/aio-libs/aiohttp/pull/1323>`_)

- Document deployment without `Gunicorn` (`#1120 <https://github.com/aio-libs/aiohttp/pull/1120>`_)

- Add deprecation warning for MD5 and SHA1 digests when used for fingerprint
  of site certs in TCPConnector. (`#1186 <https://github.com/aio-libs/aiohttp/pull/1186>`_)

- Implement sub-applications (`#1301 <https://github.com/aio-libs/aiohttp/pull/1301>`_)

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

- Boost performance by adding a custom time service (`#1350 <https://github.com/aio-libs/aiohttp/pull/1350>`_)

- Extend `ClientResponse` with `content_type` and `charset`
  properties like in `web.Request`. (`#1349 <https://github.com/aio-libs/aiohttp/pull/1349>`_)

- Disable aiodns by default (`#559 <https://github.com/aio-libs/aiohttp/pull/559>`_)

- Don't flap `tcp_cork` in client code, use TCP_NODELAY mode by default.

- Implement `web.Request.clone()` (`#1361 <https://github.com/aio-libs/aiohttp/pull/1361>`_)

1.0.5 (2016-10-11)
==================

- Fix StreamReader._read_nowait to return all available
  data up to the requested amount (`#1297 <https://github.com/aio-libs/aiohttp/pull/1297>`_)


1.0.4 (2016-09-22)
==================

- Fix FlowControlStreamReader.read_nowait so that it checks
  whether the transport is paused (`#1206 <https://github.com/aio-libs/aiohttp/pull/1206>`_)


1.0.2 (2016-09-22)
==================

- Make CookieJar compatible with 32-bit systems (`#1188 <https://github.com/aio-libs/aiohttp/pull/1188>`_)

- Add missing `WSMsgType` to `web_ws.__all__`, see (`#1200 <https://github.com/aio-libs/aiohttp/pull/1200>`_)

- Fix `CookieJar` ctor when called with `loop=None` (`#1203 <https://github.com/aio-libs/aiohttp/pull/1203>`_)

- Fix broken upper-casing in wsgi support (`#1197 <https://github.com/aio-libs/aiohttp/pull/1197>`_)


1.0.1 (2016-09-16)
==================

- Restore `aiohttp.web.MsgType` alias for `aiohttp.WSMsgType` for sake
  of backward compatibility (`#1178 <https://github.com/aio-libs/aiohttp/pull/1178>`_)

- Tune alabaster schema.

- Use `text/html` content type for displaying index pages by static
  file handler.

- Fix `AssertionError` in static file handling (`#1177 <https://github.com/aio-libs/aiohttp/pull/1177>`_)

- Fix access log formats `%O` and `%b` for static file handling

- Remove `debug` setting of GunicornWorker, use `app.debug`
  to control its debug-mode instead


1.0.0 (2016-09-16)
==================

- Change default size for client session's connection pool from
  unlimited to 20 (`#977 <https://github.com/aio-libs/aiohttp/pull/977>`_)

- Add IE support for cookie deletion. (`#994 <https://github.com/aio-libs/aiohttp/pull/994>`_)

- Remove deprecated `WebSocketResponse.wait_closed` method (BACKWARD
  INCOMPATIBLE)

- Remove deprecated `force` parameter for `ClientResponse.close`
  method (BACKWARD INCOMPATIBLE)

- Avoid using of mutable CIMultiDict kw param in make_mocked_request
  (`#997 <https://github.com/aio-libs/aiohttp/pull/997>`_)

- Make WebSocketResponse.close a little bit faster by avoiding new
  task creating just for timeout measurement

- Add `proxy` and `proxy_auth` params to `client.get()` and family,
  deprecate `ProxyConnector` (`#998 <https://github.com/aio-libs/aiohttp/pull/998>`_)

- Add support for websocket send_json and receive_json, synchronize
  server and client API for websockets (`#984 <https://github.com/aio-libs/aiohttp/pull/984>`_)

- Implement router shourtcuts for most useful HTTP methods, use
  `app.router.add_get()`, `app.router.add_post()` etc. instead of
  `app.router.add_route()` (`#986 <https://github.com/aio-libs/aiohttp/pull/986>`_)

- Support SSL connections for gunicorn worker (`#1003 <https://github.com/aio-libs/aiohttp/pull/1003>`_)

- Move obsolete examples to legacy folder

- Switch to multidict 2.0 and title-cased strings (`#1015 <https://github.com/aio-libs/aiohttp/pull/1015>`_)

- `{FOO}e` logger format is case-sensitive now

- Fix logger report for unix socket 8e8469b

- Rename aiohttp.websocket to aiohttp._ws_impl

- Rename aiohttp.MsgType tp aiohttp.WSMsgType

- Introduce aiohttp.WSMessage officially

- Rename Message -> WSMessage

- Remove deprecated decode param from resp.read(decode=True)

- Use 5min default client timeout (`#1028 <https://github.com/aio-libs/aiohttp/pull/1028>`_)

- Relax HTTP method validation in UrlDispatcher (`#1037 <https://github.com/aio-libs/aiohttp/pull/1037>`_)

- Pin minimal supported asyncio version to 3.4.2+ (`loop.is_close()`
  should be present)

- Remove aiohttp.websocket module (BACKWARD INCOMPATIBLE)
  Please use high-level client and server approaches

- Link header for 451 status code is mandatory

- Fix test_client fixture to allow multiple clients per test (`#1072 <https://github.com/aio-libs/aiohttp/pull/1072>`_)

- make_mocked_request now accepts dict as headers (`#1073 <https://github.com/aio-libs/aiohttp/pull/1073>`_)

- Add Python 3.5.2/3.6+ compatibility patch for async generator
  protocol change (`#1082 <https://github.com/aio-libs/aiohttp/pull/1082>`_)

- Improvement test_client can accept instance object (`#1083 <https://github.com/aio-libs/aiohttp/pull/1083>`_)

- Simplify ServerHttpProtocol implementation (`#1060 <https://github.com/aio-libs/aiohttp/pull/1060>`_)

- Add a flag for optional showing directory index for static file
  handling (`#921 <https://github.com/aio-libs/aiohttp/pull/921>`_)

- Define `web.Application.on_startup()` signal handler (`#1103 <https://github.com/aio-libs/aiohttp/pull/1103>`_)

- Drop ChunkedParser and LinesParser (`#1111 <https://github.com/aio-libs/aiohttp/pull/1111>`_)

- Call `Application.startup` in GunicornWebWorker (`#1105 <https://github.com/aio-libs/aiohttp/pull/1105>`_)

- Fix client handling hostnames with 63 bytes when a port is given in
  the url (`#1044 <https://github.com/aio-libs/aiohttp/pull/1044>`_)

- Implement proxy support for ClientSession.ws_connect (`#1025 <https://github.com/aio-libs/aiohttp/pull/1025>`_)

- Return named tuple from WebSocketResponse.can_prepare (`#1016 <https://github.com/aio-libs/aiohttp/pull/1016>`_)

- Fix access_log_format in `GunicornWebWorker` (`#1117 <https://github.com/aio-libs/aiohttp/pull/1117>`_)

- Setup Content-Type to application/octet-stream by default (`#1124 <https://github.com/aio-libs/aiohttp/pull/1124>`_)

- Deprecate debug parameter from app.make_handler(), use
  `Application(debug=True)` instead (`#1121 <https://github.com/aio-libs/aiohttp/pull/1121>`_)

- Remove fragment string in request path (`#846 <https://github.com/aio-libs/aiohttp/pull/846>`_)

- Use aiodns.DNSResolver.gethostbyname() if available (`#1136 <https://github.com/aio-libs/aiohttp/pull/1136>`_)

- Fix static file sending on uvloop when sendfile is available (`#1093 <https://github.com/aio-libs/aiohttp/pull/1093>`_)

- Make prettier urls if query is empty dict (`#1143 <https://github.com/aio-libs/aiohttp/pull/1143>`_)

- Fix redirects for HEAD requests (`#1147 <https://github.com/aio-libs/aiohttp/pull/1147>`_)

- Default value for `StreamReader.read_nowait` is -1 from now (`#1150 <https://github.com/aio-libs/aiohttp/pull/1150>`_)

- `aiohttp.StreamReader` is not inherited from `asyncio.StreamReader` from now
  (BACKWARD INCOMPATIBLE) (`#1150 <https://github.com/aio-libs/aiohttp/pull/1150>`_)

- Streams documentation added (`#1150 <https://github.com/aio-libs/aiohttp/pull/1150>`_)

- Add `multipart` coroutine method for web Request object (`#1067 <https://github.com/aio-libs/aiohttp/pull/1067>`_)

- Publish ClientSession.loop property (`#1149 <https://github.com/aio-libs/aiohttp/pull/1149>`_)

- Fix static file with spaces (`#1140 <https://github.com/aio-libs/aiohttp/pull/1140>`_)

- Fix piling up asyncio loop by cookie expiration callbacks (`#1061 <https://github.com/aio-libs/aiohttp/pull/1061>`_)

- Drop `Timeout` class for sake of `async_timeout` external library.
  `aiohttp.Timeout` is an alias for `async_timeout.timeout`

- `use_dns_cache` parameter of `aiohttp.TCPConnector` is `True` by
  default (BACKWARD INCOMPATIBLE) (`#1152 <https://github.com/aio-libs/aiohttp/pull/1152>`_)

- `aiohttp.TCPConnector` uses asynchronous DNS resolver if available by
  default (BACKWARD INCOMPATIBLE) (`#1152 <https://github.com/aio-libs/aiohttp/pull/1152>`_)

- Conform to RFC3986 - do not include url fragments in client requests (`#1174 <https://github.com/aio-libs/aiohttp/pull/1174>`_)

- Drop `ClientSession.cookies` (BACKWARD INCOMPATIBLE) (`#1173 <https://github.com/aio-libs/aiohttp/pull/1173>`_)

- Refactor `AbstractCookieJar` public API (BACKWARD INCOMPATIBLE) (`#1173 <https://github.com/aio-libs/aiohttp/pull/1173>`_)

- Fix clashing cookies with have the same name but belong to different
  domains (BACKWARD INCOMPATIBLE) (`#1125 <https://github.com/aio-libs/aiohttp/pull/1125>`_)

- Support binary Content-Transfer-Encoding (`#1169 <https://github.com/aio-libs/aiohttp/pull/1169>`_)


0.22.5 (08-02-2016)
===================

- Pin miltidict version to >=1.2.2

0.22.3 (07-26-2016)
===================

- Do not filter cookies if unsafe flag provided (`#1005 <https://github.com/aio-libs/aiohttp/pull/1005>`_)


0.22.2 (07-23-2016)
===================

- Suppress CancelledError when Timeout raises TimeoutError (`#970 <https://github.com/aio-libs/aiohttp/pull/970>`_)

- Don't expose `aiohttp.__version__`

- Add unsafe parameter to CookieJar (`#968 <https://github.com/aio-libs/aiohttp/pull/968>`_)

- Use unsafe cookie jar in test client tools

- Expose aiohttp.CookieJar name


0.22.1 (07-16-2016)
===================

- Large cookie expiration/max-age does not break an event loop from now
  (fixes (`#967 <https://github.com/aio-libs/aiohttp/pull/967>`_))


0.22.0 (07-15-2016)
===================

- Fix bug in serving static directory (`#803 <https://github.com/aio-libs/aiohttp/pull/803>`_)

- Fix command line arg parsing (`#797 <https://github.com/aio-libs/aiohttp/pull/797>`_)

- Fix a documentation chapter about cookie usage (`#790 <https://github.com/aio-libs/aiohttp/pull/790>`_)

- Handle empty body with gzipped encoding (`#758 <https://github.com/aio-libs/aiohttp/pull/758>`_)

- Support 451 Unavailable For Legal Reasons http status  (`#697 <https://github.com/aio-libs/aiohttp/pull/697>`_)

- Fix Cookie share example and few small typos in docs (`#817 <https://github.com/aio-libs/aiohttp/pull/817>`_)

- UrlDispatcher.add_route with partial coroutine handler (`#814 <https://github.com/aio-libs/aiohttp/pull/814>`_)

- Optional support for aiodns (`#728 <https://github.com/aio-libs/aiohttp/pull/728>`_)

- Add ServiceRestart and TryAgainLater websocket close codes (`#828 <https://github.com/aio-libs/aiohttp/pull/828>`_)

- Fix prompt message for `web.run_app` (`#832 <https://github.com/aio-libs/aiohttp/pull/832>`_)

- Allow to pass None as a timeout value to disable timeout logic (`#834 <https://github.com/aio-libs/aiohttp/pull/834>`_)

- Fix leak of connection slot during connection error (`#835 <https://github.com/aio-libs/aiohttp/pull/835>`_)

- Gunicorn worker with uvloop support
  `aiohttp.worker.GunicornUVLoopWebWorker` (`#878 <https://github.com/aio-libs/aiohttp/pull/878>`_)

- Don't send body in response to HEAD request (`#838 <https://github.com/aio-libs/aiohttp/pull/838>`_)

- Skip the preamble in MultipartReader (`#881 <https://github.com/aio-libs/aiohttp/pull/881>`_)

- Implement BasicAuth decode classmethod. (`#744 <https://github.com/aio-libs/aiohttp/pull/744>`_)

- Don't crash logger when transport is None (`#889 <https://github.com/aio-libs/aiohttp/pull/889>`_)

- Use a create_future compatibility wrapper instead of creating
  Futures directly (`#896 <https://github.com/aio-libs/aiohttp/pull/896>`_)

- Add test utilities to aiohttp (`#902 <https://github.com/aio-libs/aiohttp/pull/902>`_)

- Improve Request.__repr__ (`#875 <https://github.com/aio-libs/aiohttp/pull/875>`_)

- Skip DNS resolving if provided host is already an ip address (`#874 <https://github.com/aio-libs/aiohttp/pull/874>`_)

- Add headers to ClientSession.ws_connect (`#785 <https://github.com/aio-libs/aiohttp/pull/785>`_)

- Document that server can send pre-compressed data (`#906 <https://github.com/aio-libs/aiohttp/pull/906>`_)

- Don't add Content-Encoding and Transfer-Encoding if no body (`#891 <https://github.com/aio-libs/aiohttp/pull/891>`_)

- Add json() convenience methods to websocket message objects (`#897 <https://github.com/aio-libs/aiohttp/pull/897>`_)

- Add client_resp.raise_for_status() (`#908 <https://github.com/aio-libs/aiohttp/pull/908>`_)

- Implement cookie filter (`#799 <https://github.com/aio-libs/aiohttp/pull/799>`_)

- Include an example of middleware to handle error pages (`#909 <https://github.com/aio-libs/aiohttp/pull/909>`_)

- Fix error handling in StaticFileMixin (`#856 <https://github.com/aio-libs/aiohttp/pull/856>`_)

- Add mocked request helper (`#900 <https://github.com/aio-libs/aiohttp/pull/900>`_)

- Fix empty ALLOW Response header for cls based View (`#929 <https://github.com/aio-libs/aiohttp/pull/929>`_)

- Respect CONNECT method to implement a proxy server (`#847 <https://github.com/aio-libs/aiohttp/pull/847>`_)

- Add pytest_plugin (`#914 <https://github.com/aio-libs/aiohttp/pull/914>`_)

- Add tutorial

- Add backlog option to support more than 128 (default value in
  "create_server" function) concurrent connections (`#892 <https://github.com/aio-libs/aiohttp/pull/892>`_)

- Allow configuration of header size limits (`#912 <https://github.com/aio-libs/aiohttp/pull/912>`_)

- Separate sending file logic from StaticRoute dispatcher (`#901 <https://github.com/aio-libs/aiohttp/pull/901>`_)

- Drop deprecated share_cookies connector option (BACKWARD INCOMPATIBLE)

- Drop deprecated support for tuple as auth parameter.
  Use aiohttp.BasicAuth instead (BACKWARD INCOMPATIBLE)

- Remove deprecated `request.payload` property, use `content` instead.
  (BACKWARD INCOMPATIBLE)

- Drop all mentions about api changes in documentation for versions
  older than 0.16

- Allow to override default cookie jar (`#963 <https://github.com/aio-libs/aiohttp/pull/963>`_)

- Add manylinux wheel builds

- Dup a socket for sendfile usage (`#964 <https://github.com/aio-libs/aiohttp/pull/964>`_)

0.21.6 (05-05-2016)
===================

- Drop initial query parameters on redirects (`#853 <https://github.com/aio-libs/aiohttp/pull/853>`_)


0.21.5 (03-22-2016)
===================

- Fix command line arg parsing (`#797 <https://github.com/aio-libs/aiohttp/pull/797>`_)

0.21.4 (03-12-2016)
===================

- Fix ResourceAdapter: don't add method to allowed if resource is not
  match (`#826 <https://github.com/aio-libs/aiohttp/pull/826>`_)

- Fix Resource: append found method to returned allowed methods

0.21.2 (02-16-2016)
===================

- Fix a regression: support for handling ~/path in static file routes was
  broken (`#782 <https://github.com/aio-libs/aiohttp/pull/782>`_)

0.21.1 (02-10-2016)
===================

- Make new resources classes public (`#767 <https://github.com/aio-libs/aiohttp/pull/767>`_)

- Add `router.resources()` view

- Fix cmd-line parameter names in doc

0.21.0 (02-04-2016)
===================

- Introduce on_shutdown signal (`#722 <https://github.com/aio-libs/aiohttp/pull/722>`_)

- Implement raw input headers (`#726 <https://github.com/aio-libs/aiohttp/pull/726>`_)

- Implement web.run_app utility function (`#734 <https://github.com/aio-libs/aiohttp/pull/734>`_)

- Introduce on_cleanup signal

- Deprecate Application.finish() / Application.register_on_finish() in favor of
  on_cleanup.

- Get rid of bare aiohttp.request(), aiohttp.get() and family in docs (`#729 <https://github.com/aio-libs/aiohttp/pull/729>`_)

- Deprecate bare aiohttp.request(), aiohttp.get() and family (`#729 <https://github.com/aio-libs/aiohttp/pull/729>`_)

- Refactor keep-alive support (`#737 <https://github.com/aio-libs/aiohttp/pull/737>`_):

  - Enable keepalive for HTTP 1.0 by default

  - Disable it for HTTP 0.9 (who cares about 0.9, BTW?)

  - For keepalived connections

      - Send `Connection: keep-alive` for HTTP 1.0 only

      - don't send `Connection` header for HTTP 1.1

  - For non-keepalived connections

      - Send `Connection: close` for HTTP 1.1 only

      - don't send `Connection` header for HTTP 1.0

- Add version parameter to ClientSession constructor,
  deprecate it for session.request() and family (`#736 <https://github.com/aio-libs/aiohttp/pull/736>`_)

- Enable access log by default (`#735 <https://github.com/aio-libs/aiohttp/pull/735>`_)

- Deprecate app.router.register_route() (the method was not documented
  intentionally BTW).

- Deprecate app.router.named_routes() in favor of app.router.named_resources()

- route.add_static accepts pathlib.Path now (`#743 <https://github.com/aio-libs/aiohttp/pull/743>`_)

- Add command line support: `$ python -m aiohttp.web package.main` (`#740 <https://github.com/aio-libs/aiohttp/pull/740>`_)

- FAQ section was added to docs. Enjoy and fill free to contribute new topics

- Add async context manager support to ClientSession

- Document ClientResponse's host, method, url properties

- Use CORK/NODELAY in client API (`#748 <https://github.com/aio-libs/aiohttp/pull/748>`_)

- ClientSession.close and Connector.close are coroutines now

- Close client connection on exception in ClientResponse.release()

- Allow to read multipart parts without content-length specified (`#750 <https://github.com/aio-libs/aiohttp/pull/750>`_)

- Add support for unix domain sockets to gunicorn worker (`#470 <https://github.com/aio-libs/aiohttp/pull/470>`_)

- Add test for default Expect handler (`#601 <https://github.com/aio-libs/aiohttp/pull/601>`_)

- Add the first demo project

- Rename `loader` keyword argument in `web.Request.json` method. (`#646 <https://github.com/aio-libs/aiohttp/pull/646>`_)

- Add local socket binding for TCPConnector (`#678 <https://github.com/aio-libs/aiohttp/pull/678>`_)

0.20.2 (01-07-2016)
===================

- Enable use of `await` for a class based view (`#717 <https://github.com/aio-libs/aiohttp/pull/717>`_)

- Check address family to fill wsgi env properly (`#718 <https://github.com/aio-libs/aiohttp/pull/718>`_)

- Fix memory leak in headers processing (thanks to Marco Paolini) (`#723 <https://github.com/aio-libs/aiohttp/pull/723>`_)

0.20.1 (12-30-2015)
===================

- Raise RuntimeError is Timeout context manager was used outside of
  task context.

- Add number of bytes to stream.read_nowait (`#700 <https://github.com/aio-libs/aiohttp/pull/700>`_)

- Use X-FORWARDED-PROTO for wsgi.url_scheme when available


0.20.0 (12-28-2015)
===================

- Extend list of web exceptions, add HTTPMisdirectedRequest,
  HTTPUpgradeRequired, HTTPPreconditionRequired, HTTPTooManyRequests,
  HTTPRequestHeaderFieldsTooLarge, HTTPVariantAlsoNegotiates,
  HTTPNotExtended, HTTPNetworkAuthenticationRequired status codes (`#644 <https://github.com/aio-libs/aiohttp/pull/644>`_)

- Do not remove AUTHORIZATION header by WSGI handler (`#649 <https://github.com/aio-libs/aiohttp/pull/649>`_)

- Fix broken support for https proxies with authentication (`#617 <https://github.com/aio-libs/aiohttp/pull/617>`_)

- Get REMOTE_* and SEVER_* http vars from headers when listening on
  unix socket (`#654 <https://github.com/aio-libs/aiohttp/pull/654>`_)

- Add HTTP 308 support (`#663 <https://github.com/aio-libs/aiohttp/pull/663>`_)

- Add Tf format (time to serve request in seconds, %06f format) to
  access log (`#669 <https://github.com/aio-libs/aiohttp/pull/669>`_)

- Remove one and a half years long deprecated
  ClientResponse.read_and_close() method

- Optimize chunked encoding: use a single syscall instead of 3 calls
  on sending chunked encoded data

- Use TCP_CORK and TCP_NODELAY to optimize network latency and
  throughput (`#680 <https://github.com/aio-libs/aiohttp/pull/680>`_)

- Websocket XOR performance improved (`#687 <https://github.com/aio-libs/aiohttp/pull/687>`_)

- Avoid sending cookie attributes in Cookie header (`#613 <https://github.com/aio-libs/aiohttp/pull/613>`_)

- Round server timeouts to seconds for grouping pending calls.  That
  leads to less amount of poller syscalls e.g. epoll.poll(). (`#702 <https://github.com/aio-libs/aiohttp/pull/702>`_)

- Close connection on websocket handshake error (`#703 <https://github.com/aio-libs/aiohttp/pull/703>`_)

- Implement class based views (`#684 <https://github.com/aio-libs/aiohttp/pull/684>`_)

- Add *headers* parameter to ws_connect() (`#709 <https://github.com/aio-libs/aiohttp/pull/709>`_)

- Drop unused function `parse_remote_addr()` (`#708 <https://github.com/aio-libs/aiohttp/pull/708>`_)

- Close session on exception (`#707 <https://github.com/aio-libs/aiohttp/pull/707>`_)

- Store http code and headers in WSServerHandshakeError (`#706 <https://github.com/aio-libs/aiohttp/pull/706>`_)

- Make some low-level message properties readonly (`#710 <https://github.com/aio-libs/aiohttp/pull/710>`_)


0.19.0 (11-25-2015)
===================

- Memory leak in ParserBuffer (`#579 <https://github.com/aio-libs/aiohttp/pull/579>`_)

- Support gunicorn's `max_requests` settings in gunicorn worker

- Fix wsgi environment building (`#573 <https://github.com/aio-libs/aiohttp/pull/573>`_)

- Improve access logging (`#572 <https://github.com/aio-libs/aiohttp/pull/572>`_)

- Drop unused host and port from low-level server (`#586 <https://github.com/aio-libs/aiohttp/pull/586>`_)

- Add Python 3.5 `async for` implementation to server websocket (`#543 <https://github.com/aio-libs/aiohttp/pull/543>`_)

- Add Python 3.5 `async for` implementation to client websocket

- Add Python 3.5 `async with` implementation to client websocket

- Add charset parameter to web.Response constructor (`#593 <https://github.com/aio-libs/aiohttp/pull/593>`_)

- Forbid passing both Content-Type header and content_type or charset
  params into web.Response constructor

- Forbid duplicating of web.Application and web.Request (`#602 <https://github.com/aio-libs/aiohttp/pull/602>`_)

- Add an option to pass Origin header in ws_connect (`#607 <https://github.com/aio-libs/aiohttp/pull/607>`_)

- Add json_response function (`#592 <https://github.com/aio-libs/aiohttp/pull/592>`_)

- Make concurrent connections respect limits (`#581 <https://github.com/aio-libs/aiohttp/pull/581>`_)

- Collect history of responses if redirects occur (`#614 <https://github.com/aio-libs/aiohttp/pull/614>`_)

- Enable passing pre-compressed data in requests (`#621 <https://github.com/aio-libs/aiohttp/pull/621>`_)

- Expose named routes via UrlDispatcher.named_routes() (`#622 <https://github.com/aio-libs/aiohttp/pull/622>`_)

- Allow disabling sendfile by environment variable AIOHTTP_NOSENDFILE (`#629 <https://github.com/aio-libs/aiohttp/pull/629>`_)

- Use ensure_future if available

- Always quote params for Content-Disposition (`#641 <https://github.com/aio-libs/aiohttp/pull/641>`_)

- Support async for in multipart reader (`#640 <https://github.com/aio-libs/aiohttp/pull/640>`_)

- Add Timeout context manager (`#611 <https://github.com/aio-libs/aiohttp/pull/611>`_)

0.18.4 (13-11-2015)
===================

- Relax rule for router names again by adding dash to allowed
  characters: they may contain identifiers, dashes, dots and columns

0.18.3 (25-10-2015)
===================

- Fix formatting for _RequestContextManager helper (`#590 <https://github.com/aio-libs/aiohttp/pull/590>`_)

0.18.2 (22-10-2015)
===================

- Fix regression for OpenSSL < 1.0.0 (`#583 <https://github.com/aio-libs/aiohttp/pull/583>`_)

0.18.1 (20-10-2015)
===================

- Relax rule for router names: they may contain dots and columns
  starting from now

0.18.0 (19-10-2015)
===================

- Use errors.HttpProcessingError.message as HTTP error reason and
  message (`#459 <https://github.com/aio-libs/aiohttp/pull/459>`_)

- Optimize cythonized multidict a bit

- Change repr's of multidicts and multidict views

- default headers in ClientSession are now case-insensitive

- Make '=' char and 'wss://' schema safe in urls (`#477 <https://github.com/aio-libs/aiohttp/pull/477>`_)

- `ClientResponse.close()` forces connection closing by default from now (`#479 <https://github.com/aio-libs/aiohttp/pull/479>`_)

  N.B. Backward incompatible change: was `.close(force=False) Using
  `force` parameter for the method is deprecated: use `.release()`
  instead.

- Properly requote URL's path (`#480 <https://github.com/aio-libs/aiohttp/pull/480>`_)

- add `skip_auto_headers` parameter for client API (`#486 <https://github.com/aio-libs/aiohttp/pull/486>`_)

- Properly parse URL path in aiohttp.web.Request (`#489 <https://github.com/aio-libs/aiohttp/pull/489>`_)

- Raise RuntimeError when chunked enabled and HTTP is 1.0 (`#488 <https://github.com/aio-libs/aiohttp/pull/488>`_)

- Fix a bug with processing io.BytesIO as data parameter for client API (`#500 <https://github.com/aio-libs/aiohttp/pull/500>`_)

- Skip auto-generation of Content-Type header (`#507 <https://github.com/aio-libs/aiohttp/pull/507>`_)

- Use sendfile facility for static file handling (`#503 <https://github.com/aio-libs/aiohttp/pull/503>`_)

- Default `response_factory` in `app.router.add_static` now is
  `StreamResponse`, not `None`. The functionality is not changed if
  default is not specified.

- Drop `ClientResponse.message` attribute, it was always implementation detail.

- Streams are optimized for speed and mostly memory in case of a big
  HTTP message sizes (`#496 <https://github.com/aio-libs/aiohttp/pull/496>`_)

- Fix a bug for server-side cookies for dropping cookie and setting it
  again without Max-Age parameter.

- Don't trim redirect URL in client API (`#499 <https://github.com/aio-libs/aiohttp/pull/499>`_)

- Extend precision of access log "D" to milliseconds (`#527 <https://github.com/aio-libs/aiohttp/pull/527>`_)

- Deprecate `StreamResponse.start()` method in favor of
  `StreamResponse.prepare()` coroutine (`#525 <https://github.com/aio-libs/aiohttp/pull/525>`_)

  `.start()` is still supported but responses begun with `.start()`
  does not call signal for response preparing to be sent.

- Add `StreamReader.__repr__`

- Drop Python 3.3 support, from now minimal required version is Python
  3.4.1 (`#541 <https://github.com/aio-libs/aiohttp/pull/541>`_)

- Add `async with` support for `ClientSession.request()` and family (`#536 <https://github.com/aio-libs/aiohttp/pull/536>`_)

- Ignore message body on 204 and 304 responses (`#505 <https://github.com/aio-libs/aiohttp/pull/505>`_)

- `TCPConnector` processed both IPv4 and IPv6 by default (`#559 <https://github.com/aio-libs/aiohttp/pull/559>`_)

- Add `.routes()` view for urldispatcher (`#519 <https://github.com/aio-libs/aiohttp/pull/519>`_)

- Route name should be a valid identifier name from now (`#567 <https://github.com/aio-libs/aiohttp/pull/567>`_)

- Implement server signals (`#562 <https://github.com/aio-libs/aiohttp/pull/562>`_)

- Drop a year-old deprecated *files* parameter from client API.

- Added `async for` support for aiohttp stream (`#542 <https://github.com/aio-libs/aiohttp/pull/542>`_)

0.17.4 (09-29-2015)
===================

- Properly parse URL path in aiohttp.web.Request (`#489 <https://github.com/aio-libs/aiohttp/pull/489>`_)

- Add missing coroutine decorator, the client api is await-compatible now

0.17.3 (08-28-2015)
===================

- Remove Content-Length header on compressed responses (`#450 <https://github.com/aio-libs/aiohttp/pull/450>`_)

- Support Python 3.5

- Improve performance of transport in-use list (`#472 <https://github.com/aio-libs/aiohttp/pull/472>`_)

- Fix connection pooling (`#473 <https://github.com/aio-libs/aiohttp/pull/473>`_)

0.17.2 (08-11-2015)
===================

- Don't forget to pass `data` argument forward (`#462 <https://github.com/aio-libs/aiohttp/pull/462>`_)

- Fix multipart read bytes count (`#463 <https://github.com/aio-libs/aiohttp/pull/463>`_)

0.17.1 (08-10-2015)
===================

- Fix multidict comparison to arbitrary abc.Mapping

0.17.0 (08-04-2015)
===================

- Make StaticRoute support Last-Modified and If-Modified-Since headers (`#386 <https://github.com/aio-libs/aiohttp/pull/386>`_)

- Add Request.if_modified_since and Stream.Response.last_modified properties

- Fix deflate compression when writing a chunked response (`#395 <https://github.com/aio-libs/aiohttp/pull/395>`_)

- Request`s content-length header is cleared now after redirect from
  POST method (`#391 <https://github.com/aio-libs/aiohttp/pull/391>`_)

- Return a 400 if server received a non HTTP content (`#405 <https://github.com/aio-libs/aiohttp/pull/405>`_)

- Fix keep-alive support for aiohttp clients (`#406 <https://github.com/aio-libs/aiohttp/pull/406>`_)

- Allow gzip compression in high-level server response interface (`#403 <https://github.com/aio-libs/aiohttp/pull/403>`_)

- Rename TCPConnector.resolve and family to dns_cache (`#415 <https://github.com/aio-libs/aiohttp/pull/415>`_)

- Make UrlDispatcher ignore quoted characters during url matching (`#414 <https://github.com/aio-libs/aiohttp/pull/414>`_)
  Backward-compatibility warning: this may change the url matched by
  your queries if they send quoted character (like %2F for /) (`#414 <https://github.com/aio-libs/aiohttp/pull/414>`_)

- Use optional cchardet accelerator if present (`#418 <https://github.com/aio-libs/aiohttp/pull/418>`_)

- Borrow loop from Connector in ClientSession if loop is not set

- Add context manager support to ClientSession for session closing.

- Add toplevel get(), post(), put(), head(), delete(), options(),
  patch() coroutines.

- Fix IPv6 support for client API (`#425 <https://github.com/aio-libs/aiohttp/pull/425>`_)

- Pass SSL context through proxy connector (`#421 <https://github.com/aio-libs/aiohttp/pull/421>`_)

- Make the rule: path for add_route should start with slash

- Don't process request finishing by low-level server on closed event loop

- Don't override data if multiple files are uploaded with same key (`#433 <https://github.com/aio-libs/aiohttp/pull/433>`_)

- Ensure multipart.BodyPartReader.read_chunk read all the necessary data
  to avoid false assertions about malformed multipart payload

- Don't send body for 204, 205 and 304 http exceptions (`#442 <https://github.com/aio-libs/aiohttp/pull/442>`_)

- Correctly skip Cython compilation in MSVC not found (`#453 <https://github.com/aio-libs/aiohttp/pull/453>`_)

- Add response factory to StaticRoute (`#456 <https://github.com/aio-libs/aiohttp/pull/456>`_)

- Don't append trailing CRLF for multipart.BodyPartReader (`#454 <https://github.com/aio-libs/aiohttp/pull/454>`_)


0.16.6 (07-15-2015)
===================

- Skip compilation on Windows if vcvarsall.bat cannot be found (`#438 <https://github.com/aio-libs/aiohttp/pull/438>`_)

0.16.5 (06-13-2015)
===================

- Get rid of all comprehensions and yielding in _multidict (`#410 <https://github.com/aio-libs/aiohttp/pull/410>`_)


0.16.4 (06-13-2015)
===================

- Don't clear current exception in multidict's `__repr__` (cythonized
  versions) (`#410 <https://github.com/aio-libs/aiohttp/pull/410>`_)


0.16.3 (05-30-2015)
===================

- Fix StaticRoute vulnerability to directory traversal attacks (`#380 <https://github.com/aio-libs/aiohttp/pull/380>`_)


0.16.2 (05-27-2015)
===================

- Update python version required for `__del__` usage: it's actually
  3.4.1 instead of 3.4.0

- Add check for presence of loop.is_closed() method before call the
  former (`#378 <https://github.com/aio-libs/aiohttp/pull/378>`_)


0.16.1 (05-27-2015)
===================

- Fix regression in static file handling (`#377 <https://github.com/aio-libs/aiohttp/pull/377>`_)

0.16.0 (05-26-2015)
===================

- Unset waiter future after cancellation (`#363 <https://github.com/aio-libs/aiohttp/pull/363>`_)

- Update request url with query parameters (`#372 <https://github.com/aio-libs/aiohttp/pull/372>`_)

- Support new `fingerprint` param of TCPConnector to enable verifying
  SSL certificates via MD5, SHA1, or SHA256 digest (`#366 <https://github.com/aio-libs/aiohttp/pull/366>`_)

- Setup uploaded filename if field value is binary and transfer
  encoding is not specified (`#349 <https://github.com/aio-libs/aiohttp/pull/349>`_)

- Implement `ClientSession.close()` method

- Implement `connector.closed` readonly property

- Implement `ClientSession.closed` readonly property

- Implement `ClientSession.connector` readonly property

- Implement `ClientSession.detach` method

- Add `__del__` to client-side objects: sessions, connectors,
  connections, requests, responses.

- Refactor connections cleanup by connector (`#357 <https://github.com/aio-libs/aiohttp/pull/357>`_)

- Add `limit` parameter to connector constructor (`#358 <https://github.com/aio-libs/aiohttp/pull/358>`_)

- Add `request.has_body` property (`#364 <https://github.com/aio-libs/aiohttp/pull/364>`_)

- Add `response_class` parameter to `ws_connect()` (`#367 <https://github.com/aio-libs/aiohttp/pull/367>`_)

- `ProxyConnector` does not support keep-alive requests by default
  starting from now (`#368 <https://github.com/aio-libs/aiohttp/pull/368>`_)

- Add `connector.force_close` property

- Add ws_connect to ClientSession (`#374 <https://github.com/aio-libs/aiohttp/pull/374>`_)

- Support optional `chunk_size` parameter in `router.add_static()`


0.15.3 (04-22-2015)
===================

- Fix graceful shutdown handling

- Fix `Expect` header handling for not found and not allowed routes (`#340 <https://github.com/aio-libs/aiohttp/pull/340>`_)


0.15.2 (04-19-2015)
===================

- Flow control subsystem refactoring

- HTTP server performance optimizations

- Allow to match any request method with `*`

- Explicitly call drain on transport (`#316 <https://github.com/aio-libs/aiohttp/pull/316>`_)

- Make chardet module dependency mandatory (`#318 <https://github.com/aio-libs/aiohttp/pull/318>`_)

- Support keep-alive for HTTP 1.0 (`#325 <https://github.com/aio-libs/aiohttp/pull/325>`_)

- Do not chunk single file during upload (`#327 <https://github.com/aio-libs/aiohttp/pull/327>`_)

- Add ClientSession object for cookie storage and default headers (`#328 <https://github.com/aio-libs/aiohttp/pull/328>`_)

- Add `keep_alive_on` argument for HTTP server handler.


0.15.1 (03-31-2015)
===================

- Pass Autobahn Testsuite tests

- Fixed websocket fragmentation

- Fixed websocket close procedure

- Fixed parser buffer limits

- Added `timeout` parameter to WebSocketResponse ctor

- Added `WebSocketResponse.close_code` attribute


0.15.0 (03-27-2015)
===================

- Client WebSockets support

- New Multipart system (`#273 <https://github.com/aio-libs/aiohttp/pull/273>`_)

- Support for "Except" header (`#287 <https://github.com/aio-libs/aiohttp/pull/287>`_) (`#267 <https://github.com/aio-libs/aiohttp/pull/267>`_)

- Set default Content-Type for post requests (`#184 <https://github.com/aio-libs/aiohttp/pull/184>`_)

- Fix issue with construction dynamic route with regexps and trailing slash (`#266 <https://github.com/aio-libs/aiohttp/pull/266>`_)

- Add repr to web.Request

- Add repr to web.Response

- Add repr for NotFound and NotAllowed match infos

- Add repr for web.Application

- Add repr to UrlMappingMatchInfo (`#217 <https://github.com/aio-libs/aiohttp/pull/217>`_)

- Gunicorn 19.2.x compatibility


0.14.4 (01-29-2015)
===================

- Fix issue with error during constructing of url with regex parts (`#264 <https://github.com/aio-libs/aiohttp/pull/264>`_)


0.14.3 (01-28-2015)
===================

- Use path='/' by default for cookies (`#261 <https://github.com/aio-libs/aiohttp/pull/261>`_)


0.14.2 (01-23-2015)
===================

- Connections leak in BaseConnector (`#253 <https://github.com/aio-libs/aiohttp/pull/253>`_)

- Do not swallow websocket reader exceptions (`#255 <https://github.com/aio-libs/aiohttp/pull/255>`_)

- web.Request's read, text, json are memorized (`#250 <https://github.com/aio-libs/aiohttp/pull/250>`_)


0.14.1 (01-15-2015)
===================

- HttpMessage._add_default_headers does not overwrite existing headers (`#216 <https://github.com/aio-libs/aiohttp/pull/216>`_)

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

- Application does not accept `**kwargs` anymore ((`#243 <https://github.com/aio-libs/aiohttp/pull/243>`_)).

- Request is inherited from dict now for making per-request storage to
  middlewares ((`#242 <https://github.com/aio-libs/aiohttp/pull/242>`_)).


0.13.1 (12-31-2014)
===================

- Add `aiohttp.web.StreamResponse.started` property (`#213 <https://github.com/aio-libs/aiohttp/pull/213>`_)

- HTML escape traceback text in `ServerHttpProtocol.handle_error`

- Mention handler and middlewares in `aiohttp.web.RequestHandler.handle_request`
  on error ((`#218 <https://github.com/aio-libs/aiohttp/pull/218>`_))


0.13.0 (12-29-2014)
===================

- `StreamResponse.charset` converts value to lower-case on assigning.

- Chain exceptions when raise `ClientRequestError`.

- Support custom regexps in route variables (`#204 <https://github.com/aio-libs/aiohttp/pull/204>`_)

- Fixed graceful shutdown, disable keep-alive on connection closing.

- Decode HTTP message with `utf-8` encoding, some servers send headers
  in utf-8 encoding (`#207 <https://github.com/aio-libs/aiohttp/pull/207>`_)

- Support `aiohtt.web` middlewares (`#209 <https://github.com/aio-libs/aiohttp/pull/209>`_)

- Add ssl_context to TCPConnector (`#206 <https://github.com/aio-libs/aiohttp/pull/206>`_)


0.12.0 (12-12-2014)
===================

- Deep refactoring of `aiohttp.web` in backward-incompatible manner.
  Sorry, we have to do this.

- Automatically force aiohttp.web handlers to coroutines in
  `UrlDispatcher.add_route()` (`#186 <https://github.com/aio-libs/aiohttp/pull/186>`_)

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
===================

- Support named routes in `aiohttp.web.UrlDispatcher` (`#179 <https://github.com/aio-libs/aiohttp/pull/179>`_)

- Make websocket subprotocols conform to spec (`#181 <https://github.com/aio-libs/aiohttp/pull/181>`_)


0.10.2 (11-19-2014)
===================

- Don't unquote `environ['PATH_INFO']` in wsgi.py (`#177 <https://github.com/aio-libs/aiohttp/pull/177>`_)


0.10.1 (11-17-2014)
===================

- aiohttp.web.HTTPException and descendants now files response body
  with string like `404: NotFound`

- Fix multidict `__iter__`, the method should iterate over keys, not
  (key, value) pairs.


0.10.0 (11-13-2014)
===================

- Add aiohttp.web subpackage for highlevel HTTP server support.

- Add *reason* optional parameter to aiohttp.protocol.Response ctor.

- Fix aiohttp.client bug for sending file without content-type.

- Change error text for connection closed between server responses
  from 'Can not read status line' to explicit 'Connection closed by
  server'

- Drop closed connections from connector (`#173 <https://github.com/aio-libs/aiohttp/pull/173>`_)

- Set server.transport to None on .closing() (`#172 <https://github.com/aio-libs/aiohttp/pull/172>`_)


0.9.3 (10-30-2014)
==================

- Fix compatibility with asyncio 3.4.1+ (`#170 <https://github.com/aio-libs/aiohttp/pull/170>`_)


0.9.2 (10-16-2014)
==================

- Improve redirect handling (`#157 <https://github.com/aio-libs/aiohttp/pull/157>`_)

- Send raw files as is (`#153 <https://github.com/aio-libs/aiohttp/pull/153>`_)

- Better websocket support (`#150 <https://github.com/aio-libs/aiohttp/pull/150>`_)


0.9.1 (08-30-2014)
==================

- Added MultiDict support for client request params and data (`#114 <https://github.com/aio-libs/aiohttp/pull/114>`_).

- Fixed parameter type for IncompleteRead exception (`#118 <https://github.com/aio-libs/aiohttp/pull/118>`_).

- Strictly require ASCII headers names and values (`#137 <https://github.com/aio-libs/aiohttp/pull/137>`_)

- Keep port in ProxyConnector (`#128 <https://github.com/aio-libs/aiohttp/pull/128>`_).

- Python 3.4.1 compatibility (`#131 <https://github.com/aio-libs/aiohttp/pull/131>`_).


0.9.0 (07-08-2014)
==================

- Better client basic authentication support (`#112 <https://github.com/aio-libs/aiohttp/pull/112>`_).

- Fixed incorrect line splitting in HttpRequestParser (`#97 <https://github.com/aio-libs/aiohttp/pull/97>`_).

- Support StreamReader and DataQueue as request data.

- Client files handling refactoring (`#20 <https://github.com/aio-libs/aiohttp/pull/20>`_).

- Backward incompatible: Replace DataQueue with StreamReader for
  request payload (`#87 <https://github.com/aio-libs/aiohttp/pull/87>`_).


0.8.4 (07-04-2014)
==================

- Change ProxyConnector authorization parameters.


0.8.3 (07-03-2014)
==================

- Publish TCPConnector properties: verify_ssl, family, resolve, resolved_hosts.

- Don't parse message body for HEAD responses.

- Refactor client response decoding.


0.8.2 (06-22-2014)
==================

- Make ProxyConnector.proxy immutable property.

- Make UnixConnector.path immutable property.

- Fix resource leak for aiohttp.request() with implicit connector.

- Rename Connector's reuse_timeout to keepalive_timeout.


0.8.1 (06-18-2014)
==================

- Use case insensitive multidict for server request/response headers.

- MultiDict.getall() accepts default value.

- Catch server ConnectionError.

- Accept MultiDict (and derived) instances in aiohttp.request header argument.

- Proxy 'CONNECT' support.


0.8.0 (06-06-2014)
==================

- Add support for utf-8 values in HTTP headers

- Allow to use custom response class instead of HttpResponse

- Use MultiDict for client request headers

- Use MultiDict for server request/response headers

- Store response headers in ClientResponse.headers attribute

- Get rid of timeout parameter in aiohttp.client API

- Exceptions refactoring


0.7.3 (05-20-2014)
==================

- Simple HTTP proxy support.


0.7.2 (05-14-2014)
==================

- Get rid of `__del__` methods

- Use ResourceWarning instead of logging warning record.


0.7.1 (04-28-2014)
==================

- Do not unquote client request urls.

- Allow multiple waiters on transport drain.

- Do not return client connection to pool in case of exceptions.

- Rename SocketConnector to TCPConnector and UnixSocketConnector to
  UnixConnector.


0.7.0 (04-16-2014)
==================

- Connection flow control.

- HTTP client session/connection pool refactoring.

- Better handling for bad server requests.


0.6.5 (03-29-2014)
==================

- Added client session reuse timeout.

- Better client request cancellation support.

- Better handling responses without content length.

- Added HttpClient verify_ssl parameter support.


0.6.4 (02-27-2014)
==================

- Log content-length missing warning only for put and post requests.


0.6.3 (02-27-2014)
==================

- Better support for server exit.

- Read response body until EOF if content-length is not defined (`#14 <https://github.com/aio-libs/aiohttp/pull/14>`_)


0.6.2 (02-18-2014)
==================

- Fix trailing char in allowed_methods.

- Start slow request timer for first request.


0.6.1 (02-17-2014)
==================

- Added utility method HttpResponse.read_and_close()

- Added slow request timeout.

- Enable socket SO_KEEPALIVE if available.


0.6.0 (02-12-2014)
==================

- Better handling for process exit.


0.5.0 (01-29-2014)
==================

- Allow to use custom HttpRequest client class.

- Use gunicorn keepalive setting for asynchronous worker.

- Log leaking responses.

- python 3.4 compatibility


0.4.4 (11-15-2013)
==================

- Resolve only AF_INET family, because it is not clear how to pass
  extra info to asyncio.


0.4.3 (11-15-2013)
==================

- Allow to wait completion of request with `HttpResponse.wait_for_close()`


0.4.2 (11-14-2013)
==================

- Handle exception in client request stream.

- Prevent host resolving for each client request.


0.4.1 (11-12-2013)
==================

- Added client support for `expect: 100-continue` header.


0.4 (11-06-2013)
================

- Added custom wsgi application close procedure

- Fixed concurrent host failure in HttpClient


0.3 (11-04-2013)
================

- Added PortMapperWorker

- Added HttpClient

- Added TCP connection timeout to HTTP client

- Better client connection errors handling

- Gracefully handle process exit


0.2
===

- Fix packaging
