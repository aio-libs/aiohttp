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
