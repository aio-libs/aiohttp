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
