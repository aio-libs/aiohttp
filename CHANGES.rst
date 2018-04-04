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

3.1.1 (2018-03-27)
==================

* Support *asynchronous iterators* (and *asynchronous generators* as
  well) in both client and server API as request / response BODY
  payloads. (#2802)


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
  "application/xxx+json" instead of strict "application/json". (#2206)
- Bump C HTTP parser to version 2.8 (#2730)
- Accept a coroutine as an application factory in ``web.run_app`` and gunicorn
  worker. (#2739)
- Implement application cleanup context (``app.cleanup_ctx`` property). (#2747)
- Make ``writer.write_headers`` a coroutine. (#2762)
- Add tracking signals for getting request/response bodies. (#2767)
- Deprecate ClientResponseError.code in favor of .status to keep similarity
  with response classes. (#2781)
- Implement ``app.add_routes()`` method. (#2787)
- Implement ``web.static()`` and ``RouteTableDef.static()`` API. (#2795)
- Install a test event loop as default by ``asyncio.set_event_loop()``. The
  change affects aiohttp test utils but backward compatibility is not broken
  for 99.99% of use cases. (#2804)
- Refactor ``ClientResponse`` constructor: make logically required constructor
  arguments mandatory, drop ``_post_init()`` method. (#2820)
- Use ``app.add_routes()`` in server docs everywhere (#2830)
- Websockets refactoring, all websocket writer methods are converted into
  coroutines. (#2836)
- Provide ``Content-Range`` header for ``Range`` requests (#2844)


Bugfixes
--------

- Fix websocket client return EofStream. (#2784)
- Fix websocket demo. (#2789)
- Property ``BaseRequest.http_range`` now returns a python-like slice when
  requesting the tail of the range. It's now indicated by a negative value in
  ``range.start`` rather then in ``range.stop`` (#2805)
- Close a connection if an unexpected exception occurs while sending a request
  (#2827)
- Fix firing DNS tracing events. (#2841)


Improved Documentation
----------------------

- Change ``ClientResponse.json()`` documentation to reflect that it now
  allows "application/xxx+json" content-types (#2206)
- Document behavior when cchardet detects encodings that are unknown to Python.
  (#2732)
- Add diagrams for tracing request life style. (#2748)
- Drop removed functionality for passing ``StreamReader`` as data at client
  side. (#2793)
