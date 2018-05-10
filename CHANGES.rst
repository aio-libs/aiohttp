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
