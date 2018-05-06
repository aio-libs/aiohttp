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

3.2.0 (2018-05-06)
==================

Features
--------

- Raise ``TooManyRedirects`` exception when client gets redirected too many
  times instead of returning last response. (#2631)
- Extract route definitions into separate ``web_routedef.py`` file (#2876)
- Raise an exception on request body reading after sending response. (#2895)
- ClientResponse and RequestInfo now have real_url property, which is request
  url without fragment part being stripped (#2925)
- Speed up connector limiting (#2937)
- Added and links property for ClientResponse object (#2948)
- Add ``request.config_dict`` for exposing nested applications data. (#2949)
- Speed up HTTP headers serialization, server micro-benchmark runs 5% faster
  now. (#2957)
- Apply assertions in debug mode only (#2966)


Bugfixes
--------

- expose property `app` for TestClient (#2891)
- Call on_chunk_sent when write_eof takes as a param the last chunk (#2909)
- A closing bracket was added to __repr__ of resources (#2935)
- Fix compression of FileResponse (#2942)
- Fixes some bugs in the limit connection feature (#2964)


Improved Documentation
----------------------

- Drop ``async_timeout`` usage from documentation for client API in favor of
  ``timeout`` parameter. (#2865)
- Improve Gunicorn logging documentation (#2921)
- Replace multipart writer `.serialize()` method with `.write()` in
  documentation. (#2965)


Deprecations and Removals
-------------------------

- Deprecate Application.make_handler() (#2938)


Misc
----

- #2958
