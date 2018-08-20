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
