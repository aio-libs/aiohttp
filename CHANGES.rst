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

3.7.4.post0 (2021-03-06)
========================

Misc
----

- Bumped upper bound of the ``chardet`` runtime dependency
  to allow their v4.0 version stream.
  `#5366 <https://github.com/aio-libs/aiohttp/issues/5366>`_


----


3.7.4 (2021-02-25)
==================

Bugfixes
--------

- **(SECURITY BUG)** Started preventing open redirects in the
  ``aiohttp.web.normalize_path_middleware`` middleware. For
  more details, see
  https://github.com/aio-libs/aiohttp/security/advisories/GHSA-v6wp-4m6f-gcjg.

  Thanks to `Beast Glatisant <https://github.com/g147>`__ for
  finding the first instance of this issue and `Jelmer Vernooĳ
  <https://jelmer.uk/>`__ for reporting and tracking it down
  in aiohttp.
  `#5497 <https://github.com/aio-libs/aiohttp/issues/5497>`_
- Fix interpretation difference of the pure-Python and the Cython-based
  HTTP parsers construct a ``yarl.URL`` object for HTTP request-target.

  Before this fix, the Python parser would turn the URI's absolute-path
  for ``//some-path`` into ``/`` while the Cython code preserved it as
  ``//some-path``. Now, both do the latter.
  `#5498 <https://github.com/aio-libs/aiohttp/issues/5498>`_


----


3.7.3 (2020-11-18)
==================

Features
--------

- Use Brotli instead of brotlipy
  `#3803 <https://github.com/aio-libs/aiohttp/issues/3803>`_
- Made exceptions pickleable. Also changed the repr of some exceptions.
  `#4077 <https://github.com/aio-libs/aiohttp/issues/4077>`_


Bugfixes
--------

- Raise a ClientResponseError instead of an AssertionError for a blank
  HTTP Reason Phrase.
  `#3532 <https://github.com/aio-libs/aiohttp/issues/3532>`_
- Fix ``web_middlewares.normalize_path_middleware`` behavior for patch without slash.
  `#3669 <https://github.com/aio-libs/aiohttp/issues/3669>`_
- Fix overshadowing of overlapped sub-applications prefixes.
  `#3701 <https://github.com/aio-libs/aiohttp/issues/3701>`_
- Make `BaseConnector.close()` a coroutine and wait until the client closes all connections. Drop deprecated "with Connector():" syntax.
  `#3736 <https://github.com/aio-libs/aiohttp/issues/3736>`_
- Reset the ``sock_read`` timeout each time data is received for a ``aiohttp.client`` response.
  `#3808 <https://github.com/aio-libs/aiohttp/issues/3808>`_
- Fixed type annotation for add_view method of UrlDispatcher to accept any subclass of View
  `#3880 <https://github.com/aio-libs/aiohttp/issues/3880>`_
- Fixed querying the address families from DNS that the current host supports.
  `#5156 <https://github.com/aio-libs/aiohttp/issues/5156>`_
- Change return type of MultipartReader.__aiter__() and BodyPartReader.__aiter__() to AsyncIterator.
  `#5163 <https://github.com/aio-libs/aiohttp/issues/5163>`_
- Provide x86 Windows wheels.
  `#5230 <https://github.com/aio-libs/aiohttp/issues/5230>`_


Improved Documentation
----------------------

- Add documentation for ``aiohttp.web.FileResponse``.
  `#3958 <https://github.com/aio-libs/aiohttp/issues/3958>`_
- Removed deprecation warning in tracing example docs
  `#3964 <https://github.com/aio-libs/aiohttp/issues/3964>`_
- Fixed wrong "Usage" docstring of ``aiohttp.client.request``.
  `#4603 <https://github.com/aio-libs/aiohttp/issues/4603>`_
- Add aiohttp-pydantic to third party libraries
  `#5228 <https://github.com/aio-libs/aiohttp/issues/5228>`_


Misc
----

- `#4102 <https://github.com/aio-libs/aiohttp/issues/4102>`_


----


3.7.2 (2020-10-27)
==================

Bugfixes
--------

- Fixed static files handling for loops without ``.sendfile()`` support
  `#5149 <https://github.com/aio-libs/aiohttp/issues/5149>`_


----


3.7.1 (2020-10-25)
==================

Bugfixes
--------

- Fixed a type error caused by the conditional import of `Protocol`.
  `#5111 <https://github.com/aio-libs/aiohttp/issues/5111>`_
- Server doesn't send Content-Length for 1xx or 204
  `#4901 <https://github.com/aio-libs/aiohttp/issues/4901>`_
- Fix run_app typing
  `#4957 <https://github.com/aio-libs/aiohttp/issues/4957>`_
- Always require ``typing_extensions`` library.
  `#5107 <https://github.com/aio-libs/aiohttp/issues/5107>`_
- Fix a variable-shadowing bug causing `ThreadedResolver.resolve` to
  return the resolved IP as the ``hostname`` in each record, which prevented
  validation of HTTPS connections.
  `#5110 <https://github.com/aio-libs/aiohttp/issues/5110>`_
- Added annotations to all public attributes.
  `#5115 <https://github.com/aio-libs/aiohttp/issues/5115>`_
- Fix flaky test_when_timeout_smaller_second
  `#5116 <https://github.com/aio-libs/aiohttp/issues/5116>`_
- Ensure sending a zero byte file does not throw an exception
  `#5124 <https://github.com/aio-libs/aiohttp/issues/5124>`_
- Fix a bug in ``web.run_app()`` about Python version checking on Windows
  `#5127 <https://github.com/aio-libs/aiohttp/issues/5127>`_


----


3.7.0 (2020-10-24)
==================

Features
--------

- Response headers are now prepared prior to running ``on_response_prepare`` hooks, directly before headers are sent to the client.
  `#1958 <https://github.com/aio-libs/aiohttp/issues/1958>`_
- Add a ``quote_cookie`` option to ``CookieJar``, a way to skip quotation wrapping of cookies containing special characters.
  `#2571 <https://github.com/aio-libs/aiohttp/issues/2571>`_
- Call ``AccessLogger.log`` with the current exception available from ``sys.exc_info()``.
  `#3557 <https://github.com/aio-libs/aiohttp/issues/3557>`_
- `web.UrlDispatcher.add_routes` and `web.Application.add_routes` return a list
  of registered `AbstractRoute` instances. `AbstractRouteDef.register` (and all
  subclasses) return a list of registered resources registered resource.
  `#3866 <https://github.com/aio-libs/aiohttp/issues/3866>`_
- Added properties of default ClientSession params to ClientSession class so it is available for introspection
  `#3882 <https://github.com/aio-libs/aiohttp/issues/3882>`_
- Don't cancel web handler on peer disconnection, raise `OSError` on reading/writing instead.
  `#4080 <https://github.com/aio-libs/aiohttp/issues/4080>`_
- Implement BaseRequest.get_extra_info() to access a protocol transports' extra info.
  `#4189 <https://github.com/aio-libs/aiohttp/issues/4189>`_
- Added `ClientSession.timeout` property.
  `#4191 <https://github.com/aio-libs/aiohttp/issues/4191>`_
- allow use of SameSite in cookies.
  `#4224 <https://github.com/aio-libs/aiohttp/issues/4224>`_
- Use ``loop.sendfile()`` instead of custom implementation if available.
  `#4269 <https://github.com/aio-libs/aiohttp/issues/4269>`_
- Apply SO_REUSEADDR to test server's socket.
  `#4393 <https://github.com/aio-libs/aiohttp/issues/4393>`_
- Use .raw_host instead of slower .host in client API
  `#4402 <https://github.com/aio-libs/aiohttp/issues/4402>`_
- Allow configuring the buffer size of input stream by passing ``read_bufsize`` argument.
  `#4453 <https://github.com/aio-libs/aiohttp/issues/4453>`_
- Pass tests on Python 3.8 for Windows.
  `#4513 <https://github.com/aio-libs/aiohttp/issues/4513>`_
- Add `method` and `url` attributes to `TraceRequestChunkSentParams` and `TraceResponseChunkReceivedParams`.
  `#4674 <https://github.com/aio-libs/aiohttp/issues/4674>`_
- Add ClientResponse.ok property for checking status code under 400.
  `#4711 <https://github.com/aio-libs/aiohttp/issues/4711>`_
- Don't ceil timeouts that are smaller than 5 seconds.
  `#4850 <https://github.com/aio-libs/aiohttp/issues/4850>`_
- TCPSite now listens by default on all interfaces instead of just IPv4 when `None` is passed in as the host.
  `#4894 <https://github.com/aio-libs/aiohttp/issues/4894>`_
- Bump ``http_parser`` to 2.9.4
  `#5070 <https://github.com/aio-libs/aiohttp/issues/5070>`_


Bugfixes
--------

- Fix keepalive connections not being closed in time
  `#3296 <https://github.com/aio-libs/aiohttp/issues/3296>`_
- Fix failed websocket handshake leaving connection hanging.
  `#3380 <https://github.com/aio-libs/aiohttp/issues/3380>`_
- Fix tasks cancellation order on exit. The run_app task needs to be cancelled first for cleanup hooks to run with all tasks intact.
  `#3805 <https://github.com/aio-libs/aiohttp/issues/3805>`_
- Don't start heartbeat until _writer is set
  `#4062 <https://github.com/aio-libs/aiohttp/issues/4062>`_
- Fix handling of multipart file uploads without a content type.
  `#4089 <https://github.com/aio-libs/aiohttp/issues/4089>`_
- Preserve view handler function attributes across middlewares
  `#4174 <https://github.com/aio-libs/aiohttp/issues/4174>`_
- Fix the string representation of ``ServerDisconnectedError``.
  `#4175 <https://github.com/aio-libs/aiohttp/issues/4175>`_
- Raising RuntimeError when trying to get encoding from not read body
  `#4214 <https://github.com/aio-libs/aiohttp/issues/4214>`_
- Remove warning messages from noop.
  `#4282 <https://github.com/aio-libs/aiohttp/issues/4282>`_
- Raise ClientPayloadError if FormData re-processed.
  `#4345 <https://github.com/aio-libs/aiohttp/issues/4345>`_
- Fix a warning about unfinished task in ``web_protocol.py``
  `#4408 <https://github.com/aio-libs/aiohttp/issues/4408>`_
- Fixed 'deflate' compression. According to RFC 2616 now.
  `#4506 <https://github.com/aio-libs/aiohttp/issues/4506>`_
- Fixed OverflowError on platforms with 32-bit time_t
  `#4515 <https://github.com/aio-libs/aiohttp/issues/4515>`_
- Fixed request.body_exists returns wrong value for methods without body.
  `#4528 <https://github.com/aio-libs/aiohttp/issues/4528>`_
- Fix connecting to link-local IPv6 addresses.
  `#4554 <https://github.com/aio-libs/aiohttp/issues/4554>`_
- Fix a problem with connection waiters that are never awaited.
  `#4562 <https://github.com/aio-libs/aiohttp/issues/4562>`_
- Always make sure transport is not closing before reuse a connection.

  Reuse a protocol based on keepalive in headers is unreliable.
  For example, uWSGI will not support keepalive even it serves a
  HTTP 1.1 request, except explicitly configure uWSGI with a
  ``--http-keepalive`` option.

  Servers designed like uWSGI could cause aiohttp intermittently
  raise a ConnectionResetException when the protocol poll runs
  out and some protocol is reused.
  `#4587 <https://github.com/aio-libs/aiohttp/issues/4587>`_
- Handle the last CRLF correctly even if it is received via separate TCP segment.
  `#4630 <https://github.com/aio-libs/aiohttp/issues/4630>`_
- Fix the register_resource function to validate route name before splitting it so that route name can include python keywords.
  `#4691 <https://github.com/aio-libs/aiohttp/issues/4691>`_
- Improve typing annotations for ``web.Request``, ``aiohttp.ClientResponse`` and
  ``multipart`` module.
  `#4736 <https://github.com/aio-libs/aiohttp/issues/4736>`_
- Fix resolver task is not awaited when connector is cancelled
  `#4795 <https://github.com/aio-libs/aiohttp/issues/4795>`_
- Fix a bug "Aiohttp doesn't return any error on invalid request methods"
  `#4798 <https://github.com/aio-libs/aiohttp/issues/4798>`_
- Fix HEAD requests for static content.
  `#4809 <https://github.com/aio-libs/aiohttp/issues/4809>`_
- Fix incorrect size calculation for memoryview
  `#4890 <https://github.com/aio-libs/aiohttp/issues/4890>`_
- Add HTTPMove to _all__.
  `#4897 <https://github.com/aio-libs/aiohttp/issues/4897>`_
- Fixed the type annotations in the ``tracing`` module.
  `#4912 <https://github.com/aio-libs/aiohttp/issues/4912>`_
- Fix typing for multipart ``__aiter__``.
  `#4931 <https://github.com/aio-libs/aiohttp/issues/4931>`_
- Fix for race condition on connections in BaseConnector that leads to exceeding the connection limit.
  `#4936 <https://github.com/aio-libs/aiohttp/issues/4936>`_
- Add forced UTF-8 encoding for ``application/rdap+json`` responses.
  `#4938 <https://github.com/aio-libs/aiohttp/issues/4938>`_
- Fix inconsistency between Python and C http request parsers in parsing pct-encoded URL.
  `#4972 <https://github.com/aio-libs/aiohttp/issues/4972>`_
- Fix connection closing issue in HEAD request.
  `#5012 <https://github.com/aio-libs/aiohttp/issues/5012>`_
- Fix type hint on BaseRunner.addresses (from ``List[str]`` to ``List[Any]``)
  `#5086 <https://github.com/aio-libs/aiohttp/issues/5086>`_
- Make `web.run_app()` more responsive to Ctrl+C on Windows for Python < 3.8. It slightly
  increases CPU load as a side effect.
  `#5098 <https://github.com/aio-libs/aiohttp/issues/5098>`_


Improved Documentation
----------------------

- Fix example code in client quick-start
  `#3376 <https://github.com/aio-libs/aiohttp/issues/3376>`_
- Updated the docs so there is no contradiction in ``ttl_dns_cache`` default value
  `#3512 <https://github.com/aio-libs/aiohttp/issues/3512>`_
- Add 'Deploy with SSL' to docs.
  `#4201 <https://github.com/aio-libs/aiohttp/issues/4201>`_
- Change typing of the secure argument on StreamResponse.set_cookie from ``Optional[str]`` to ``Optional[bool]``
  `#4204 <https://github.com/aio-libs/aiohttp/issues/4204>`_
- Changes ``ttl_dns_cache`` type from int to Optional[int].
  `#4270 <https://github.com/aio-libs/aiohttp/issues/4270>`_
- Simplify README hello word example and add a documentation page for people coming from requests.
  `#4272 <https://github.com/aio-libs/aiohttp/issues/4272>`_
- Improve some code examples in the documentation involving websockets and starting a simple HTTP site with an AppRunner.
  `#4285 <https://github.com/aio-libs/aiohttp/issues/4285>`_
- Fix typo in code example in Multipart docs
  `#4312 <https://github.com/aio-libs/aiohttp/issues/4312>`_
- Fix code example in Multipart section.
  `#4314 <https://github.com/aio-libs/aiohttp/issues/4314>`_
- Update contributing guide so new contributors read the most recent version of that guide. Update command used to create test coverage reporting.
  `#4810 <https://github.com/aio-libs/aiohttp/issues/4810>`_
- Spelling: Change "canonize" to "canonicalize".
  `#4986 <https://github.com/aio-libs/aiohttp/issues/4986>`_
- Add ``aiohttp-sse-client`` library to third party usage list.
  `#5084 <https://github.com/aio-libs/aiohttp/issues/5084>`_


Misc
----

- `#2856 <https://github.com/aio-libs/aiohttp/issues/2856>`_, `#4218 <https://github.com/aio-libs/aiohttp/issues/4218>`_, `#4250 <https://github.com/aio-libs/aiohttp/issues/4250>`_


----


3.6.3 (2020-10-12)
==================

Bugfixes
--------

- Pin yarl to ``<1.6.0`` to avoid buggy behavior that will be fixed by the next aiohttp
  release.

3.6.2 (2019-10-09)
==================

Features
--------

- Made exceptions pickleable. Also changed the repr of some exceptions.
  `#4077 <https://github.com/aio-libs/aiohttp/issues/4077>`_
- Use ``Iterable`` type hint instead of ``Sequence`` for ``Application`` *middleware*
  parameter.  `#4125 <https://github.com/aio-libs/aiohttp/issues/4125>`_


Bugfixes
--------

- Reset the ``sock_read`` timeout each time data is received for a
  ``aiohttp.ClientResponse``.  `#3808
  <https://github.com/aio-libs/aiohttp/issues/3808>`_
- Fix handling of expired cookies so they are not stored in CookieJar.
  `#4063 <https://github.com/aio-libs/aiohttp/issues/4063>`_
- Fix misleading message in the string representation of ``ClientConnectorError``;
  ``self.ssl == None`` means default SSL context, not SSL disabled `#4097
  <https://github.com/aio-libs/aiohttp/issues/4097>`_
- Don't clobber HTTP status when using FileResponse.
  `#4106 <https://github.com/aio-libs/aiohttp/issues/4106>`_


Improved Documentation
----------------------

- Added minimal required logging configuration to logging documentation.
  `#2469 <https://github.com/aio-libs/aiohttp/issues/2469>`_
- Update docs to reflect proxy support.
  `#4100 <https://github.com/aio-libs/aiohttp/issues/4100>`_
- Fix typo in code example in testing docs.
  `#4108 <https://github.com/aio-libs/aiohttp/issues/4108>`_


Misc
----

- `#4102 <https://github.com/aio-libs/aiohttp/issues/4102>`_


----


3.6.1 (2019-09-19)
==================

Features
--------

- Compatibility with Python 3.8.
  `#4056 <https://github.com/aio-libs/aiohttp/issues/4056>`_


Bugfixes
--------

- correct some exception string format
  `#4068 <https://github.com/aio-libs/aiohttp/issues/4068>`_
- Emit a warning when ``ssl.OP_NO_COMPRESSION`` is
  unavailable because the runtime is built against
  an outdated OpenSSL.
  `#4052 <https://github.com/aio-libs/aiohttp/issues/4052>`_
- Update multidict requirement to >= 4.5
  `#4057 <https://github.com/aio-libs/aiohttp/issues/4057>`_


Improved Documentation
----------------------

- Provide pytest-aiohttp namespace for pytest fixtures in docs.
  `#3723 <https://github.com/aio-libs/aiohttp/issues/3723>`_


----


3.6.0 (2019-09-06)
==================

Features
--------

- Add support for Named Pipes (Site and Connector) under Windows. This feature requires
  Proactor event loop to work.  `#3629
  <https://github.com/aio-libs/aiohttp/issues/3629>`_
- Removed ``Transfer-Encoding: chunked`` header from websocket responses to be
  compatible with more http proxy servers.  `#3798
  <https://github.com/aio-libs/aiohttp/issues/3798>`_
- Accept non-GET request for starting websocket handshake on server side.
  `#3980 <https://github.com/aio-libs/aiohttp/issues/3980>`_


Bugfixes
--------

- Raise a ClientResponseError instead of an AssertionError for a blank
  HTTP Reason Phrase.
  `#3532 <https://github.com/aio-libs/aiohttp/issues/3532>`_
- Fix an issue where cookies would sometimes not be set during a redirect.
  `#3576 <https://github.com/aio-libs/aiohttp/issues/3576>`_
- Change normalize_path_middleware to use 308 redirect instead of 301.

  This behavior should prevent clients from being unable to use PUT/POST
  methods on endpoints that are redirected because of a trailing slash.
  `#3579 <https://github.com/aio-libs/aiohttp/issues/3579>`_
- Drop the processed task from ``all_tasks()`` list early. It prevents logging about a
  task with unhandled exception when the server is used in conjunction with
  ``asyncio.run()``.  `#3587 <https://github.com/aio-libs/aiohttp/issues/3587>`_
- ``Signal`` type annotation changed from ``Signal[Callable[['TraceConfig'],
  Awaitable[None]]]`` to ``Signal[Callable[ClientSession, SimpleNamespace, ...]``.
  `#3595 <https://github.com/aio-libs/aiohttp/issues/3595>`_
- Use sanitized URL as Location header in redirects
  `#3614 <https://github.com/aio-libs/aiohttp/issues/3614>`_
- Improve typing annotations for multipart.py along with changes required
  by mypy in files that references multipart.py.
  `#3621 <https://github.com/aio-libs/aiohttp/issues/3621>`_
- Close session created inside ``aiohttp.request`` when unhandled exception occurs
  `#3628 <https://github.com/aio-libs/aiohttp/issues/3628>`_
- Cleanup per-chunk data in generic data read. Memory leak fixed.
  `#3631 <https://github.com/aio-libs/aiohttp/issues/3631>`_
- Use correct type for add_view and family
  `#3633 <https://github.com/aio-libs/aiohttp/issues/3633>`_
- Fix _keepalive field in __slots__ of ``RequestHandler``.
  `#3644 <https://github.com/aio-libs/aiohttp/issues/3644>`_
- Properly handle ConnectionResetError, to silence the "Cannot write to closing
  transport" exception when clients disconnect uncleanly.
  `#3648 <https://github.com/aio-libs/aiohttp/issues/3648>`_
- Suppress pytest warnings due to ``test_utils`` classes
  `#3660 <https://github.com/aio-libs/aiohttp/issues/3660>`_
- Fix overshadowing of overlapped sub-application prefixes.
  `#3701 <https://github.com/aio-libs/aiohttp/issues/3701>`_
- Fixed return type annotation for WSMessage.json()
  `#3720 <https://github.com/aio-libs/aiohttp/issues/3720>`_
- Properly expose TooManyRedirects publicly as documented.
  `#3818 <https://github.com/aio-libs/aiohttp/issues/3818>`_
- Fix missing brackets for IPv6 in proxy CONNECT request
  `#3841 <https://github.com/aio-libs/aiohttp/issues/3841>`_
- Make the signature of ``aiohttp.test_utils.TestClient.request`` match
  ``asyncio.ClientSession.request`` according to the docs `#3852
  <https://github.com/aio-libs/aiohttp/issues/3852>`_
- Use correct style for re-exported imports, makes mypy ``--strict`` mode happy.
  `#3868 <https://github.com/aio-libs/aiohttp/issues/3868>`_
- Fixed type annotation for add_view method of UrlDispatcher to accept any subclass of
  View `#3880 <https://github.com/aio-libs/aiohttp/issues/3880>`_
- Made cython HTTP parser set Reason-Phrase of the response to an empty string if it is
  missing.  `#3906 <https://github.com/aio-libs/aiohttp/issues/3906>`_
- Add URL to the string representation of ClientResponseError.
  `#3959 <https://github.com/aio-libs/aiohttp/issues/3959>`_
- Accept ``istr`` keys in ``LooseHeaders`` type hints.
  `#3976 <https://github.com/aio-libs/aiohttp/issues/3976>`_
- Fixed race conditions in _resolve_host caching and throttling when tracing is enabled.
  `#4013 <https://github.com/aio-libs/aiohttp/issues/4013>`_
- For URLs like "unix://localhost/..." set Host HTTP header to "localhost" instead of
  "localhost:None".  `#4039 <https://github.com/aio-libs/aiohttp/issues/4039>`_


Improved Documentation
----------------------

- Modify documentation for Background Tasks to remove deprecated usage of event loop.
  `#3526 <https://github.com/aio-libs/aiohttp/issues/3526>`_
- use ``if __name__ == '__main__':`` in server examples.
  `#3775 <https://github.com/aio-libs/aiohttp/issues/3775>`_
- Update documentation reference to the default access logger.
  `#3783 <https://github.com/aio-libs/aiohttp/issues/3783>`_
- Improve documentation for ``web.BaseRequest.path`` and ``web.BaseRequest.raw_path``.
  `#3791 <https://github.com/aio-libs/aiohttp/issues/3791>`_
- Removed deprecation warning in tracing example docs
  `#3964 <https://github.com/aio-libs/aiohttp/issues/3964>`_


----


3.5.4 (2019-01-12)
==================

Bugfixes
--------

- Fix stream ``.read()`` / ``.readany()`` / ``.iter_any()`` which used to return a
  partial content only in case of compressed content
  `#3525 <https://github.com/aio-libs/aiohttp/issues/3525>`_


3.5.3 (2019-01-10)
==================

Bugfixes
--------

- Fix type stubs for ``aiohttp.web.run_app(access_log=True)`` and fix edge case of
  ``access_log=True`` and the event loop being in debug mode.  `#3504
  <https://github.com/aio-libs/aiohttp/issues/3504>`_
- Fix ``aiohttp.ClientTimeout`` type annotations to accept ``None`` for fields
  `#3511 <https://github.com/aio-libs/aiohttp/issues/3511>`_
- Send custom per-request cookies even if session jar is empty
  `#3515 <https://github.com/aio-libs/aiohttp/issues/3515>`_
- Restore Linux binary wheels publishing on PyPI

----


3.5.2 (2019-01-08)
==================

Features
--------

- ``FileResponse`` from ``web_fileresponse.py`` uses a ``ThreadPoolExecutor`` to work
  with files asynchronously.  I/O based payloads from ``payload.py`` uses a
  ``ThreadPoolExecutor`` to work with I/O objects asynchronously.  `#3313
  <https://github.com/aio-libs/aiohttp/issues/3313>`_
- Internal Server Errors in plain text if the browser does not support HTML.
  `#3483 <https://github.com/aio-libs/aiohttp/issues/3483>`_


Bugfixes
--------

- Preserve MultipartWriter parts headers on write.  Refactor the way how
  ``Payload.headers`` are handled. Payload instances now always have headers and
  Content-Type defined.  Fix Payload Content-Disposition header reset after initial
  creation.  `#3035 <https://github.com/aio-libs/aiohttp/issues/3035>`_
- Log suppressed exceptions in ``GunicornWebWorker``.
  `#3464 <https://github.com/aio-libs/aiohttp/issues/3464>`_
- Remove wildcard imports.
  `#3468 <https://github.com/aio-libs/aiohttp/issues/3468>`_
- Use the same task for app initialization and web server handling in gunicorn workers.
  It allows to use Python3.7 context vars smoothly.
  `#3471 <https://github.com/aio-libs/aiohttp/issues/3471>`_
- Fix handling of chunked+gzipped response when first chunk does not give uncompressed
  data `#3477 <https://github.com/aio-libs/aiohttp/issues/3477>`_
- Replace ``collections.MutableMapping`` with ``collections.abc.MutableMapping`` to
  avoid a deprecation warning.  `#3480
  <https://github.com/aio-libs/aiohttp/issues/3480>`_
- ``Payload.size`` type annotation changed from ``Optional[float]`` to
  ``Optional[int]``.  `#3484 <https://github.com/aio-libs/aiohttp/issues/3484>`_
- Ignore done tasks when cancels pending activities on ``web.run_app`` finalization.
  `#3497 <https://github.com/aio-libs/aiohttp/issues/3497>`_


Improved Documentation
----------------------

- Add documentation for ``aiohttp.web.HTTPException``.
  `#3490 <https://github.com/aio-libs/aiohttp/issues/3490>`_


Misc
----

- `#3487 <https://github.com/aio-libs/aiohttp/issues/3487>`_


----


3.5.1 (2018-12-24)
====================

- Fix a regression about ``ClientSession._requote_redirect_url`` modification in debug
  mode.

3.5.0 (2018-12-22)
====================

Features
--------

- The library type annotations are checked in strict mode now.
- Add support for setting cookies for individual request (`#2387
  <https://github.com/aio-libs/aiohttp/pull/2387>`_)
- Application.add_domain implementation (`#2809
  <https://github.com/aio-libs/aiohttp/pull/2809>`_)
- The default ``app`` in the request returned by ``test_utils.make_mocked_request`` can
  now have objects assigned to it and retrieved using the ``[]`` operator. (`#3174
  <https://github.com/aio-libs/aiohttp/pull/3174>`_)
- Make ``request.url`` accessible when transport is closed. (`#3177
  <https://github.com/aio-libs/aiohttp/pull/3177>`_)
- Add ``zlib_executor_size`` argument to ``Response`` constructor to allow compression
  to run in a background executor to avoid blocking the main thread and potentially
  triggering health check failures. (`#3205
  <https://github.com/aio-libs/aiohttp/pull/3205>`_)
- Enable users to set ``ClientTimeout`` in ``aiohttp.request`` (`#3213
  <https://github.com/aio-libs/aiohttp/pull/3213>`_)
- Don't raise a warning if ``NETRC`` environment variable is not set and ``~/.netrc``
  file doesn't exist. (`#3267 <https://github.com/aio-libs/aiohttp/pull/3267>`_)
- Add default logging handler to web.run_app If the ``Application.debug``` flag is set
  and the default logger ``aiohttp.access`` is used, access logs will now be output
  using a *stderr* ``StreamHandler`` if no handlers are attached. Furthermore, if the
  default logger has no log level set, the log level will be set to ``DEBUG``. (`#3324
  <https://github.com/aio-libs/aiohttp/pull/3324>`_)
- Add method argument to ``session.ws_connect()``.  Sometimes server API requires a
  different HTTP method for WebSocket connection establishment.  For example, ``Docker
  exec`` needs POST. (`#3378 <https://github.com/aio-libs/aiohttp/pull/3378>`_)
- Create a task per request handling. (`#3406
  <https://github.com/aio-libs/aiohttp/pull/3406>`_)


Bugfixes
--------

- Enable passing ``access_log_class`` via ``handler_args`` (`#3158
  <https://github.com/aio-libs/aiohttp/pull/3158>`_)
- Return empty bytes with end-of-chunk marker in empty stream reader. (`#3186
  <https://github.com/aio-libs/aiohttp/pull/3186>`_)
- Accept ``CIMultiDictProxy`` instances for ``headers`` argument in ``web.Response``
  constructor. (`#3207 <https://github.com/aio-libs/aiohttp/pull/3207>`_)
- Don't uppercase HTTP method in parser (`#3233
  <https://github.com/aio-libs/aiohttp/pull/3233>`_)
- Make method match regexp RFC-7230 compliant (`#3235
  <https://github.com/aio-libs/aiohttp/pull/3235>`_)
- Add ``app.pre_frozen`` state to properly handle startup signals in
  sub-applications. (`#3237 <https://github.com/aio-libs/aiohttp/pull/3237>`_)
- Enhanced parsing and validation of helpers.BasicAuth.decode. (`#3239
  <https://github.com/aio-libs/aiohttp/pull/3239>`_)
- Change imports from collections module in preparation for 3.8. (`#3258
  <https://github.com/aio-libs/aiohttp/pull/3258>`_)
- Ensure Host header is added first to ClientRequest to better replicate browser (`#3265
  <https://github.com/aio-libs/aiohttp/pull/3265>`_)
- Fix forward compatibility with Python 3.8: importing ABCs directly from the
  collections module will not be supported anymore. (`#3273
  <https://github.com/aio-libs/aiohttp/pull/3273>`_)
- Keep the query string by ``normalize_path_middleware``. (`#3278
  <https://github.com/aio-libs/aiohttp/pull/3278>`_)
- Fix missing parameter ``raise_for_status`` for aiohttp.request() (`#3290
  <https://github.com/aio-libs/aiohttp/pull/3290>`_)
- Bracket IPv6 addresses in the HOST header (`#3304
  <https://github.com/aio-libs/aiohttp/pull/3304>`_)
- Fix default message for server ping and pong frames. (`#3308
  <https://github.com/aio-libs/aiohttp/pull/3308>`_)
- Fix tests/test_connector.py typo and tests/autobahn/server.py duplicate loop
  def. (`#3337 <https://github.com/aio-libs/aiohttp/pull/3337>`_)
- Fix false-negative indicator end_of_HTTP_chunk in StreamReader.readchunk function
  (`#3361 <https://github.com/aio-libs/aiohttp/pull/3361>`_)
- Release HTTP response before raising status exception (`#3364
  <https://github.com/aio-libs/aiohttp/pull/3364>`_)
- Fix task cancellation when ``sendfile()`` syscall is used by static file
  handling. (`#3383 <https://github.com/aio-libs/aiohttp/pull/3383>`_)
- Fix stack trace for ``asyncio.TimeoutError`` which was not logged, when it is caught
  in the handler. (`#3414 <https://github.com/aio-libs/aiohttp/pull/3414>`_)


Improved Documentation
----------------------

- Improve documentation of ``Application.make_handler`` parameters. (`#3152
  <https://github.com/aio-libs/aiohttp/pull/3152>`_)
- Fix BaseRequest.raw_headers doc. (`#3215
  <https://github.com/aio-libs/aiohttp/pull/3215>`_)
- Fix typo in TypeError exception reason in ``web.Application._handle`` (`#3229
  <https://github.com/aio-libs/aiohttp/pull/3229>`_)
- Make server access log format placeholder %b documentation reflect
  behavior and docstring. (`#3307 <https://github.com/aio-libs/aiohttp/pull/3307>`_)


Deprecations and Removals
-------------------------

- Deprecate modification of ``session.requote_redirect_url`` (`#2278
  <https://github.com/aio-libs/aiohttp/pull/2278>`_)
- Deprecate ``stream.unread_data()`` (`#3260
  <https://github.com/aio-libs/aiohttp/pull/3260>`_)
- Deprecated use of boolean in ``resp.enable_compression()`` (`#3318
  <https://github.com/aio-libs/aiohttp/pull/3318>`_)
- Encourage creation of aiohttp public objects inside a coroutine (`#3331
  <https://github.com/aio-libs/aiohttp/pull/3331>`_)
- Drop dead ``Connection.detach()`` and ``Connection.writer``. Both methods were broken
  for more than 2 years. (`#3358 <https://github.com/aio-libs/aiohttp/pull/3358>`_)
- Deprecate ``app.loop``, ``request.loop``, ``client.loop`` and ``connector.loop``
  properties. (`#3374 <https://github.com/aio-libs/aiohttp/pull/3374>`_)
- Deprecate explicit debug argument. Use asyncio debug mode instead. (`#3381
  <https://github.com/aio-libs/aiohttp/pull/3381>`_)
- Deprecate body parameter in HTTPException (and derived classes) constructor. (`#3385
  <https://github.com/aio-libs/aiohttp/pull/3385>`_)
- Deprecate bare connector close, use ``async with connector:`` and ``await
  connector.close()`` instead. (`#3417
  <https://github.com/aio-libs/aiohttp/pull/3417>`_)
- Deprecate obsolete ``read_timeout`` and ``conn_timeout`` in ``ClientSession``
  constructor. (`#3438 <https://github.com/aio-libs/aiohttp/pull/3438>`_)


Misc
----

- #3341, #3351
