..
    You should *NOT* be adding new change log entries to this file, this
    file is managed by towncrier. You *may* edit previous change logs to
    fix problems like typo corrections or such.
    To add a new change log entry, please see
    https://pip.pypa.io/en/latest/development/#adding-a-news-entry
    we named the news folder "changes".

    WARNING: Don't drop the next directive!

.. towncrier release notes start

3.11.6 (2024-11-19)
===================

Bug fixes
---------

- Restored the ``force_close`` method to the ``ResponseHandler`` -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9997`.




----


3.11.5 (2024-11-19)
===================

Bug fixes
---------

- Fixed the ``ANY`` method not appearing in :meth:`~aiohttp.web.UrlDispatcher.routes` -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9899`, :issue:`9987`.




----


3.11.4 (2024-11-18)
===================

Bug fixes
---------

- Fixed ``StaticResource`` not allowing the ``OPTIONS`` method after calling ``set_options_route`` -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9972`, :issue:`9975`, :issue:`9976`.




Miscellaneous internal changes
------------------------------

- Improved performance of creating web responses when there are no cookies -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9895`.




----


3.11.3 (2024-11-18)
===================

Bug fixes
---------

- Removed non-existing ``__author__`` from ``dir(aiohttp)`` -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`9918`.



- Restored the ``FlowControlDataQueue`` class -- by :user:`bdraco`.

  This class is no longer used internally, and will be permanently removed in the next major version.


  *Related issues and pull requests on GitHub:*
  :issue:`9963`.




Miscellaneous internal changes
------------------------------

- Improved performance of resolving resources when multiple methods are registered for the same route -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9899`.




----


3.11.2 (2024-11-14)
===================

Bug fixes
---------

- Fixed improperly closed WebSocket connections generating an unhandled exception -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9883`.




----


3.11.1 (2024-11-14)
===================

Bug fixes
---------

- Added a backward compatibility layer to :class:`aiohttp.RequestInfo` to allow creating these objects without a ``real_url`` -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9873`.




----


3.11.0 (2024-11-13)
===================

Bug fixes
---------

- Raise :exc:`aiohttp.ServerFingerprintMismatch` exception on client-side if request through http proxy with mismatching server fingerprint digest: `aiohttp.ClientSession(headers=headers, connector=TCPConnector(ssl=aiohttp.Fingerprint(mismatch_digest), trust_env=True).request(...)` -- by :user:`gangj`.


  *Related issues and pull requests on GitHub:*
  :issue:`6652`.



- Modified websocket :meth:`aiohttp.ClientWebSocketResponse.receive_str`, :py:meth:`aiohttp.ClientWebSocketResponse.receive_bytes`, :py:meth:`aiohttp.web.WebSocketResponse.receive_str` & :py:meth:`aiohttp.web.WebSocketResponse.receive_bytes` methods to raise new :py:exc:`aiohttp.WSMessageTypeError` exception, instead of generic :py:exc:`TypeError`, when websocket messages of incorrect types are received -- by :user:`ara-25`.


  *Related issues and pull requests on GitHub:*
  :issue:`6800`.



- Made ``TestClient.app`` a ``Generic`` so type checkers will know the correct type (avoiding unneeded ``client.app is not None`` checks) -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8977`.



- Fixed the keep-alive connection pool to be FIFO instead of LIFO -- by :user:`bdraco`.

  Keep-alive connections are more likely to be reused before they disconnect.


  *Related issues and pull requests on GitHub:*
  :issue:`9672`.




Features
--------

- Added ``strategy`` parameter to :meth:`aiohttp.web.StreamResponse.enable_compression`
  The value of this parameter is passed to the :func:`zlib.compressobj` function, allowing people
  to use a more sufficient compression algorithm for their data served by :mod:`aiohttp.web`
  -- by :user:`shootkin`


  *Related issues and pull requests on GitHub:*
  :issue:`6257`.



- Added ``server_hostname`` parameter to ``ws_connect``.


  *Related issues and pull requests on GitHub:*
  :issue:`7941`.



- Exported :py:class:`~aiohttp.ClientWSTimeout` to top-level namespace -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8612`.



- Added ``secure``/``httponly``/``samesite`` parameters to ``.del_cookie()`` -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8956`.



- Updated :py:class:`~aiohttp.ClientSession`'s auth logic to include default auth only if the request URL's origin matches _base_url; otherwise, the auth will not be included -- by :user:`MaximZemskov`


  *Related issues and pull requests on GitHub:*
  :issue:`8966`, :issue:`9466`.



- Added ``proxy`` and ``proxy_auth`` parameters to :py:class:`~aiohttp.ClientSession` -- by :user:`meshya`.


  *Related issues and pull requests on GitHub:*
  :issue:`9207`.



- Added ``default_to_multipart`` parameter to ``FormData``.


  *Related issues and pull requests on GitHub:*
  :issue:`9335`.



- Added :py:meth:`~aiohttp.ClientWebSocketResponse.send_frame` and :py:meth:`~aiohttp.web.WebSocketResponse.send_frame` for WebSockets -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9348`.



- Updated :py:class:`~aiohttp.ClientSession` to support paths in ``base_url`` parameter.
  ``base_url`` paths must end with a ``/``  -- by :user:`Cycloctane`.


  *Related issues and pull requests on GitHub:*
  :issue:`9530`.



- Improved performance of reading WebSocket messages with a Cython implementation -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9543`, :issue:`9554`, :issue:`9556`, :issue:`9558`, :issue:`9636`, :issue:`9649`, :issue:`9781`.



- Added ``writer_limit`` to the :py:class:`~aiohttp.web.WebSocketResponse` to be able to adjust the limit before the writer forces the buffer to be drained -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9572`.



- Added an :attr:`~aiohttp.abc.AbstractAccessLogger.enabled` property to :class:`aiohttp.abc.AbstractAccessLogger` to dynamically check if logging is enabled -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9822`.




Deprecations (removal in next major release)
--------------------------------------------

- Deprecate obsolete `timeout: float` and `receive_timeout: Optional[float]` in :py:meth:`~aiohttp.ClientSession.ws_connect`. Change default websocket receive timeout from `None` to `10.0`.


  *Related issues and pull requests on GitHub:*
  :issue:`3945`.




Removals and backward incompatible breaking changes
---------------------------------------------------

- Dropped support for Python 3.8 -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8797`.



- Increased minimum yarl version to 1.17.0 -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`8909`, :issue:`9079`, :issue:`9305`, :issue:`9574`.



- Removed the ``is_ipv6_address`` and ``is_ip4_address`` helpers are they are no longer used -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9344`.



- Changed ``ClientRequest.connection_key`` to be a `NamedTuple` to improve client performance -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9365`.



- ``FlowControlDataQueue`` has been replaced with the ``WebSocketDataQueue`` -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9685`.



- Changed ``ClientRequest.request_info`` to be a `NamedTuple` to improve client performance -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9692`.




Packaging updates and notes for downstreams
-------------------------------------------

- Switched to using the :mod:`propcache <propcache.api>` package for property caching
  -- by :user:`bdraco`.

  The :mod:`propcache <propcache.api>` package is derived from the property caching
  code in :mod:`yarl` and has been broken out to avoid maintaining it for multiple
  projects.


  *Related issues and pull requests on GitHub:*
  :issue:`9394`.



- Separated ``aiohttp.http_websocket`` into multiple files to make it easier to maintain -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9542`, :issue:`9552`.




Contributor-facing changes
--------------------------

- Changed diagram images generator from ``blockdiag`` to ``GraphViz``.
  Generating documentation now requires the GraphViz executable to be included in $PATH or sphinx build configuration.


  *Related issues and pull requests on GitHub:*
  :issue:`9359`.




Miscellaneous internal changes
------------------------------

- Added flake8 settings to avoid some forms of implicit concatenation. -- by :user:`booniepepper`.


  *Related issues and pull requests on GitHub:*
  :issue:`7731`.



- Enabled keep-alive support on proxies (which was originally disabled several years ago) -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8920`.



- Changed web entry point to not listen on TCP when only a Unix path is passed -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`9033`.



- Disabled automatic retries of failed requests in :class:`aiohttp.test_utils.TestClient`'s client session
  (which could potentially hide errors in tests) -- by :user:`ShubhAgarwal-dev`.


  *Related issues and pull requests on GitHub:*
  :issue:`9141`.



- Changed web ``keepalive_timeout`` default to around an hour in order to reduce race conditions on reverse proxies -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`9285`.



- Reduced memory required for stream objects created during the client request lifecycle -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9407`.



- Improved performance of the internal ``DataQueue`` -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9659`.



- Improved performance of calling ``receive`` for WebSockets for the most common message types -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9679`.



- Replace internal helper methods ``method_must_be_empty_body`` and ``status_code_must_be_empty_body`` with simple `set` lookups -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9722`.



- Improved performance of :py:class:`aiohttp.BaseConnector` when there is no ``limit_per_host`` -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9756`.



- Improved performance of sending HTTP requests when there is no body -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9757`.



- Improved performance of the ``WebsocketWriter`` when the protocol is not paused -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9796`.



- Implemented zero copy writes for ``StreamWriter`` -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9839`.




----


3.10.11 (2024-11-13)
====================

Bug fixes
---------

- Authentication provided by a redirect now takes precedence over provided ``auth`` when making requests with the client -- by :user:`PLPeeters`.


  *Related issues and pull requests on GitHub:*
  :issue:`9436`.



- Fixed :py:meth:`WebSocketResponse.close() <aiohttp.web.WebSocketResponse.close>` to discard non-close messages within its timeout window after sending close -- by :user:`lenard-mosys`.


  *Related issues and pull requests on GitHub:*
  :issue:`9506`.



- Fixed a deadlock that could occur while attempting to get a new connection slot after a timeout -- by :user:`bdraco`.

  The connector was not cancellation-safe.


  *Related issues and pull requests on GitHub:*
  :issue:`9670`, :issue:`9671`.



- Fixed the WebSocket flow control calculation undercounting with multi-byte data -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9686`.



- Fixed incorrect parsing of chunk extensions with the pure Python parser -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9851`.



- Fixed system routes polluting the middleware cache -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9852`.




Removals and backward incompatible breaking changes
---------------------------------------------------

- Improved performance of the connector when a connection can be reused -- by :user:`bdraco`.

  If ``BaseConnector.connect`` has been subclassed and replaced with custom logic, the ``ceil_timeout`` must be added.


  *Related issues and pull requests on GitHub:*
  :issue:`9600`.




Miscellaneous internal changes
------------------------------

- Improved performance of the client request lifecycle when there are no cookies -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9470`.



- Improved performance of sending client requests when the writer can finish synchronously -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9485`.



- Improved performance of serializing HTTP headers -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9603`.



- Passing ``enable_cleanup_closed`` to :py:class:`aiohttp.TCPConnector` is now ignored on Python 3.12.7+ and 3.13.1+ since the underlying bug that caused asyncio to leak SSL connections has been fixed upstream -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9726`, :issue:`9736`.



----




3.10.10 (2024-10-10)
====================

Bug fixes
---------

- Fixed error messages from :py:class:`~aiohttp.resolver.AsyncResolver` being swallowed -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9451`, :issue:`9455`.




Features
--------

- Added :exc:`aiohttp.ClientConnectorDNSError` for differentiating DNS resolution errors from other connector errors -- by :user:`mstojcevich`.


  *Related issues and pull requests on GitHub:*
  :issue:`8455`.




Miscellaneous internal changes
------------------------------

- Simplified DNS resolution throttling code to reduce chance of race conditions -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9454`.




----


3.10.9 (2024-10-04)
===================

Bug fixes
---------

- Fixed proxy headers being used in the ``ConnectionKey`` hash when a proxy was not being used -- by :user:`bdraco`.

  If default headers are used, they are also used for proxy headers. This could have led to creating connections that were not needed when one was already available.


  *Related issues and pull requests on GitHub:*
  :issue:`9368`.



- Widened the type of the ``trace_request_ctx`` parameter of
  :meth:`ClientSession.request() <aiohttp.ClientSession.request>` and friends
  -- by :user:`layday`.


  *Related issues and pull requests on GitHub:*
  :issue:`9397`.




Removals and backward incompatible breaking changes
---------------------------------------------------

- Fixed failure to try next host after single-host connection timeout -- by :user:`brettdh`.

  The default client :class:`aiohttp.ClientTimeout` params has changed to include a ``sock_connect`` timeout of 30 seconds so that this correct behavior happens by default.


  *Related issues and pull requests on GitHub:*
  :issue:`7342`.




Miscellaneous internal changes
------------------------------

- Improved performance of resolving hosts with Python 3.12+ -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9342`.



- Reduced memory required for timer objects created during the client request lifecycle -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9406`.




----


3.10.8 (2024-09-28)
===================

Bug fixes
---------

- Fixed cancellation leaking upwards on timeout -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9326`.




----


3.10.7 (2024-09-27)
===================

Bug fixes
---------

- Fixed assembling the :class:`~yarl.URL` for web requests when the host contains a non-default port or IPv6 address -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9309`.




Miscellaneous internal changes
------------------------------

- Improved performance of determining if a URL is absolute -- by :user:`bdraco`.

  The property :attr:`~yarl.URL.absolute` is more performant than the method ``URL.is_absolute()`` and preferred when newer versions of yarl are used.


  *Related issues and pull requests on GitHub:*
  :issue:`9171`.



- Replaced code that can now be handled by ``yarl`` -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9301`.




----


3.10.6 (2024-09-24)
===================

Bug fixes
---------

- Added :exc:`aiohttp.ClientConnectionResetError`. Client code that previously threw :exc:`ConnectionResetError`
  will now throw this -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`9137`.



- Fixed an unclosed transport ``ResourceWarning`` on web handlers -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8875`.



- Fixed resolve_host() 'Task was destroyed but is pending' errors -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8967`.



- Fixed handling of some file-like objects (e.g. ``tarfile.extractfile()``) which raise ``AttributeError`` instead of ``OSError`` when ``fileno`` fails for streaming payload data -- by :user:`ReallyReivax`.


  *Related issues and pull requests on GitHub:*
  :issue:`6732`.



- Fixed web router not matching pre-encoded URLs (requires yarl 1.9.6+) -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8898`, :issue:`9267`.



- Fixed an error when trying to add a route for multiple methods with a path containing a regex pattern -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8998`.



- Fixed ``Response.text`` when body is a ``Payload`` -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`6485`.



- Fixed compressed requests failing when no body was provided -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`9108`.



- Fixed client incorrectly reusing a connection when the previous message had not been fully sent -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8992`.



- Fixed race condition that could cause server to close connection incorrectly at keepalive timeout -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`9140`.



- Fixed Python parser chunked handling with multiple Transfer-Encoding values -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8823`.



- Fixed error handling after 100-continue so server sends 500 response instead of disconnecting -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8876`.



- Stopped adding a default Content-Type header when response has no content -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8858`.



- Added support for URL credentials with empty (zero-length) username, e.g. ``https://:password@host`` -- by :user:`shuckc`


  *Related issues and pull requests on GitHub:*
  :issue:`6494`.



- Stopped logging exceptions from ``web.run_app()`` that would be raised regardless -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`6807`.



- Implemented binding to IPv6 addresses in the pytest server fixture.


  *Related issues and pull requests on GitHub:*
  :issue:`4650`.



- Fixed the incorrect use of flags for ``getnameinfo()`` in the Resolver --by :user:`GitNMLee`

  Link-Local IPv6 addresses can now be handled by the Resolver correctly.


  *Related issues and pull requests on GitHub:*
  :issue:`9032`.



- Fixed StreamResponse.prepared to return True after EOF is sent -- by :user:`arthurdarcet`.


  *Related issues and pull requests on GitHub:*
  :issue:`5343`.



- Changed ``make_mocked_request()`` to use empty payload by default -- by :user:`rahulnht`.


  *Related issues and pull requests on GitHub:*
  :issue:`7167`.



- Used more precise type for ``ClientResponseError.headers``, fixing some type errors when using them -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8768`.



- Changed behavior when returning an invalid response to send a 500 response -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8845`.



- Fixed response reading from closed session to throw an error immediately instead of timing out -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8878`.



- Fixed ``CancelledError`` from one cleanup context stopping other contexts from completing -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8908`.



- Fixed changing scheme/host in ``Response.clone()`` for absolute URLs -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8990`.



- Fixed ``Site.name`` when host is an empty string -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8929`.



- Updated Python parser to reject messages after a close message, matching C parser behaviour -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`9018`.



- Fixed creation of ``SSLContext`` inside of :py:class:`aiohttp.TCPConnector` with multiple event loops in different threads -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9029`.



- Fixed (on Python 3.11+) some edge cases where a task cancellation may get incorrectly suppressed -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`9030`.



- Fixed exception information getting lost on ``HttpProcessingError`` -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`9052`.



- Fixed ``If-None-Match`` not using weak comparison -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`9063`.



- Fixed badly encoded charset crashing when getting response text instead of falling back to charset detector.


  *Related issues and pull requests on GitHub:*
  :issue:`9160`.



- Rejected `\n` in `reason` values to avoid sending broken HTTP messages -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`9167`.



- Changed :py:meth:`ClientResponse.raise_for_status() <aiohttp.ClientResponse.raise_for_status>` to only release the connection when invoked outside an ``async with`` context -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`9239`.




Features
--------

- Improved type on ``params`` to match the underlying type allowed by ``yarl`` -- by :user:`lpetre`.


  *Related issues and pull requests on GitHub:*
  :issue:`8564`.



- Declared Python 3.13 supported -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`8748`.




Removals and backward incompatible breaking changes
---------------------------------------------------

- Improved middleware performance -- by :user:`bdraco`.

  The ``set_current_app`` method was removed from ``UrlMappingMatchInfo`` because it is no longer used, and it was unlikely external caller would ever use it.


  *Related issues and pull requests on GitHub:*
  :issue:`9200`.



- Increased minimum yarl version to 1.12.0 -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9267`.




Improved documentation
----------------------

- Clarified that ``GracefulExit`` needs to be handled in ``AppRunner`` and ``ServerRunner`` when using ``handle_signals=True``. -- by :user:`Daste745`


  *Related issues and pull requests on GitHub:*
  :issue:`4414`.



- Clarified that auth parameter in ClientSession will persist and be included with any request to any origin, even during redirects to different origins.  -- by :user:`MaximZemskov`.


  *Related issues and pull requests on GitHub:*
  :issue:`6764`.



- Clarified which timeout exceptions happen on which timeouts -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8968`.



- Updated ``ClientSession`` parameters to match current code -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8991`.




Packaging updates and notes for downstreams
-------------------------------------------

- Fixed ``test_client_session_timeout_zero`` to not require internet access -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`9004`.




Miscellaneous internal changes
------------------------------

- Improved performance of making requests when there are no auto headers to skip -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`8847`.



- Exported ``aiohttp.TraceRequestHeadersSentParams`` -- by :user:`Hadock-is-ok`.


  *Related issues and pull requests on GitHub:*
  :issue:`8947`.



- Avoided tracing overhead in the http writer when there are no active traces -- by user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9031`.



- Improved performance of reify Cython implementation -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9054`.



- Use :meth:`URL.extend_query() <yarl.URL.extend_query>` to extend query params (requires yarl 1.11.0+) -- by :user:`bdraco`.

  If yarl is older than 1.11.0, the previous slower hand rolled version will be used.


  *Related issues and pull requests on GitHub:*
  :issue:`9068`.



- Improved performance of checking if a host is an IP Address -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9095`.



- Significantly improved performance of middlewares -- by :user:`bdraco`.

  The construction of the middleware wrappers is now cached and is built once per handler instead of on every request.


  *Related issues and pull requests on GitHub:*
  :issue:`9158`, :issue:`9170`.



- Improved performance of web requests -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9168`, :issue:`9169`, :issue:`9172`, :issue:`9174`, :issue:`9175`, :issue:`9241`.



- Improved performance of starting web requests when there is no response prepare hook -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9173`.



- Significantly improved performance of expiring cookies -- by :user:`bdraco`.

  Expiring cookies has been redesigned to use :mod:`heapq` instead of a linear search, to better scale.


  *Related issues and pull requests on GitHub:*
  :issue:`9203`.



- Significantly sped up filtering cookies -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`9204`.




----


3.10.5 (2024-08-19)
=========================

Bug fixes
---------

- Fixed :meth:`aiohttp.ClientResponse.json()` not setting ``status`` when :exc:`aiohttp.ContentTypeError` is raised -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`8742`.




Miscellaneous internal changes
------------------------------

- Improved performance of the WebSocket reader -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`8736`, :issue:`8747`.




----


3.10.4 (2024-08-17)
===================

Bug fixes
---------

- Fixed decoding base64 chunk in BodyPartReader -- by :user:`hyzyla`.


  *Related issues and pull requests on GitHub:*
  :issue:`3867`.



- Fixed a race closing the server-side WebSocket where the close code would not reach the client -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`8680`.



- Fixed unconsumed exceptions raised by the WebSocket heartbeat -- by :user:`bdraco`.

  If the heartbeat ping raised an exception, it would not be consumed and would be logged as an warning.


  *Related issues and pull requests on GitHub:*
  :issue:`8685`.



- Fixed an edge case in the Python parser when chunk separators happen to align with network chunks -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8720`.




Improved documentation
----------------------

- Added ``aiohttp-apischema`` to supported libraries -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8700`.




Miscellaneous internal changes
------------------------------

- Improved performance of starting request handlers with Python 3.12+ -- by :user:`bdraco`.

  This change is a followup to :issue:`8661` to make the same optimization for Python 3.12+ where the request is connected.


  *Related issues and pull requests on GitHub:*
  :issue:`8681`.




----


3.10.3 (2024-08-10)
========================

Bug fixes
---------

- Fixed multipart reading when stream buffer splits the boundary over several read() calls -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8653`.



- Fixed :py:class:`aiohttp.TCPConnector` doing blocking I/O in the event loop to create the ``SSLContext`` -- by :user:`bdraco`.

  The blocking I/O would only happen once per verify mode. However, it could cause the event loop to block for a long time if the ``SSLContext`` creation is slow, which is more likely during startup when the disk cache is not yet present.


  *Related issues and pull requests on GitHub:*
  :issue:`8672`.




Miscellaneous internal changes
------------------------------

- Improved performance of :py:meth:`~aiohttp.ClientWebSocketResponse.receive` and :py:meth:`~aiohttp.web.WebSocketResponse.receive` when there is no timeout. -- by :user:`bdraco`.

  The timeout context manager is now avoided when there is no timeout as it accounted for up to 50% of the time spent in the :py:meth:`~aiohttp.ClientWebSocketResponse.receive` and :py:meth:`~aiohttp.web.WebSocketResponse.receive` methods.


  *Related issues and pull requests on GitHub:*
  :issue:`8660`.



- Improved performance of starting request handlers with Python 3.12+ -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`8661`.



- Improved performance of HTTP keep-alive checks -- by :user:`bdraco`.

  Previously, when processing a request for a keep-alive connection, the keep-alive check would happen every second; the check is now rescheduled if it fires too early instead.


  *Related issues and pull requests on GitHub:*
  :issue:`8662`.



- Improved performance of generating random WebSocket mask -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`8667`.




----


3.10.2 (2024-08-08)
===================

Bug fixes
---------

- Fixed server checks for circular symbolic links to be compatible with Python 3.13 -- by :user:`steverep`.


  *Related issues and pull requests on GitHub:*
  :issue:`8565`.



- Fixed request body not being read when ignoring an Upgrade request -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8597`.



- Fixed an edge case where shutdown would wait for timeout when the handler was already completed -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8611`.



- Fixed connecting to ``npipe://``, ``tcp://``, and ``unix://`` urls -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`8632`.



- Fixed WebSocket ping tasks being prematurely garbage collected -- by :user:`bdraco`.

  There was a small risk that WebSocket ping tasks would be prematurely garbage collected because the event loop only holds a weak reference to the task. The garbage collection risk has been fixed by holding a strong reference to the task. Additionally, the task is now scheduled eagerly with Python 3.12+ to increase the chance it can be completed immediately and avoid having to hold any references to the task.


  *Related issues and pull requests on GitHub:*
  :issue:`8641`.



- Fixed incorrectly following symlinks for compressed file variants -- by :user:`steverep`.


  *Related issues and pull requests on GitHub:*
  :issue:`8652`.




Removals and backward incompatible breaking changes
---------------------------------------------------

- Removed ``Request.wait_for_disconnection()``, which was mistakenly added briefly in 3.10.0 -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8636`.




Contributor-facing changes
--------------------------

- Fixed monkey patches for ``Path.stat()`` and ``Path.is_dir()`` for Python 3.13 compatibility -- by :user:`steverep`.


  *Related issues and pull requests on GitHub:*
  :issue:`8551`.




Miscellaneous internal changes
------------------------------

- Improved WebSocket performance when messages are sent or received frequently -- by :user:`bdraco`.

  The WebSocket heartbeat scheduling algorithm was improved to reduce the ``asyncio`` scheduling overhead by decreasing the number of ``asyncio.TimerHandle`` creations and cancellations.


  *Related issues and pull requests on GitHub:*
  :issue:`8608`.



- Minor improvements to various type annotations -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8634`.




----


3.10.1 (2024-08-03)
========================

Bug fixes
---------

- Fixed WebSocket server heartbeat timeout logic to terminate :py:meth:`~aiohttp.ClientWebSocketResponse.receive` and return :py:class:`~aiohttp.ServerTimeoutError` -- by :user:`arcivanov`.

  When a WebSocket pong message was not received, the :py:meth:`~aiohttp.ClientWebSocketResponse.receive` operation did not terminate. This change causes ``_pong_not_received`` to feed the ``reader`` an error message, causing pending :py:meth:`~aiohttp.ClientWebSocketResponse.receive` to terminate and return the error message. The error message contains the exception :py:class:`~aiohttp.ServerTimeoutError`.


  *Related issues and pull requests on GitHub:*
  :issue:`8540`.



- Fixed url dispatcher index not matching when a variable is preceded by a fixed string after a slash -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`8566`.




Removals and backward incompatible breaking changes
---------------------------------------------------

- Creating :py:class:`aiohttp.TCPConnector`, :py:class:`aiohttp.ClientSession`, :py:class:`~aiohttp.resolver.ThreadedResolver` :py:class:`aiohttp.web.Server`, or :py:class:`aiohttp.CookieJar` instances without a running event loop now raises a :exc:`RuntimeError` -- by :user:`asvetlov`.

  Creating these objects without a running event loop was deprecated in :issue:`3372` which was released in version 3.5.0.

  This change first appeared in version 3.10.0 as :issue:`6378`.


  *Related issues and pull requests on GitHub:*
  :issue:`8555`, :issue:`8583`.




----


3.10.0 (2024-07-30)
========================

Bug fixes
---------

- Fixed server response headers for ``Content-Type`` and ``Content-Encoding`` for
  static compressed files -- by :user:`steverep`.

  Server will now respond with a ``Content-Type`` appropriate for the compressed
  file (e.g. ``"application/gzip"``), and omit the ``Content-Encoding`` header.
  Users should expect that most clients will no longer decompress such responses
  by default.


  *Related issues and pull requests on GitHub:*
  :issue:`4462`.



- Fixed duplicate cookie expiration calls in the CookieJar implementation


  *Related issues and pull requests on GitHub:*
  :issue:`7784`.



- Adjusted ``FileResponse`` to check file existence and access when preparing the response -- by :user:`steverep`.

  The :py:class:`~aiohttp.web.FileResponse` class was modified to respond with
   403 Forbidden or 404 Not Found as appropriate.  Previously, it would cause a
   server error if the path did not exist or could not be accessed.  Checks for
   existence, non-regular files, and permissions were expected to be done in the
   route handler.  For static routes, this now permits a compressed file to exist
   without its uncompressed variant and still be served.  In addition, this
   changes the response status for files without read permission to 403, and for
   non-regular files from 404 to 403 for consistency.


  *Related issues and pull requests on GitHub:*
  :issue:`8182`.



- Fixed ``AsyncResolver`` to match ``ThreadedResolver`` behavior
  -- by :user:`bdraco`.

  On system with IPv6 support, the :py:class:`~aiohttp.resolver.AsyncResolver` would not fallback
  to providing A records when AAAA records were not available.
  Additionally, unlike the :py:class:`~aiohttp.resolver.ThreadedResolver`, the :py:class:`~aiohttp.resolver.AsyncResolver`
  did not handle link-local addresses correctly.

  This change makes the behavior consistent with the :py:class:`~aiohttp.resolver.ThreadedResolver`.


  *Related issues and pull requests on GitHub:*
  :issue:`8270`.



- Fixed ``ws_connect`` not respecting `receive_timeout`` on WS(S) connection.
  -- by :user:`arcivanov`.


  *Related issues and pull requests on GitHub:*
  :issue:`8444`.



- Removed blocking I/O in the event loop for static resources and refactored
  exception handling -- by :user:`steverep`.

  File system calls when handling requests for static routes were moved to a
  separate thread to potentially improve performance. Exception handling
  was tightened in order to only return 403 Forbidden or 404 Not Found responses
  for expected scenarios; 500 Internal Server Error would be returned for any
  unknown errors.


  *Related issues and pull requests on GitHub:*
  :issue:`8507`.




Features
--------

- Added a Request.wait_for_disconnection() method, as means of allowing request handlers to be notified of premature client disconnections.


  *Related issues and pull requests on GitHub:*
  :issue:`2492`.



- Added 5 new exceptions: :py:exc:`~aiohttp.InvalidUrlClientError`, :py:exc:`~aiohttp.RedirectClientError`,
  :py:exc:`~aiohttp.NonHttpUrlClientError`, :py:exc:`~aiohttp.InvalidUrlRedirectClientError`,
  :py:exc:`~aiohttp.NonHttpUrlRedirectClientError`

  :py:exc:`~aiohttp.InvalidUrlRedirectClientError`, :py:exc:`~aiohttp.NonHttpUrlRedirectClientError`
  are raised instead of :py:exc:`ValueError` or :py:exc:`~aiohttp.InvalidURL` when the redirect URL is invalid. Classes
  :py:exc:`~aiohttp.InvalidUrlClientError`, :py:exc:`~aiohttp.RedirectClientError`,
  :py:exc:`~aiohttp.NonHttpUrlClientError` are base for them.

  The :py:exc:`~aiohttp.InvalidURL` now exposes a ``description`` property with the text explanation of the error details.

  -- by :user:`setla`, :user:`AraHaan`, and :user:`bdraco`


  *Related issues and pull requests on GitHub:*
  :issue:`2507`, :issue:`3315`, :issue:`6722`, :issue:`8481`, :issue:`8482`.



- Added a feature to retry closed connections automatically for idempotent methods. -- by :user:`Dreamsorcerer`


  *Related issues and pull requests on GitHub:*
  :issue:`7297`.



- Implemented filter_cookies() with domain-matching and path-matching on the keys, instead of testing every single cookie.
  This may break existing cookies that have been saved with `CookieJar.save()`. Cookies can be migrated with this script::

      import pickle
      with file_path.open("rb") as f:
          cookies = pickle.load(f)

      morsels = [(name, m) for c in cookies.values() for name, m in c.items()]
      cookies.clear()
      for name, m in morsels:
          cookies[(m["domain"], m["path"].rstrip("/"))][name] = m

      with file_path.open("wb") as f:
          pickle.dump(cookies, f, pickle.HIGHEST_PROTOCOL)


  *Related issues and pull requests on GitHub:*
  :issue:`7583`, :issue:`8535`.



- Separated connection and socket timeout errors, from ServerTimeoutError.


  *Related issues and pull requests on GitHub:*
  :issue:`7801`.



- Implemented happy eyeballs


  *Related issues and pull requests on GitHub:*
  :issue:`7954`.



- Added server capability to check for static files with Brotli compression via a ``.br`` extension -- by :user:`steverep`.


  *Related issues and pull requests on GitHub:*
  :issue:`8062`.




Removals and backward incompatible breaking changes
---------------------------------------------------

- The shutdown logic in 3.9 waited on all tasks, which caused issues with some libraries.
  In 3.10 we've changed this logic to only wait on request handlers. This means that it's
  important for developers to correctly handle the lifecycle of background tasks using a
  library such as ``aiojobs``. If an application is using ``handler_cancellation=True`` then
  it is also a good idea to ensure that any :func:`asyncio.shield` calls are replaced with
  :func:`aiojobs.aiohttp.shield`.

  Please read the updated documentation on these points: \
  https://docs.aiohttp.org/en/stable/web_advanced.html#graceful-shutdown \
  https://docs.aiohttp.org/en/stable/web_advanced.html#web-handler-cancellation

  -- by :user:`Dreamsorcerer`


  *Related issues and pull requests on GitHub:*
  :issue:`8495`.




Improved documentation
----------------------

- Added documentation for ``aiohttp.web.FileResponse``.


  *Related issues and pull requests on GitHub:*
  :issue:`3958`.



- Improved the docs for the `ssl` params.


  *Related issues and pull requests on GitHub:*
  :issue:`8403`.




Contributor-facing changes
--------------------------

- Enabled HTTP parser tests originally intended for 3.9.2 release -- by :user:`pajod`.


  *Related issues and pull requests on GitHub:*
  :issue:`8088`.




Miscellaneous internal changes
------------------------------

- Improved URL handler resolution time by indexing resources in the UrlDispatcher.
  For applications with a large number of handlers, this should increase performance significantly.
  -- by :user:`bdraco`


  *Related issues and pull requests on GitHub:*
  :issue:`7829`.



- Added `nacl_middleware <https://github.com/CosmicDNA/nacl_middleware>`_ to the list of middlewares in the third party section of the documentation.


  *Related issues and pull requests on GitHub:*
  :issue:`8346`.



- Minor improvements to static typing -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8364`.



- Added a 3.11-specific overloads to ``ClientSession``  -- by :user:`max-muoto`.


  *Related issues and pull requests on GitHub:*
  :issue:`8463`.



- Simplified path checks for ``UrlDispatcher.add_static()`` method -- by :user:`steverep`.


  *Related issues and pull requests on GitHub:*
  :issue:`8491`.



- Avoided creating a future on every websocket receive -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`8498`.



- Updated identity checks for all ``WSMsgType`` type compares -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`8501`.



- When using Python 3.12 or later, the writer is no longer scheduled on the event loop if it can finish synchronously. Avoiding event loop scheduling reduces latency and improves performance. -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`8510`.



- Restored :py:class:`~aiohttp.resolver.AsyncResolver` to be the default resolver. -- by :user:`bdraco`.

  :py:class:`~aiohttp.resolver.AsyncResolver` was disabled by default because
  of IPv6 compatibility issues. These issues have been resolved and
  :py:class:`~aiohttp.resolver.AsyncResolver` is again now the default resolver.


  *Related issues and pull requests on GitHub:*
  :issue:`8522`.




----


3.9.5 (2024-04-16)
==================

Bug fixes
---------

- Fixed "Unclosed client session" when initialization of
  :py:class:`~aiohttp.ClientSession` fails -- by :user:`NewGlad`.


  *Related issues and pull requests on GitHub:*
  :issue:`8253`.



- Fixed regression (from :pr:`8280`) with adding ``Content-Disposition`` to the ``form-data``
  part after appending to writer -- by :user:`Dreamsorcerer`/:user:`Olegt0rr`.


  *Related issues and pull requests on GitHub:*
  :issue:`8332`.



- Added default ``Content-Disposition`` in ``multipart/form-data`` responses to avoid broken
  form-data responses -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8335`.




----


3.9.4 (2024-04-11)
==================

Bug fixes
---------

- The asynchronous internals now set the underlying causes
  when assigning exceptions to the future objects
  -- by :user:`webknjaz`.


  *Related issues and pull requests on GitHub:*
  :issue:`8089`.



- Treated values of ``Accept-Encoding`` header as case-insensitive when checking
  for gzip files -- by :user:`steverep`.


  *Related issues and pull requests on GitHub:*
  :issue:`8104`.



- Improved the DNS resolution performance on cache hit -- by :user:`bdraco`.

  This is achieved by avoiding an :mod:`asyncio` task creation in this case.


  *Related issues and pull requests on GitHub:*
  :issue:`8163`.


- Changed the type annotations to allow ``dict`` on :meth:`aiohttp.MultipartWriter.append`,
  :meth:`aiohttp.MultipartWriter.append_json` and
  :meth:`aiohttp.MultipartWriter.append_form` -- by :user:`cakemanny`


  *Related issues and pull requests on GitHub:*
  :issue:`7741`.



- Ensure websocket transport is closed when client does not close it
  -- by :user:`bdraco`.

  The transport could remain open if the client did not close it. This
  change ensures the transport is closed when the client does not close
  it.


  *Related issues and pull requests on GitHub:*
  :issue:`8200`.



- Leave websocket transport open if receive times out or is cancelled
  -- by :user:`bdraco`.

  This restores the behavior prior to the change in #7978.


  *Related issues and pull requests on GitHub:*
  :issue:`8251`.



- Fixed content not being read when an upgrade request was not supported with the pure Python implementation.
  -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`8252`.



- Fixed a race condition with incoming connections during server shutdown -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8271`.



- Fixed ``multipart/form-data`` compliance with :rfc:`7578` -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8280`.



- Fixed blocking I/O in the event loop while processing files in a POST request
  -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`8283`.



- Escaped filenames in static view -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`8317`.



- Fixed the pure python parser to mark a connection as closing when a
  response has no length -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8320`.




Features
--------

- Upgraded *llhttp* to 9.2.1, and started rejecting obsolete line folding
  in Python parser to match -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8146`, :issue:`8292`.




Deprecations (removal in next major release)
--------------------------------------------

- Deprecated ``content_transfer_encoding`` parameter in :py:meth:`FormData.add_field()
  <aiohttp.FormData.add_field>` -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8280`.




Improved documentation
----------------------

- Added a note about canceling tasks to avoid delaying server shutdown -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8267`.




Contributor-facing changes
--------------------------

- The pull request template is now asking the contributors to
  answer a question about the long-term maintenance challenges
  they envision as a result of merging their patches
  -- by :user:`webknjaz`.


  *Related issues and pull requests on GitHub:*
  :issue:`8099`.



- Updated CI and documentation to use NPM clean install and upgrade
  node to version 18 -- by :user:`steverep`.


  *Related issues and pull requests on GitHub:*
  :issue:`8116`.



- A pytest fixture ``hello_txt`` was introduced to aid
  static file serving tests in
  :file:`test_web_sendfile_functional.py`. It dynamically
  provisions ``hello.txt`` file variants shared across the
  tests in the module.

  -- by :user:`steverep`


  *Related issues and pull requests on GitHub:*
  :issue:`8136`.




Packaging updates and notes for downstreams
-------------------------------------------

- Added an ``internal`` pytest marker for tests which should be skipped
  by packagers (use ``-m 'not internal'`` to disable them) -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8299`.




----


3.9.3 (2024-01-29)
==================

Bug fixes
---------

- Fixed backwards compatibility breakage (in 3.9.2) of ``ssl`` parameter when set outside
  of ``ClientSession`` (e.g. directly in ``TCPConnector``) -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`8097`, :issue:`8098`.




Miscellaneous internal changes
------------------------------

- Improved test suite handling of paths and temp files to consistently use pathlib and pytest fixtures.


  *Related issues and pull requests on GitHub:*
  :issue:`3957`.




----


3.9.2 (2024-01-28)
==================

Bug fixes
---------

- Fixed server-side websocket connection leak.


  *Related issues and pull requests on GitHub:*
  :issue:`7978`.



- Fixed ``web.FileResponse`` doing blocking I/O in the event loop.


  *Related issues and pull requests on GitHub:*
  :issue:`8012`.



- Fixed double compress when compression enabled and compressed file exists in server file responses.


  *Related issues and pull requests on GitHub:*
  :issue:`8014`.



- Added runtime type check for ``ClientSession`` ``timeout`` parameter.


  *Related issues and pull requests on GitHub:*
  :issue:`8021`.



- Fixed an unhandled exception in the Python HTTP parser on header lines starting with a colon -- by :user:`pajod`.

  Invalid request lines with anything but a dot between the HTTP major and minor version are now rejected.
  Invalid header field names containing question mark or slash are now rejected.
  Such requests are incompatible with :rfc:`9110#section-5.6.2` and are not known to be of any legitimate use.


  *Related issues and pull requests on GitHub:*
  :issue:`8074`.



- Improved validation of paths for static resources requests to the server -- by :user:`bdraco`.


  *Related issues and pull requests on GitHub:*
  :issue:`8079`.




Features
--------

- Added support for passing :py:data:`True` to ``ssl`` parameter in ``ClientSession`` while
  deprecating :py:data:`None` -- by :user:`xiangyan99`.


  *Related issues and pull requests on GitHub:*
  :issue:`7698`.



Breaking changes
----------------

- Fixed an unhandled exception in the Python HTTP parser on header lines starting with a colon -- by :user:`pajod`.

  Invalid request lines with anything but a dot between the HTTP major and minor version are now rejected.
  Invalid header field names containing question mark or slash are now rejected.
  Such requests are incompatible with :rfc:`9110#section-5.6.2` and are not known to be of any legitimate use.


  *Related issues and pull requests on GitHub:*
  :issue:`8074`.




Improved documentation
----------------------

- Fixed examples of ``fallback_charset_resolver`` function in the :doc:`client_advanced` document. -- by :user:`henry0312`.


  *Related issues and pull requests on GitHub:*
  :issue:`7995`.



- The Sphinx setup was updated to avoid showing the empty
  changelog draft section in the tagged release documentation
  builds on Read The Docs -- by :user:`webknjaz`.


  *Related issues and pull requests on GitHub:*
  :issue:`8067`.




Packaging updates and notes for downstreams
-------------------------------------------

- The changelog categorization was made clearer. The
  contributors can now mark their fragment files more
  accurately -- by :user:`webknjaz`.

  The new category tags are:

      * ``bugfix``

      * ``feature``

      * ``deprecation``

      * ``breaking`` (previously, ``removal``)

      * ``doc``

      * ``packaging``

      * ``contrib``

      * ``misc``


  *Related issues and pull requests on GitHub:*
  :issue:`8066`.




Contributor-facing changes
--------------------------

- Updated :ref:`contributing/Tests coverage <aiohttp-contributing>` section to show how we use ``codecov`` -- by :user:`Dreamsorcerer`.


  *Related issues and pull requests on GitHub:*
  :issue:`7916`.



- The changelog categorization was made clearer. The
  contributors can now mark their fragment files more
  accurately -- by :user:`webknjaz`.

  The new category tags are:

      * ``bugfix``

      * ``feature``

      * ``deprecation``

      * ``breaking`` (previously, ``removal``)

      * ``doc``

      * ``packaging``

      * ``contrib``

      * ``misc``


  *Related issues and pull requests on GitHub:*
  :issue:`8066`.




Miscellaneous internal changes
------------------------------

- Replaced all ``tmpdir`` fixtures with ``tmp_path`` in test suite.


  *Related issues and pull requests on GitHub:*
  :issue:`3551`.




----


3.9.1 (2023-11-26)
==================

Bugfixes
--------

- Fixed importing aiohttp under PyPy on Windows.

  `#7848 <https://github.com/aio-libs/aiohttp/issues/7848>`_

- Fixed async concurrency safety in websocket compressor.

  `#7865 <https://github.com/aio-libs/aiohttp/issues/7865>`_

- Fixed ``ClientResponse.close()`` releasing the connection instead of closing.

  `#7869 <https://github.com/aio-libs/aiohttp/issues/7869>`_

- Fixed a regression where connection may get closed during upgrade. -- by :user:`Dreamsorcerer`

  `#7879 <https://github.com/aio-libs/aiohttp/issues/7879>`_

- Fixed messages being reported as upgraded without an Upgrade header in Python parser. -- by :user:`Dreamsorcerer`

  `#7895 <https://github.com/aio-libs/aiohttp/issues/7895>`_



----


3.9.0 (2023-11-18)
==================

Features
--------

- Introduced ``AppKey`` for static typing support of ``Application`` storage.
  See https://docs.aiohttp.org/en/stable/web_advanced.html#application-s-config

  `#5864 <https://github.com/aio-libs/aiohttp/issues/5864>`_

- Added a graceful shutdown period which allows pending tasks to complete before the application's cleanup is called.
  The period can be adjusted with the ``shutdown_timeout`` parameter. -- by :user:`Dreamsorcerer`.
  See https://docs.aiohttp.org/en/latest/web_advanced.html#graceful-shutdown

  `#7188 <https://github.com/aio-libs/aiohttp/issues/7188>`_

- Added `handler_cancellation <https://docs.aiohttp.org/en/stable/web_advanced.html#web-handler-cancellation>`_ parameter to cancel web handler on client disconnection. -- by :user:`mosquito`
  This (optionally) reintroduces a feature removed in a previous release.
  Recommended for those looking for an extra level of protection against denial-of-service attacks.

  `#7056 <https://github.com/aio-libs/aiohttp/issues/7056>`_

- Added support for setting response header parameters ``max_line_size`` and ``max_field_size``.

  `#2304 <https://github.com/aio-libs/aiohttp/issues/2304>`_

- Added ``auto_decompress`` parameter to ``ClientSession.request`` to override ``ClientSession._auto_decompress``. -- by :user:`Daste745`

  `#3751 <https://github.com/aio-libs/aiohttp/issues/3751>`_

- Changed ``raise_for_status`` to allow a coroutine.

  `#3892 <https://github.com/aio-libs/aiohttp/issues/3892>`_

- Added client brotli compression support (optional with runtime check).

  `#5219 <https://github.com/aio-libs/aiohttp/issues/5219>`_

- Added ``client_max_size`` to ``BaseRequest.clone()`` to allow overriding the request body size. -- :user:`anesabml`.

  `#5704 <https://github.com/aio-libs/aiohttp/issues/5704>`_

- Added a middleware type alias ``aiohttp.typedefs.Middleware``.

  `#5898 <https://github.com/aio-libs/aiohttp/issues/5898>`_

- Exported ``HTTPMove`` which can be used to catch any redirection request
  that has a location -- :user:`dreamsorcerer`.

  `#6594 <https://github.com/aio-libs/aiohttp/issues/6594>`_

- Changed the ``path`` parameter in ``web.run_app()`` to accept a ``pathlib.Path`` object.

  `#6839 <https://github.com/aio-libs/aiohttp/issues/6839>`_

- Performance: Skipped filtering ``CookieJar`` when the jar is empty or all cookies have expired.

  `#7819 <https://github.com/aio-libs/aiohttp/issues/7819>`_

- Performance: Only check origin if insecure scheme and there are origins to treat as secure, in ``CookieJar.filter_cookies()``.

  `#7821 <https://github.com/aio-libs/aiohttp/issues/7821>`_

- Performance: Used timestamp instead of ``datetime`` to achieve faster cookie expiration in ``CookieJar``.

  `#7824 <https://github.com/aio-libs/aiohttp/issues/7824>`_

- Added support for passing a custom server name parameter to HTTPS connection.

  `#7114 <https://github.com/aio-libs/aiohttp/issues/7114>`_

- Added support for using Basic Auth credentials from :file:`.netrc` file when making HTTP requests with the
  :py:class:`~aiohttp.ClientSession` ``trust_env`` argument is set to ``True``. -- by :user:`yuvipanda`.

  `#7131 <https://github.com/aio-libs/aiohttp/issues/7131>`_

- Turned access log into no-op when the logger is disabled.

  `#7240 <https://github.com/aio-libs/aiohttp/issues/7240>`_

- Added typing information to ``RawResponseMessage``. -- by :user:`Gobot1234`

  `#7365 <https://github.com/aio-libs/aiohttp/issues/7365>`_

- Removed ``async-timeout`` for Python 3.11+ (replaced with ``asyncio.timeout()`` on newer releases).

  `#7502 <https://github.com/aio-libs/aiohttp/issues/7502>`_

- Added support for ``brotlicffi`` as an alternative to ``brotli`` (fixing Brotli support on PyPy).

  `#7611 <https://github.com/aio-libs/aiohttp/issues/7611>`_

- Added ``WebSocketResponse.get_extra_info()`` to access a protocol transport's extra info.

  `#7078 <https://github.com/aio-libs/aiohttp/issues/7078>`_

- Allow ``link`` argument to be set to None/empty in HTTP 451 exception.

  `#7689 <https://github.com/aio-libs/aiohttp/issues/7689>`_



Bugfixes
--------

- Implemented stripping the trailing dots from fully-qualified domain names in ``Host`` headers and TLS context when acting as an HTTP client.
  This allows the client to connect to URLs with FQDN host name like ``https://example.com./``.
  -- by :user:`martin-sucha`.

  `#3636 <https://github.com/aio-libs/aiohttp/issues/3636>`_

- Fixed client timeout not working when incoming data is always available without waiting. -- by :user:`Dreamsorcerer`.

  `#5854 <https://github.com/aio-libs/aiohttp/issues/5854>`_

- Fixed ``readuntil`` to work with a delimiter of more than one character.

  `#6701 <https://github.com/aio-libs/aiohttp/issues/6701>`_

- Added ``__repr__`` to ``EmptyStreamReader`` to avoid ``AttributeError``.

  `#6916 <https://github.com/aio-libs/aiohttp/issues/6916>`_

- Fixed bug when using ``TCPConnector`` with ``ttl_dns_cache=0``.

  `#7014 <https://github.com/aio-libs/aiohttp/issues/7014>`_

- Fixed response returned from expect handler being thrown away. -- by :user:`Dreamsorcerer`

  `#7025 <https://github.com/aio-libs/aiohttp/issues/7025>`_

- Avoided raising ``UnicodeDecodeError`` in multipart and in HTTP headers parsing.

  `#7044 <https://github.com/aio-libs/aiohttp/issues/7044>`_

- Changed ``sock_read`` timeout to start after writing has finished, avoiding read timeouts caused by an unfinished write. -- by :user:`dtrifiro`

  `#7149 <https://github.com/aio-libs/aiohttp/issues/7149>`_

- Fixed missing query in tracing method URLs when using ``yarl`` 1.9+.

  `#7259 <https://github.com/aio-libs/aiohttp/issues/7259>`_

- Changed max 32-bit timestamp to an aware datetime object, for consistency with the non-32-bit one, and to avoid a ``DeprecationWarning`` on Python 3.12.

  `#7302 <https://github.com/aio-libs/aiohttp/issues/7302>`_

- Fixed ``EmptyStreamReader.iter_chunks()`` never ending. -- by :user:`mind1m`

  `#7616 <https://github.com/aio-libs/aiohttp/issues/7616>`_

- Fixed a rare ``RuntimeError: await wasn't used with future`` exception. -- by :user:`stalkerg`

  `#7785 <https://github.com/aio-libs/aiohttp/issues/7785>`_

- Fixed issue with insufficient HTTP method and version validation.

  `#7700 <https://github.com/aio-libs/aiohttp/issues/7700>`_

- Added check to validate that absolute URIs have schemes.

  `#7712 <https://github.com/aio-libs/aiohttp/issues/7712>`_

- Fixed unhandled exception when Python HTTP parser encounters unpaired Unicode surrogates.

  `#7715 <https://github.com/aio-libs/aiohttp/issues/7715>`_

- Updated parser to disallow invalid characters in header field names and stop accepting LF as a request line separator.

  `#7719 <https://github.com/aio-libs/aiohttp/issues/7719>`_

- Fixed Python HTTP parser not treating 204/304/1xx as an empty body.

  `#7755 <https://github.com/aio-libs/aiohttp/issues/7755>`_

- Ensure empty body response for 1xx/204/304 per RFC 9112 sec 6.3.

  `#7756 <https://github.com/aio-libs/aiohttp/issues/7756>`_

- Fixed an issue when a client request is closed before completing a chunked payload. -- by :user:`Dreamsorcerer`

  `#7764 <https://github.com/aio-libs/aiohttp/issues/7764>`_

- Edge Case Handling for ResponseParser for missing reason value.

  `#7776 <https://github.com/aio-libs/aiohttp/issues/7776>`_

- Fixed ``ClientWebSocketResponse.close_code`` being erroneously set to ``None`` when there are concurrent async tasks receiving data and closing the connection.

  `#7306 <https://github.com/aio-libs/aiohttp/issues/7306>`_

- Added HTTP method validation.

  `#6533 <https://github.com/aio-libs/aiohttp/issues/6533>`_

- Fixed arbitrary sequence types being allowed to inject values via version parameter. -- by :user:`Dreamsorcerer`

  `#7835 <https://github.com/aio-libs/aiohttp/issues/7835>`_

- Performance: Fixed increase in latency with small messages from websocket compression changes.

  `#7797 <https://github.com/aio-libs/aiohttp/issues/7797>`_



Improved Documentation
----------------------

- Fixed the `ClientResponse.release`'s type in the doc. Changed from `comethod` to `method`.

  `#5836 <https://github.com/aio-libs/aiohttp/issues/5836>`_

- Added information on behavior of base_url parameter in `ClientSession`.

  `#6647 <https://github.com/aio-libs/aiohttp/issues/6647>`_

- Fixed `ClientResponseError` docs.

  `#6700 <https://github.com/aio-libs/aiohttp/issues/6700>`_

- Updated Redis code examples to follow the latest API.

  `#6907 <https://github.com/aio-libs/aiohttp/issues/6907>`_

- Added a note about possibly needing to update headers when using ``on_response_prepare``. -- by :user:`Dreamsorcerer`

  `#7283 <https://github.com/aio-libs/aiohttp/issues/7283>`_

- Completed ``trust_env`` parameter description to honor ``wss_proxy``, ``ws_proxy`` or ``no_proxy`` env.

  `#7325 <https://github.com/aio-libs/aiohttp/issues/7325>`_

- Expanded SSL documentation with more examples (e.g. how to use certifi). -- by :user:`Dreamsorcerer`

  `#7334 <https://github.com/aio-libs/aiohttp/issues/7334>`_

- Fix, update, and improve client exceptions documentation.

  `#7733 <https://github.com/aio-libs/aiohttp/issues/7733>`_



Deprecations and Removals
-------------------------

- Added ``shutdown_timeout`` parameter to ``BaseRunner``, while
  deprecating ``shutdown_timeout`` parameter from ``BaseSite``. -- by :user:`Dreamsorcerer`

  `#7718 <https://github.com/aio-libs/aiohttp/issues/7718>`_

- Dropped Python 3.6 support.

  `#6378 <https://github.com/aio-libs/aiohttp/issues/6378>`_

- Dropped Python 3.7 support. -- by :user:`Dreamsorcerer`

  `#7336 <https://github.com/aio-libs/aiohttp/issues/7336>`_

- Removed support for abandoned ``tokio`` event loop. -- by :user:`Dreamsorcerer`

  `#7281 <https://github.com/aio-libs/aiohttp/issues/7281>`_



Misc
----

- Made ``print`` argument in ``run_app()`` optional.

  `#3690 <https://github.com/aio-libs/aiohttp/issues/3690>`_

- Improved performance of ``ceil_timeout`` in some cases.

  `#6316 <https://github.com/aio-libs/aiohttp/issues/6316>`_

- Changed importing Gunicorn to happen on-demand, decreasing import time by ~53%. -- :user:`Dreamsorcerer`

  `#6591 <https://github.com/aio-libs/aiohttp/issues/6591>`_

- Improved import time by replacing ``http.server`` with ``http.HTTPStatus``.

  `#6903 <https://github.com/aio-libs/aiohttp/issues/6903>`_

- Fixed annotation of ``ssl`` parameter to disallow ``True``. -- by :user:`Dreamsorcerer`.

  `#7335 <https://github.com/aio-libs/aiohttp/issues/7335>`_


----


3.8.6 (2023-10-07)
==================

Security bugfixes
-----------------

- Upgraded the vendored copy of llhttp_ to v9.1.3 -- by :user:`Dreamsorcerer`

  Thanks to :user:`kenballus` for reporting this, see
  https://github.com/aio-libs/aiohttp/security/advisories/GHSA-pjjw-qhg8-p2p9.

  .. _llhttp: https://llhttp.org

  `#7647 <https://github.com/aio-libs/aiohttp/issues/7647>`_

- Updated Python parser to comply with RFCs 9110/9112 -- by :user:`Dreamorcerer`

  Thanks to :user:`kenballus` for reporting this, see
  https://github.com/aio-libs/aiohttp/security/advisories/GHSA-gfw2-4jvh-wgfg.

  `#7663 <https://github.com/aio-libs/aiohttp/issues/7663>`_


Deprecation
-----------

- Added ``fallback_charset_resolver`` parameter in ``ClientSession`` to allow a user-supplied
  character set detection function.

  Character set detection will no longer be included in 3.9 as a default. If this feature is needed,
  please use `fallback_charset_resolver <https://docs.aiohttp.org/en/stable/client_advanced.html#character-set-detection>`_.

  `#7561 <https://github.com/aio-libs/aiohttp/issues/7561>`_


Features
--------

- Enabled lenient response parsing for more flexible parsing in the client
  (this should resolve some regressions when dealing with badly formatted HTTP responses). -- by :user:`Dreamsorcerer`

  `#7490 <https://github.com/aio-libs/aiohttp/issues/7490>`_



Bugfixes
--------

- Fixed ``PermissionError`` when ``.netrc`` is unreadable due to permissions.

  `#7237 <https://github.com/aio-libs/aiohttp/issues/7237>`_

- Fixed output of parsing errors pointing to a ``\n``. -- by :user:`Dreamsorcerer`

  `#7468 <https://github.com/aio-libs/aiohttp/issues/7468>`_

- Fixed ``GunicornWebWorker`` max_requests_jitter not working.

  `#7518 <https://github.com/aio-libs/aiohttp/issues/7518>`_

- Fixed sorting in ``filter_cookies`` to use cookie with longest path. -- by :user:`marq24`.

  `#7577 <https://github.com/aio-libs/aiohttp/issues/7577>`_

- Fixed display of ``BadStatusLine`` messages from llhttp_. -- by :user:`Dreamsorcerer`

  `#7651 <https://github.com/aio-libs/aiohttp/issues/7651>`_


----


3.8.5 (2023-07-19)
==================

Security bugfixes
-----------------

- Upgraded the vendored copy of llhttp_ to v8.1.1 -- by :user:`webknjaz`
  and :user:`Dreamsorcerer`.

  Thanks to :user:`sethmlarson` for reporting this and providing us with
  comprehensive reproducer, workarounds and fixing details! For more
  information, see
  https://github.com/aio-libs/aiohttp/security/advisories/GHSA-45c4-8wx5-qw6w.

  .. _llhttp: https://llhttp.org

  `#7346 <https://github.com/aio-libs/aiohttp/issues/7346>`_


Features
--------

- Added information to C parser exceptions to show which character caused the error. -- by :user:`Dreamsorcerer`

  `#7366 <https://github.com/aio-libs/aiohttp/issues/7366>`_


Bugfixes
--------

- Fixed a transport is :data:`None` error -- by :user:`Dreamsorcerer`.

  `#3355 <https://github.com/aio-libs/aiohttp/issues/3355>`_


----


3.8.4 (2023-02-12)
==================

Bugfixes
--------

- Fixed incorrectly overwriting cookies with the same name and domain, but different path.
  `#6638 <https://github.com/aio-libs/aiohttp/issues/6638>`_
- Fixed ``ConnectionResetError`` not being raised after client disconnection in SSL environments.
  `#7180 <https://github.com/aio-libs/aiohttp/issues/7180>`_


----


3.8.3 (2022-09-21)
==================

.. attention::

   This is the last :doc:`aiohttp <index>` release tested under
   Python 3.6. The 3.9 stream is dropping it from the CI and the
   distribution package metadata.

Bugfixes
--------

- Increased the upper boundary of the :doc:`multidict:index` dependency
  to allow for the version 6 -- by :user:`hugovk`.

  It used to be limited below version 7 in :doc:`aiohttp <index>` v3.8.1 but
  was lowered in v3.8.2 via :pr:`6550` and never brought back, causing
  problems with dependency pins when upgrading. :doc:`aiohttp <index>` v3.8.3
  fixes that by recovering the original boundary of ``< 7``.
  `#6950 <https://github.com/aio-libs/aiohttp/issues/6950>`_


----


3.8.2 (2022-09-20, subsequently yanked on 2022-09-21)
=====================================================

Bugfixes
--------

- Support registering OPTIONS HTTP method handlers via RouteTableDef.
  `#4663 <https://github.com/aio-libs/aiohttp/issues/4663>`_
- Started supporting ``authority-form`` and ``absolute-form`` URLs on the server-side.
  `#6227 <https://github.com/aio-libs/aiohttp/issues/6227>`_
- Fix Python 3.11 alpha incompatibilities by using Cython 0.29.25
  `#6396 <https://github.com/aio-libs/aiohttp/issues/6396>`_
- Remove a deprecated usage of pytest.warns(None)
  `#6663 <https://github.com/aio-libs/aiohttp/issues/6663>`_
- Fix regression where ``asyncio.CancelledError`` occurs on client disconnection.
  `#6719 <https://github.com/aio-libs/aiohttp/issues/6719>`_
- Export :py:class:`~aiohttp.web.PrefixedSubAppResource` under
  :py:mod:`aiohttp.web` -- by :user:`Dreamsorcerer`.

  This fixes a regression introduced by :pr:`3469`.
  `#6889 <https://github.com/aio-libs/aiohttp/issues/6889>`_
- Dropped the :class:`object` type possibility from
  the :py:attr:`aiohttp.ClientSession.timeout`
  property return type declaration.
  `#6917 <https://github.com/aio-libs/aiohttp/issues/6917>`_,
  `#6923 <https://github.com/aio-libs/aiohttp/issues/6923>`_


Improved Documentation
----------------------

- Added clarification on configuring the app object with settings such as a db connection.
  `#4137 <https://github.com/aio-libs/aiohttp/issues/4137>`_
- Edited the web.run_app declaration.
  `#6401 <https://github.com/aio-libs/aiohttp/issues/6401>`_
- Dropped the :class:`object` type possibility from
  the :py:attr:`aiohttp.ClientSession.timeout`
  property return type declaration.
  `#6917 <https://github.com/aio-libs/aiohttp/issues/6917>`_,
  `#6923 <https://github.com/aio-libs/aiohttp/issues/6923>`_


Deprecations and Removals
-------------------------

- Drop Python 3.5 support, aiohttp works on 3.6+ now.
  `#4046 <https://github.com/aio-libs/aiohttp/issues/4046>`_


Misc
----

- `#6369 <https://github.com/aio-libs/aiohttp/issues/6369>`_, `#6399 <https://github.com/aio-libs/aiohttp/issues/6399>`_, `#6550 <https://github.com/aio-libs/aiohttp/issues/6550>`_, `#6708 <https://github.com/aio-libs/aiohttp/issues/6708>`_, `#6757 <https://github.com/aio-libs/aiohttp/issues/6757>`_, `#6857 <https://github.com/aio-libs/aiohttp/issues/6857>`_, `#6872 <https://github.com/aio-libs/aiohttp/issues/6872>`_


----


3.8.1 (2021-11-14)
==================

Bugfixes
--------

- Fix the error in handling the return value of `getaddrinfo`.
  `getaddrinfo` will return an `(int, bytes)` tuple, if CPython could not handle the address family.
  It will cause an index out of range error in aiohttp. For example, if user compile CPython with
  `--disable-ipv6` option, but his system enable the ipv6.
  `#5901 <https://github.com/aio-libs/aiohttp/issues/5901>`_
- Do not install "examples" as a top-level package.
  `#6189 <https://github.com/aio-libs/aiohttp/issues/6189>`_
- Restored ability to connect IPv6-only host.
  `#6195 <https://github.com/aio-libs/aiohttp/issues/6195>`_
- Remove ``Signal`` from ``__all__``, replace ``aiohttp.Signal`` with ``aiosignal.Signal`` in docs
  `#6201 <https://github.com/aio-libs/aiohttp/issues/6201>`_
- Made chunked encoding HTTP header check stricter.
  `#6305 <https://github.com/aio-libs/aiohttp/issues/6305>`_


Improved Documentation
----------------------

- update quick starter demo codes.
  `#6240 <https://github.com/aio-libs/aiohttp/issues/6240>`_
- Added an explanation of how tiny timeouts affect performance to the client reference document.
  `#6274 <https://github.com/aio-libs/aiohttp/issues/6274>`_
- Add flake8-docstrings to flake8 configuration, enable subset of checks.
  `#6276 <https://github.com/aio-libs/aiohttp/issues/6276>`_
- Added information on running complex applications with additional tasks/processes -- :user:`Dreamsorcerer`.
  `#6278 <https://github.com/aio-libs/aiohttp/issues/6278>`_


Misc
----

- `#6205 <https://github.com/aio-libs/aiohttp/issues/6205>`_


----


3.8.0 (2021-10-31)
==================

Features
--------

- Added a ``GunicornWebWorker`` feature for extending the aiohttp server configuration by allowing the 'wsgi' coroutine to return ``web.AppRunner`` object.
  `#2988 <https://github.com/aio-libs/aiohttp/issues/2988>`_
- Switch from ``http-parser`` to ``llhttp``
  `#3561 <https://github.com/aio-libs/aiohttp/issues/3561>`_
- Use Brotli instead of brotlipy
  `#3803 <https://github.com/aio-libs/aiohttp/issues/3803>`_
- Disable implicit switch-back to pure python mode. The build fails loudly if aiohttp
  cannot be compiled with C Accelerators.  Use AIOHTTP_NO_EXTENSIONS=1 to explicitly
  disable C Extensions complication and switch to Pure-Python mode.  Note that Pure-Python
  mode is significantly slower than compiled one.
  `#3828 <https://github.com/aio-libs/aiohttp/issues/3828>`_
- Make access log use local time with timezone
  `#3853 <https://github.com/aio-libs/aiohttp/issues/3853>`_
- Implemented ``readuntil`` in ``StreamResponse``
  `#4054 <https://github.com/aio-libs/aiohttp/issues/4054>`_
- FileResponse now supports ETag.
  `#4594 <https://github.com/aio-libs/aiohttp/issues/4594>`_
- Add a request handler type alias ``aiohttp.typedefs.Handler``.
  `#4686 <https://github.com/aio-libs/aiohttp/issues/4686>`_
- ``AioHTTPTestCase`` is more async friendly now.

  For people who use unittest and are used to use :py:exc:`~unittest.TestCase`
  it will be easier to write new test cases like the sync version of the :py:exc:`~unittest.TestCase` class,
  without using the decorator `@unittest_run_loop`, just `async def test_*`.
  The only difference is that for the people using python3.7 and below a new dependency is needed, it is ``asynctestcase``.
  `#4700 <https://github.com/aio-libs/aiohttp/issues/4700>`_
- Add validation of HTTP header keys and values to prevent header injection.
  `#4818 <https://github.com/aio-libs/aiohttp/issues/4818>`_
- Add predicate to ``AbstractCookieJar.clear``.
  Add ``AbstractCookieJar.clear_domain`` to clean all domain and subdomains cookies only.
  `#4942 <https://github.com/aio-libs/aiohttp/issues/4942>`_
- Add keepalive_timeout parameter to web.run_app.
  `#5094 <https://github.com/aio-libs/aiohttp/issues/5094>`_
- Tracing for client sent headers
  `#5105 <https://github.com/aio-libs/aiohttp/issues/5105>`_
- Make type hints for http parser stricter
  `#5267 <https://github.com/aio-libs/aiohttp/issues/5267>`_
- Add final declarations for constants.
  `#5275 <https://github.com/aio-libs/aiohttp/issues/5275>`_
- Switch to external frozenlist and aiosignal libraries.
  `#5293 <https://github.com/aio-libs/aiohttp/issues/5293>`_
- Don't send secure cookies by insecure transports.

  By default, the transport is secure if https or wss scheme is used.
  Use `CookieJar(treat_as_secure_origin="http://127.0.0.1")` to override the default security checker.
  `#5571 <https://github.com/aio-libs/aiohttp/issues/5571>`_
- Always create a new event loop in ``aiohttp.web.run_app()``.
  This adds better compatibility with ``asyncio.run()`` or if trying to run multiple apps in sequence.
  `#5572 <https://github.com/aio-libs/aiohttp/issues/5572>`_
- Add ``aiohttp.pytest_plugin.AiohttpClient`` for static typing of pytest plugin.
  `#5585 <https://github.com/aio-libs/aiohttp/issues/5585>`_
- Added a ``socket_factory`` argument to ``BaseTestServer``.
  `#5844 <https://github.com/aio-libs/aiohttp/issues/5844>`_
- Add compression strategy parameter to enable_compression method.
  `#5909 <https://github.com/aio-libs/aiohttp/issues/5909>`_
- Added support for Python 3.10 to Github Actions CI/CD workflows and fix the related deprecation warnings -- :user:`Hanaasagi`.
  `#5927 <https://github.com/aio-libs/aiohttp/issues/5927>`_
- Switched ``chardet`` to ``charset-normalizer`` for guessing the HTTP payload body encoding -- :user:`Ousret`.
  `#5930 <https://github.com/aio-libs/aiohttp/issues/5930>`_
- Added optional auto_decompress argument for HttpRequestParser
  `#5957 <https://github.com/aio-libs/aiohttp/issues/5957>`_
- Added support for HTTPS proxies to the extent CPython's
  :py:mod:`asyncio` supports it -- by :user:`bmbouter`,
  :user:`jborean93` and :user:`webknjaz`.
  `#5992 <https://github.com/aio-libs/aiohttp/issues/5992>`_
- Added ``base_url`` parameter to the initializer of :class:`~aiohttp.ClientSession`.
  `#6013 <https://github.com/aio-libs/aiohttp/issues/6013>`_
- Add Trove classifier and create binary wheels for 3.10. -- :user:`hugovk`.
  `#6079 <https://github.com/aio-libs/aiohttp/issues/6079>`_
- Started shipping platform-specific wheels with the ``musl`` tag targeting typical Alpine Linux runtimes — :user:`asvetlov`.
  `#6139 <https://github.com/aio-libs/aiohttp/issues/6139>`_
- Started shipping platform-specific arm64 wheels for Apple Silicon — :user:`asvetlov`.
  `#6139 <https://github.com/aio-libs/aiohttp/issues/6139>`_


Bugfixes
--------

- Modify _drain_helper() to handle concurrent `await resp.write(...)` or `ws.send_json(...)` calls without race-condition.
  `#2934 <https://github.com/aio-libs/aiohttp/issues/2934>`_
- Started using `MultiLoopChildWatcher` when it's available under POSIX while setting up the test I/O loop.
  `#3450 <https://github.com/aio-libs/aiohttp/issues/3450>`_
- Only encode content-disposition filename parameter using percent-encoding.
  Other parameters are encoded to quoted-string or RFC2231 extended parameter
  value.
  `#4012 <https://github.com/aio-libs/aiohttp/issues/4012>`_
- Fixed HTTP client requests to honor ``no_proxy`` environment variables.
  `#4431 <https://github.com/aio-libs/aiohttp/issues/4431>`_
- Fix supporting WebSockets proxies configured via environment variables.
  `#4648 <https://github.com/aio-libs/aiohttp/issues/4648>`_
- Change return type on URLDispatcher to UrlMappingMatchInfo to improve type annotations.
  `#4748 <https://github.com/aio-libs/aiohttp/issues/4748>`_
- Ensure a cleanup context is cleaned up even when an exception occurs during startup.
  `#4799 <https://github.com/aio-libs/aiohttp/issues/4799>`_
- Added a new exception type for Unix socket client errors which provides a more useful error message.
  `#4984 <https://github.com/aio-libs/aiohttp/issues/4984>`_
- Remove Transfer-Encoding and Content-Type headers for 204 in StreamResponse
  `#5106 <https://github.com/aio-libs/aiohttp/issues/5106>`_
- Only depend on typing_extensions for Python <3.8
  `#5107 <https://github.com/aio-libs/aiohttp/issues/5107>`_
- Add ABNORMAL_CLOSURE and BAD_GATEWAY to WSCloseCode
  `#5192 <https://github.com/aio-libs/aiohttp/issues/5192>`_
- Fix cookies disappearing from HTTPExceptions.
  `#5233 <https://github.com/aio-libs/aiohttp/issues/5233>`_
- StaticResource prefixes no longer match URLs with a non-folder prefix. For example ``routes.static('/foo', '/foo')`` no longer matches the URL ``/foobar``. Previously, this would attempt to load the file ``/foo/ar``.
  `#5250 <https://github.com/aio-libs/aiohttp/issues/5250>`_
- Acquire the connection before running traces to prevent race condition.
  `#5259 <https://github.com/aio-libs/aiohttp/issues/5259>`_
- Add missing slots to ```_RequestContextManager`` and ``_WSRequestContextManager``
  `#5329 <https://github.com/aio-libs/aiohttp/issues/5329>`_
- Ensure sending a zero byte file does not throw an exception (round 2)
  `#5380 <https://github.com/aio-libs/aiohttp/issues/5380>`_
- Set "text/plain" when data is an empty string in client requests.
  `#5392 <https://github.com/aio-libs/aiohttp/issues/5392>`_
- Stop automatically releasing the ``ClientResponse`` object on calls to the ``ok`` property for the failed requests.
  `#5403 <https://github.com/aio-libs/aiohttp/issues/5403>`_
- Include query parameters from `params` keyword argument in tracing `URL`.
  `#5432 <https://github.com/aio-libs/aiohttp/issues/5432>`_
- Fix annotations
  `#5466 <https://github.com/aio-libs/aiohttp/issues/5466>`_
- Fixed the multipart POST requests processing to always release file
  descriptors for the ``tempfile.Temporaryfile``-created
  ``_io.BufferedRandom`` instances of files sent within multipart request
  bodies via HTTP POST requests -- by :user:`webknjaz`.
  `#5494 <https://github.com/aio-libs/aiohttp/issues/5494>`_
- Fix 0 being incorrectly treated as an immediate timeout.
  `#5527 <https://github.com/aio-libs/aiohttp/issues/5527>`_
- Fixes failing tests when an environment variable <scheme>_proxy is set.
  `#5554 <https://github.com/aio-libs/aiohttp/issues/5554>`_
- Replace deprecated app handler design in ``tests/autobahn/server.py`` with call to ``web.run_app``; replace deprecated ``aiohttp.ws_connect`` calls in ``tests/autobahn/client.py`` with ``aiohttp.ClienSession.ws_connect``.
  `#5606 <https://github.com/aio-libs/aiohttp/issues/5606>`_
- Fixed test for ``HTTPUnauthorized`` that access the ``text`` argument. This is not used in any part of the code, so it's removed now.
  `#5657 <https://github.com/aio-libs/aiohttp/issues/5657>`_
- Remove incorrect default from docs
  `#5727 <https://github.com/aio-libs/aiohttp/issues/5727>`_
- Remove external test dependency to http://httpbin.org
  `#5840 <https://github.com/aio-libs/aiohttp/issues/5840>`_
- Don't cancel current task when entering a cancelled timer.
  `#5853 <https://github.com/aio-libs/aiohttp/issues/5853>`_
- Added ``params`` keyword argument to ``ClientSession.ws_connect``. --  :user:`hoh`.
  `#5868 <https://github.com/aio-libs/aiohttp/issues/5868>`_
- Uses :py:class:`~asyncio.ThreadedChildWatcher` under POSIX to allow setting up test loop in non-main thread.
  `#5877 <https://github.com/aio-libs/aiohttp/issues/5877>`_
- Fix the error in handling the return value of `getaddrinfo`.
  `getaddrinfo` will return an `(int, bytes)` tuple, if CPython could not handle the address family.
  It will cause a index out of range error in aiohttp. For example, if user compile CPython with
  `--disable-ipv6` option but his system enable the ipv6.
  `#5901 <https://github.com/aio-libs/aiohttp/issues/5901>`_
- Removed the deprecated ``loop`` argument from the ``asyncio.sleep``/``gather`` calls
  `#5905 <https://github.com/aio-libs/aiohttp/issues/5905>`_
- Return ``None`` from ``request.if_modified_since``, ``request.if_unmodified_since``, ``request.if_range`` and ``response.last_modified`` when corresponding http date headers are invalid.
  `#5925 <https://github.com/aio-libs/aiohttp/issues/5925>`_
- Fix resetting `SIGCHLD` signals in Gunicorn aiohttp Worker to fix `subprocesses` that capture output having an incorrect `returncode`.
  `#6130 <https://github.com/aio-libs/aiohttp/issues/6130>`_
- Raise ``400: Content-Length can't be present with Transfer-Encoding`` if both ``Content-Length`` and ``Transfer-Encoding`` are sent by peer by both C and Python implementations
  `#6182 <https://github.com/aio-libs/aiohttp/issues/6182>`_


Improved Documentation
----------------------

- Refactored OpenAPI/Swagger aiohttp addons, added ``aio-openapi``
  `#5326 <https://github.com/aio-libs/aiohttp/issues/5326>`_
- Fixed docs on request cookies type, so it matches what is actually used in the code (a
  read-only dictionary-like object).
  `#5725 <https://github.com/aio-libs/aiohttp/issues/5725>`_
- Documented that the HTTP client ``Authorization`` header is removed
  on redirects to a different host or protocol.
  `#5850 <https://github.com/aio-libs/aiohttp/issues/5850>`_


Misc
----

- `#3927 <https://github.com/aio-libs/aiohttp/issues/3927>`_, `#4247 <https://github.com/aio-libs/aiohttp/issues/4247>`_, `#4247 <https://github.com/aio-libs/aiohttp/issues/4247>`_, `#5389 <https://github.com/aio-libs/aiohttp/issues/5389>`_, `#5457 <https://github.com/aio-libs/aiohttp/issues/5457>`_, `#5486 <https://github.com/aio-libs/aiohttp/issues/5486>`_, `#5494 <https://github.com/aio-libs/aiohttp/issues/5494>`_, `#5515 <https://github.com/aio-libs/aiohttp/issues/5515>`_, `#5625 <https://github.com/aio-libs/aiohttp/issues/5625>`_, `#5635 <https://github.com/aio-libs/aiohttp/issues/5635>`_, `#5648 <https://github.com/aio-libs/aiohttp/issues/5648>`_, `#5657 <https://github.com/aio-libs/aiohttp/issues/5657>`_, `#5890 <https://github.com/aio-libs/aiohttp/issues/5890>`_, `#5914 <https://github.com/aio-libs/aiohttp/issues/5914>`_, `#5932 <https://github.com/aio-libs/aiohttp/issues/5932>`_, `#6002 <https://github.com/aio-libs/aiohttp/issues/6002>`_, `#6045 <https://github.com/aio-libs/aiohttp/issues/6045>`_, `#6131 <https://github.com/aio-libs/aiohttp/issues/6131>`_, `#6156 <https://github.com/aio-libs/aiohttp/issues/6156>`_, `#6165 <https://github.com/aio-libs/aiohttp/issues/6165>`_, `#6166 <https://github.com/aio-libs/aiohttp/issues/6166>`_


----


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
- Change normalize_path_middleware to use '308 Permanent Redirect' instead of 301.

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




----


3.4.4 (2018-09-05)
==================

- Fix installation from sources when compiling toolkit is not available (`#3241 <https://github.com/aio-libs/aiohttp/pull/3241>`_)




----


3.4.3 (2018-09-04)
==================

- Add ``app.pre_frozen`` state to properly handle startup signals in sub-applications. (`#3237 <https://github.com/aio-libs/aiohttp/pull/3237>`_)




----


3.4.2 (2018-09-01)
==================

- Fix ``iter_chunks`` type annotation (`#3230 <https://github.com/aio-libs/aiohttp/pull/3230>`_)




----


3.4.1 (2018-08-28)
==================

- Fix empty header parsing regression. (`#3218 <https://github.com/aio-libs/aiohttp/pull/3218>`_)
- Fix BaseRequest.raw_headers doc. (`#3215 <https://github.com/aio-libs/aiohttp/pull/3215>`_)
- Fix documentation building on ReadTheDocs (`#3221 <https://github.com/aio-libs/aiohttp/pull/3221>`_)




----


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




----


3.3.2 (2018-06-12)
==================

- Many HTTP proxies has buggy keepalive support. Let's not reuse connection but
  close it after processing every response. (`#3070 <https://github.com/aio-libs/aiohttp/pull/3070>`_)

- Provide vendor source files in tarball (`#3076 <https://github.com/aio-libs/aiohttp/pull/3076>`_)




----


3.3.1 (2018-06-05)
==================

- Fix ``sock_read`` timeout. (`#3053 <https://github.com/aio-libs/aiohttp/pull/3053>`_)
- When using a server-request body as the ``data=`` argument of a client request,
  iterate over the content with ``readany`` instead of ``readline`` to avoid ``Line
  too long`` errors. (`#3054 <https://github.com/aio-libs/aiohttp/pull/3054>`_)




----


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




----


3.2.1 (2018-05-10)
==================

- Don't reuse a connection with the same URL but different proxy/TLS settings
  (`#2981 <https://github.com/aio-libs/aiohttp/pull/2981>`_)




----


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




----


3.1.3 (2018-04-12)
==================

- Fix cancellation broadcast during DNS resolve (`#2910 <https://github.com/aio-libs/aiohttp/pull/2910>`_)




----


3.1.2 (2018-04-05)
==================

- Make ``LineTooLong`` exception more detailed about actual data size (`#2863 <https://github.com/aio-libs/aiohttp/pull/2863>`_)

- Call ``on_chunk_sent`` when write_eof takes as a param the last chunk (`#2909 <https://github.com/aio-libs/aiohttp/pull/2909>`_)




----


3.1.1 (2018-03-27)
==================

- Support *asynchronous iterators* (and *asynchronous generators* as
  well) in both client and server API as request / response BODY
  payloads. (`#2802 <https://github.com/aio-libs/aiohttp/pull/2802>`_)




----


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



----

3.0.9 (2018-03-14)
==================

- Close a connection if an unexpected exception occurs while sending a request
  (`#2827 <https://github.com/aio-libs/aiohttp/pull/2827>`_)



----


3.0.8 (2018-03-12)
==================

- Use ``asyncio.current_task()`` on Python 3.7 (`#2825 <https://github.com/aio-libs/aiohttp/pull/2825>`_)



----

3.0.7 (2018-03-08)
==================

- Fix SSL proxy support by client. (`#2810 <https://github.com/aio-libs/aiohttp/pull/2810>`_)
- Restore an imperative check in ``setup.py`` for python version. The check
  works in parallel to environment marker. As effect an error about unsupported
  Python versions is raised even on outdated systems with very old
  ``setuptools`` version installed. (`#2813 <https://github.com/aio-libs/aiohttp/pull/2813>`_)



----


3.0.6 (2018-03-05)
==================

- Add ``_reuse_address`` and ``_reuse_port`` to
  ``web_runner.TCPSite.__slots__``. (`#2792 <https://github.com/aio-libs/aiohttp/pull/2792>`_)



----

3.0.5 (2018-02-27)
==================

- Fix ``InvalidStateError`` on processing a sequence of two
  ``RequestHandler.data_received`` calls on web server. (`#2773 <https://github.com/aio-libs/aiohttp/pull/2773>`_)



----

3.0.4 (2018-02-26)
==================

- Fix ``IndexError`` in HTTP request handling by server. (`#2752 <https://github.com/aio-libs/aiohttp/pull/2752>`_)
- Fix MultipartWriter.append* no longer returning part/payload. (`#2759 <https://github.com/aio-libs/aiohttp/pull/2759>`_)



----


3.0.3 (2018-02-25)
==================

- Relax ``attrs`` dependency to minimal actually supported version
  17.0.3 The change allows to avoid version conflicts with currently
  existing test tools.



----

3.0.2 (2018-02-23)
==================

Security Fix
------------

- Prevent Windows absolute URLs in static files.  Paths like
  ``/static/D:\path`` and ``/static/\\hostname\drive\path`` are
  forbidden.



----

3.0.1
=====

- Technical release for fixing distribution problems.



----

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



----


2.3.10 (2018-02-02)
===================

- Fix 100% CPU usage on HTTP GET and websocket connection just after it (`#1955 <https://github.com/aio-libs/aiohttp/pull/1955>`_)
- Patch broken `ssl.match_hostname()` on Python<3.7 (`#2674 <https://github.com/aio-libs/aiohttp/pull/2674>`_)



----

2.3.9 (2018-01-16)
==================

- Fix colon handing in path for dynamic resources (`#2670 <https://github.com/aio-libs/aiohttp/pull/2670>`_)



----

2.3.8 (2018-01-15)
==================

- Do not use `yarl.unquote` internal function in aiohttp.  Fix
  incorrectly unquoted path part in URL dispatcher (`#2662 <https://github.com/aio-libs/aiohttp/pull/2662>`_)
- Fix compatibility with `yarl==1.0.0` (`#2662 <https://github.com/aio-libs/aiohttp/pull/2662>`_)



----

2.3.7 (2017-12-27)
==================

- Fixed race-condition for iterating addresses from the DNSCache. (`#2620 <https://github.com/aio-libs/aiohttp/pull/2620>`_)
- Fix docstring for request.host (`#2591 <https://github.com/aio-libs/aiohttp/pull/2591>`_)
- Fix docstring for request.remote (`#2592 <https://github.com/aio-libs/aiohttp/pull/2592>`_)



----


2.3.6 (2017-12-04)
==================

- Correct `request.app` context (for handlers not just middlewares). (`#2577 <https://github.com/aio-libs/aiohttp/pull/2577>`_)



----


2.3.5 (2017-11-30)
==================

- Fix compatibility with `pytest` 3.3+ (`#2565 <https://github.com/aio-libs/aiohttp/pull/2565>`_)



----


2.3.4 (2017-11-29)
==================

- Make `request.app` point to proper application instance when using nested
  applications (with middlewares). (`#2550 <https://github.com/aio-libs/aiohttp/pull/2550>`_)
- Change base class of ClientConnectorSSLError to ClientSSLError from
  ClientConnectorError. (`#2563 <https://github.com/aio-libs/aiohttp/pull/2563>`_)
- Return client connection back to free pool on error in `connector.connect()`.
  (`#2567 <https://github.com/aio-libs/aiohttp/pull/2567>`_)



----


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



----


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



----


2.3.1 (2017-10-18)
==================

- Relax attribute lookup in warning about old-styled middleware (`#2340 <https://github.com/aio-libs/aiohttp/pull/2340>`_)



----


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



----


2.2.5 (2017-08-03)
==================

- Don't raise deprecation warning on
  `loop.run_until_complete(client.close())` (`#2065 <https://github.com/aio-libs/aiohttp/pull/2065>`_)



----

2.2.4 (2017-08-02)
==================

- Fix issue with synchronous session closing when using ClientSession
  as an asynchronous context manager.  (`#2063 <https://github.com/aio-libs/aiohttp/pull/2063>`_)



----

2.2.3 (2017-07-04)
==================

- Fix `_CoroGuard` for python 3.4



----

2.2.2 (2017-07-03)
==================

- Allow `await session.close()` along with `yield from session.close()`



----


2.2.1 (2017-07-02)
==================

- Relax `yarl` requirement to 0.11+
- Backport #2026: `session.close` *is* a coroutine (`#2029 <https://github.com/aio-libs/aiohttp/pull/2029>`_)



----


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



----



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



----


2.0.7 (2017-04-12)
==================

- Fix *pypi* distribution
- Fix exception description (`#1807 <https://github.com/aio-libs/aiohttp/pull/1807>`_)
- Handle socket error in FileResponse (`#1773 <https://github.com/aio-libs/aiohttp/pull/1773>`_)
- Cancel websocket heartbeat on close (`#1793 <https://github.com/aio-libs/aiohttp/pull/1793>`_)



----


2.0.6 (2017-04-04)
==================

- Keeping blank values for `request.post()` and `multipart.form()` (`#1765 <https://github.com/aio-libs/aiohttp/pull/1765>`_)
- TypeError in data_received of ResponseHandler (`#1770 <https://github.com/aio-libs/aiohttp/pull/1770>`_)
- Fix ``web.run_app`` not to bind to default host-port pair if only socket is
  passed (`#1786 <https://github.com/aio-libs/aiohttp/pull/1786>`_)



----


2.0.5 (2017-03-29)
==================

- Memory leak with aiohttp.request (`#1756 <https://github.com/aio-libs/aiohttp/pull/1756>`_)
- Disable cleanup closed ssl transports by default.
- Exception in request handling if the server responds before the body
  is sent (`#1761 <https://github.com/aio-libs/aiohttp/pull/1761>`_)



----


2.0.4 (2017-03-27)
==================

- Memory leak with aiohttp.request (`#1756 <https://github.com/aio-libs/aiohttp/pull/1756>`_)
- Encoding is always UTF-8 in POST data (`#1750 <https://github.com/aio-libs/aiohttp/pull/1750>`_)
- Do not add "Content-Disposition" header by default (`#1755 <https://github.com/aio-libs/aiohttp/pull/1755>`_)



----


2.0.3 (2017-03-24)
==================

- Call https website through proxy will cause error (`#1745 <https://github.com/aio-libs/aiohttp/pull/1745>`_)
- Fix exception on multipart/form-data post if content-type is not set (`#1743 <https://github.com/aio-libs/aiohttp/pull/1743>`_)



----


2.0.2 (2017-03-21)
==================

- Fixed Application.on_loop_available signal (`#1739 <https://github.com/aio-libs/aiohttp/pull/1739>`_)
- Remove debug code



----


2.0.1 (2017-03-21)
==================

- Fix allow-head to include name on route (`#1737 <https://github.com/aio-libs/aiohttp/pull/1737>`_)
- Fixed AttributeError in WebSocketResponse.can_prepare (`#1736 <https://github.com/aio-libs/aiohttp/pull/1736>`_)



----


2.0.0 (2017-03-20)
==================

- Added `json` to `ClientSession.request()` method (`#1726 <https://github.com/aio-libs/aiohttp/pull/1726>`_)
- Added session's `raise_for_status` parameter, automatically calls
  raise_for_status() on any request. (`#1724 <https://github.com/aio-libs/aiohttp/pull/1724>`_)
- `response.json()` raises `ClientResponseError` exception if response's
  content type does not match (`#1723 <https://github.com/aio-libs/aiohttp/pull/1723>`_)
  - Cleanup timer and loop handle on any client exception.
- Deprecate `loop` parameter for Application's constructor
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



----


1.3.5 (2017-03-16)
==================

- Fixed None timeout support (`#1720 <https://github.com/aio-libs/aiohttp/pull/1720>`_)



----


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



----


1.3.3 (2017-02-19)
==================

- Fixed memory leak in time service (`#1656 <https://github.com/aio-libs/aiohttp/pull/1656>`_)



----


1.3.2 (2017-02-16)
==================

- Awaiting on WebSocketResponse.send_* does not work (`#1645 <https://github.com/aio-libs/aiohttp/pull/1645>`_)
- Fix multiple calls to client ws_connect when using a shared header
  dict (`#1643 <https://github.com/aio-libs/aiohttp/pull/1643>`_)
- Make CookieJar.filter_cookies() accept plain string parameter. (`#1636 <https://github.com/aio-libs/aiohttp/pull/1636>`_)



----


1.3.1 (2017-02-09)
==================

- Handle CLOSING in WebSocketResponse.__anext__
- Fixed AttributeError 'drain' for server websocket handler (`#1613 <https://github.com/aio-libs/aiohttp/pull/1613>`_)



----


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



----


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



----


1.1.6 (2016-11-28)
==================

- Fix `BodyPartReader.read_chunk` bug about returns zero bytes before
  `EOF` (`#1428 <https://github.com/aio-libs/aiohttp/pull/1428>`_)



----

1.1.5 (2016-11-16)
==================

- Fix static file serving in fallback mode (`#1401 <https://github.com/aio-libs/aiohttp/pull/1401>`_)



----

1.1.4 (2016-11-14)
==================

- Make `TestServer.make_url` compatible with `yarl.URL` (`#1389 <https://github.com/aio-libs/aiohttp/pull/1389>`_)
- Generate informative exception on redirects from server which
  does not provide redirection headers (`#1396 <https://github.com/aio-libs/aiohttp/pull/1396>`_)



----


1.1.3 (2016-11-10)
==================

- Support *root* resources for sub-applications (`#1379 <https://github.com/aio-libs/aiohttp/pull/1379>`_)



----


1.1.2 (2016-11-08)
==================

- Allow starting variables with an underscore (`#1379 <https://github.com/aio-libs/aiohttp/pull/1379>`_)
- Properly process UNIX sockets by gunicorn worker (`#1375 <https://github.com/aio-libs/aiohttp/pull/1375>`_)
- Fix ordering for `FrozenList`
- Don't propagate pre and post signals to sub-application (`#1377 <https://github.com/aio-libs/aiohttp/pull/1377>`_)



----

1.1.1 (2016-11-04)
==================

- Fix documentation generation (`#1120 <https://github.com/aio-libs/aiohttp/pull/1120>`_)



----

1.1.0 (2016-11-03)
==================

- Drop deprecated `WSClientDisconnectedError` (BACKWARD INCOMPATIBLE)
- Use `yarl.URL` in client API. The change is 99% backward compatible
  but `ClientResponse.url` is an `yarl.URL` instance now. (`#1217 <https://github.com/aio-libs/aiohttp/pull/1217>`_)
- Close idle keep-alive connections on shutdown (`#1222 <https://github.com/aio-libs/aiohttp/pull/1222>`_)
- Modify regex in AccessLogger to accept underscore and numbers (`#1225 <https://github.com/aio-libs/aiohttp/pull/1225>`_)
- Use `yarl.URL` in web server API. `web.Request.rel_url` and `web.Request.url` are added. URLs and templates are
  percent-encoded now. (`#1224 <https://github.com/aio-libs/aiohttp/pull/1224>`_)
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



----

1.0.5 (2016-10-11)
==================

- Fix StreamReader._read_nowait to return all available
  data up to the requested amount (`#1297 <https://github.com/aio-libs/aiohttp/pull/1297>`_)



----


1.0.4 (2016-09-22)
==================

- Fix FlowControlStreamReader.read_nowait so that it checks
  whether the transport is paused (`#1206 <https://github.com/aio-libs/aiohttp/pull/1206>`_)



----


1.0.2 (2016-09-22)
==================

- Make CookieJar compatible with 32-bit systems (`#1188 <https://github.com/aio-libs/aiohttp/pull/1188>`_)
- Add missing `WSMsgType` to `web_ws.__all__`, see (`#1200 <https://github.com/aio-libs/aiohttp/pull/1200>`_)
- Fix `CookieJar` ctor when called with `loop=None` (`#1203 <https://github.com/aio-libs/aiohttp/pull/1203>`_)
- Fix broken upper-casing in wsgi support (`#1197 <https://github.com/aio-libs/aiohttp/pull/1197>`_)



----


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



----


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
- Rename ``aiohttp.MsgType`` to ``aiohttp.WSMsgType``
- Introduce ``aiohttp.WSMessage`` officially
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



----


0.22.5 (08-02-2016)
===================

- Pin miltidict version to >=1.2.2



----

0.22.3 (07-26-2016)
===================

- Do not filter cookies if unsafe flag provided (`#1005 <https://github.com/aio-libs/aiohttp/pull/1005>`_)



----


0.22.2 (07-23-2016)
===================

- Suppress CancelledError when Timeout raises TimeoutError (`#970 <https://github.com/aio-libs/aiohttp/pull/970>`_)
- Don't expose `aiohttp.__version__`
- Add unsafe parameter to CookieJar (`#968 <https://github.com/aio-libs/aiohttp/pull/968>`_)
- Use unsafe cookie jar in test client tools
- Expose aiohttp.CookieJar name



----


0.22.1 (07-16-2016)
===================

- Large cookie expiration/max-age does not break an event loop from now
  (fixes (`#967 <https://github.com/aio-libs/aiohttp/pull/967>`_))



----


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



----

0.21.6 (05-05-2016)
===================

- Drop initial query parameters on redirects (`#853 <https://github.com/aio-libs/aiohttp/pull/853>`_)



----


0.21.5 (03-22-2016)
===================

- Fix command line arg parsing (`#797 <https://github.com/aio-libs/aiohttp/pull/797>`_)



----

0.21.4 (03-12-2016)
===================

- Fix ResourceAdapter: don't add method to allowed if resource is not
  match (`#826 <https://github.com/aio-libs/aiohttp/pull/826>`_)
- Fix Resource: append found method to returned allowed methods



----

0.21.2 (02-16-2016)
===================

- Fix a regression: support for handling ~/path in static file routes was
  broken (`#782 <https://github.com/aio-libs/aiohttp/pull/782>`_)



----

0.21.1 (02-10-2016)
===================

- Make new resources classes public (`#767 <https://github.com/aio-libs/aiohttp/pull/767>`_)
- Add `router.resources()` view
- Fix cmd-line parameter names in doc



----

0.21.0 (02-04-2016)
===================

- Introduce on_shutdown signal (`#722 <https://github.com/aio-libs/aiohttp/pull/722>`_)
- Implement raw input headers (`#726 <https://github.com/aio-libs/aiohttp/pull/726>`_)
- Implement web.run_app utility function (`#734 <https://github.com/aio-libs/aiohttp/pull/734>`_)
- Introduce on_cleanup signal
- Deprecate Application.finish() / Application.register_on_finish() in favor of on_cleanup.
- Get rid of bare aiohttp.request(), aiohttp.get() and family in docs (`#729 <https://github.com/aio-libs/aiohttp/pull/729>`_)
- Deprecate bare aiohttp.request(), aiohttp.get() and family (`#729 <https://github.com/aio-libs/aiohttp/pull/729>`_)
- Refactor keep-alive support (`#737 <https://github.com/aio-libs/aiohttp/pull/737>`_)

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
- Deprecate app.router.register_route() (the method was not documented intentionally BTW).
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



----

0.20.2 (01-07-2016)
===================

- Enable use of `await` for a class based view (`#717 <https://github.com/aio-libs/aiohttp/pull/717>`_)
- Check address family to fill wsgi env properly (`#718 <https://github.com/aio-libs/aiohttp/pull/718>`_)
- Fix memory leak in headers processing (thanks to Marco Paolini) (`#723 <https://github.com/aio-libs/aiohttp/pull/723>`_



----)

0.20.1 (12-30-2015)
===================

- Raise RuntimeError is Timeout context manager was used outside of
  task context.
- Add number of bytes to stream.read_nowait (`#700 <https://github.com/aio-libs/aiohttp/pull/700>`_)
- Use X-FORWARDED-PROTO for wsgi.url_scheme when available



----


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



----


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



----

0.18.4 (13-11-2015)
===================

- Relax rule for router names again by adding dash to allowed
  characters: they may contain identifiers, dashes, dots and columns



----

0.18.3 (25-10-2015)
===================

- Fix formatting for _RequestContextManager helper (`#590 <https://github.com/aio-libs/aiohttp/pull/590>`_)



----

0.18.2 (22-10-2015)
===================

- Fix regression for OpenSSL < 1.0.0 (`#583 <https://github.com/aio-libs/aiohttp/pull/583>`_)



----

0.18.1 (20-10-2015)
===================

- Relax rule for router names: they may contain dots and columns
  starting from now



----

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



----

0.17.4 (09-29-2015)
===================

- Properly parse URL path in aiohttp.web.Request (`#489 <https://github.com/aio-libs/aiohttp/pull/489>`_)
- Add missing coroutine decorator, the client api is await-compatible now



----

0.17.3 (08-28-2015)
===================

- Remove Content-Length header on compressed responses (`#450 <https://github.com/aio-libs/aiohttp/pull/450>`_)
- Support Python 3.5
- Improve performance of transport in-use list (`#472 <https://github.com/aio-libs/aiohttp/pull/472>`_)
- Fix connection pooling (`#473 <https://github.com/aio-libs/aiohttp/pull/473>`_)



----

0.17.2 (08-11-2015)
===================

- Don't forget to pass `data` argument forward (`#462 <https://github.com/aio-libs/aiohttp/pull/462>`_)
- Fix multipart read bytes count (`#463 <https://github.com/aio-libs/aiohttp/pull/463>`_)



----

0.17.1 (08-10-2015)
===================

- Fix multidict comparison to arbitrary abc.Mapping



----

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



----


0.16.6 (07-15-2015)
===================

- Skip compilation on Windows if vcvarsall.bat cannot be found (`#438 <https://github.com/aio-libs/aiohttp/pull/438>`_)



----

0.16.5 (06-13-2015)
===================

- Get rid of all comprehensions and yielding in _multidict (`#410 <https://github.com/aio-libs/aiohttp/pull/410>`_)



----


0.16.4 (06-13-2015)
===================

- Don't clear current exception in multidict's `__repr__` (cythonized
  versions) (`#410 <https://github.com/aio-libs/aiohttp/pull/410>`_)



----


0.16.3 (05-30-2015)
===================

- Fix StaticRoute vulnerability to directory traversal attacks (`#380 <https://github.com/aio-libs/aiohttp/pull/380>`_)



----


0.16.2 (05-27-2015)
===================

- Update python version required for `__del__` usage: it's actually
  3.4.1 instead of 3.4.0
- Add check for presence of loop.is_closed() method before call the
  former (`#378 <https://github.com/aio-libs/aiohttp/pull/378>`_)



----


0.16.1 (05-27-2015)
===================

- Fix regression in static file handling (`#377 <https://github.com/aio-libs/aiohttp/pull/377>`_)



----

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



----


0.15.3 (04-22-2015)
===================

- Fix graceful shutdown handling
- Fix `Expect` header handling for not found and not allowed routes (`#340 <https://github.com/aio-libs/aiohttp/pull/340>`_)



----


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



----


0.15.1 (03-31-2015)
===================

- Pass Autobahn Testsuite tests
- Fixed websocket fragmentation
- Fixed websocket close procedure
- Fixed parser buffer limits
- Added `timeout` parameter to WebSocketResponse ctor
- Added `WebSocketResponse.close_code` attribute



----


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



----


0.14.4 (01-29-2015)
===================

- Fix issue with error during constructing of url with regex parts (`#264 <https://github.com/aio-libs/aiohttp/pull/264>`_)



----


0.14.3 (01-28-2015)
===================

- Use path='/' by default for cookies (`#261 <https://github.com/aio-libs/aiohttp/pull/261>`_)



----


0.14.2 (01-23-2015)
===================

- Connections leak in BaseConnector (`#253 <https://github.com/aio-libs/aiohttp/pull/253>`_)
- Do not swallow websocket reader exceptions (`#255 <https://github.com/aio-libs/aiohttp/pull/255>`_)
- web.Request's read, text, json are memorized (`#250 <https://github.com/aio-libs/aiohttp/pull/250>`_)



----


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



----


0.13.1 (12-31-2014)
===================

- Add `aiohttp.web.StreamResponse.started` property (`#213 <https://github.com/aio-libs/aiohttp/pull/213>`_)
- HTML escape traceback text in `ServerHttpProtocol.handle_error`
- Mention handler and middlewares in `aiohttp.web.RequestHandler.handle_request`
  on error ((`#218 <https://github.com/aio-libs/aiohttp/pull/218>`_))



----


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



----


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



----


0.11.0 (11-29-2014)
===================

- Support named routes in `aiohttp.web.UrlDispatcher` (`#179 <https://github.com/aio-libs/aiohttp/pull/179>`_)
- Make websocket subprotocols conform to spec (`#181 <https://github.com/aio-libs/aiohttp/pull/181>`_)



----


0.10.2 (11-19-2014)
===================

- Don't unquote `environ['PATH_INFO']` in wsgi.py (`#177 <https://github.com/aio-libs/aiohttp/pull/177>`_)



----


0.10.1 (11-17-2014)
===================

- aiohttp.web.HTTPException and descendants now files response body
  with string like `404: NotFound`
- Fix multidict `__iter__`, the method should iterate over keys, not
  (key, value) pairs.



----


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



----


0.9.3 (10-30-2014)
==================

- Fix compatibility with asyncio 3.4.1+ (`#170 <https://github.com/aio-libs/aiohttp/pull/170>`_)



----


0.9.2 (10-16-2014)
==================

- Improve redirect handling (`#157 <https://github.com/aio-libs/aiohttp/pull/157>`_)
- Send raw files as is (`#153 <https://github.com/aio-libs/aiohttp/pull/153>`_)
- Better websocket support (`#150 <https://github.com/aio-libs/aiohttp/pull/150>`_)



----


0.9.1 (08-30-2014)
==================

- Added MultiDict support for client request params and data (`#114 <https://github.com/aio-libs/aiohttp/pull/114>`_).
- Fixed parameter type for IncompleteRead exception (`#118 <https://github.com/aio-libs/aiohttp/pull/118>`_).
- Strictly require ASCII headers names and values (`#137 <https://github.com/aio-libs/aiohttp/pull/137>`_)
- Keep port in ProxyConnector (`#128 <https://github.com/aio-libs/aiohttp/pull/128>`_).
- Python 3.4.1 compatibility (`#131 <https://github.com/aio-libs/aiohttp/pull/131>`_).



----


0.9.0 (07-08-2014)
==================

- Better client basic authentication support (`#112 <https://github.com/aio-libs/aiohttp/pull/112>`_).
- Fixed incorrect line splitting in HttpRequestParser (`#97 <https://github.com/aio-libs/aiohttp/pull/97>`_).
- Support StreamReader and DataQueue as request data.
- Client files handling refactoring (`#20 <https://github.com/aio-libs/aiohttp/pull/20>`_).
- Backward incompatible: Replace DataQueue with StreamReader for
  request payload (`#87 <https://github.com/aio-libs/aiohttp/pull/87>`_).



----


0.8.4 (07-04-2014)
==================

- Change ProxyConnector authorization parameters.



----


0.8.3 (07-03-2014)
==================

- Publish TCPConnector properties: verify_ssl, family, resolve, resolved_hosts.
- Don't parse message body for HEAD responses.
- Refactor client response decoding.



----


0.8.2 (06-22-2014)
==================

- Make ProxyConnector.proxy immutable property.
- Make UnixConnector.path immutable property.
- Fix resource leak for aiohttp.request() with implicit connector.
- Rename Connector's reuse_timeout to keepalive_timeout.



----


0.8.1 (06-18-2014)
==================

- Use case insensitive multidict for server request/response headers.
- MultiDict.getall() accepts default value.
- Catch server ConnectionError.
- Accept MultiDict (and derived) instances in aiohttp.request header argument.
- Proxy 'CONNECT' support.



----


0.8.0 (06-06-2014)
==================

- Add support for utf-8 values in HTTP headers
- Allow to use custom response class instead of HttpResponse
- Use MultiDict for client request headers
- Use MultiDict for server request/response headers
- Store response headers in ClientResponse.headers attribute
- Get rid of timeout parameter in aiohttp.client API
- Exceptions refactoring



----


0.7.3 (05-20-2014)
==================

- Simple HTTP proxy support.



----


0.7.2 (05-14-2014)
==================

- Get rid of `__del__` methods
- Use ResourceWarning instead of logging warning record.



----


0.7.1 (04-28-2014)
==================

- Do not unquote client request urls.
- Allow multiple waiters on transport drain.
- Do not return client connection to pool in case of exceptions.
- Rename SocketConnector to TCPConnector and UnixSocketConnector to
  UnixConnector.



----


0.7.0 (04-16-2014)
==================

- Connection flow control.
- HTTP client session/connection pool refactoring.
- Better handling for bad server requests.



----


0.6.5 (03-29-2014)
==================

- Added client session reuse timeout.
- Better client request cancellation support.
- Better handling responses without content length.
- Added HttpClient verify_ssl parameter support.



----


0.6.4 (02-27-2014)
==================

- Log content-length missing warning only for put and post requests.



----


0.6.3 (02-27-2014)
==================

- Better support for server exit.
- Read response body until EOF if content-length is not defined (`#14 <https://github.com/aio-libs/aiohttp/pull/14>`_)



----


0.6.2 (02-18-2014)
==================

- Fix trailing char in allowed_methods.
- Start slow request timer for first request.



----


0.6.1 (02-17-2014)
==================

- Added utility method HttpResponse.read_and_close()
- Added slow request timeout.
- Enable socket SO_KEEPALIVE if available.



----


0.6.0 (02-12-2014)
==================

- Better handling for process exit.



----


0.5.0 (01-29-2014)
==================
- Allow to use custom HttpRequest client class.
- Use gunicorn keepalive setting for asynchronous worker.
- Log leaking responses.
- python 3.4 compatibility



----


0.4.4 (11-15-2013)
==================

- Resolve only AF_INET family, because it is not clear how to pass
  extra info to asyncio.



----


0.4.3 (11-15-2013)
==================

- Allow to wait completion of request with `HttpResponse.wait_for_close()`



----


0.4.2 (11-14-2013)
==================

- Handle exception in client request stream.
- Prevent host resolving for each client request.



----


0.4.1 (11-12-2013)
==================

- Added client support for `expect: 100-continue` header.



----


0.4 (11-06-2013)
================

- Added custom wsgi application close procedure
- Fixed concurrent host failure in HttpClient



----


0.3 (11-04-2013)
================

- Added PortMapperWorker
- Added HttpClient
- Added TCP connection timeout to HTTP client
- Better client connection errors handling
- Gracefully handle process exit



----


0.2
===

- Fix packaging
