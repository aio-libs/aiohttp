..
    You should *NOT* be adding new change log entries to this file, this
    file is managed by towncrier. You *may* edit previous change logs to
    fix problems like typo corrections or such.
    To add a new change log entry, please see
    https://pip.pypa.io/en/latest/development/#adding-a-news-entry
    we named the news folder "changes".

    WARNING: Don't drop the next directive!

.. towncrier release notes start

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
  It will cause a index out of range error in aiohttp. For example, if user compile CPython with
  `--disable-ipv6` option but his system enable the ipv6.
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
