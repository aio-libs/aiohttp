CHANGES
=======

1.3.0 (XXXX-XX-XX)
------------------

- separate read + connect + request timeouts # 1523

- Fix polls demo run application #1487

- Ignore unknown 1XX status codes in client #1353

- Fix sub-Multipart messages missing their headers on serialization #1525

- Do not use readline when reading the content of a part
  in the multipart reader #1535

- Remove `web.Application` dependency from `web.UrlDispatcher` #1510

- Do not pause transport during set_parser stage #1211

- Lingering close doesn't terminate before timeout #1559
  
- Lots of CancelledError when requests are interrupted #1565

- Allow users to specify what should happen to decoding errors
  when calling a responses `text()` method #1542

- Return 504 if request handle raises TimeoutError.

- Refactor how we use keep-alive and clone lingering timeouts.


1.2.0 (2016-12-17)
------------------

- Extract `BaseRequest` from `web.Request`, introduce `web.Server`
  (former `RequestHandlerFactory`), introduce new low-level web server
  which is not coupled with `web.Application` and routing #1362

- Make `TestServer.make_url` compatible with `yarl.URL` #1389

- Implement range requests for static files #1382

- Support task attribute for StreamResponse #1410

- Drop `TestClient.app` property, use `TestClient.server.app` instead
  (BACKWARD INCOMPATIBLE)

- Drop `TestClient.handler` property, use `TestClient.server.handler` instead
  (BACKWARD INCOMPATIBLE)

- `TestClient.server` property returns a test server instance, was
  `asyncio.AbstractServer` (BACKWARD INCOMPATIBLE)

- Follow gunicorn's signal semantics in `Gunicorn[UVLoop]WebWorker` #1201

- Call worker_int and worker_abort callbacks in
  `Gunicorn[UVLoop]WebWorker` #1202

- Has functional tests for client proxy #1218

- Fix bugs with client proxy target path and proxy host with port #1413

- Fix bugs related to the use of unicode hostnames #1444

- Preserve cookie quoting/escaping #1453

- FileSender will send gzipped response if gzip version available #1426

- Don't override `Content-Length` header in `web.Response` if no body
  was set #1400

- Introduce `router.post_init()` for solving #1373

- Fix raise error in case of multiple calls of `TimeServive.stop()`

- Allow to raise web exceptions on router resolving stage #1460

- Add a warning for session creation outside of coroutine #1468

- Avoid a race when application might start accepting incoming requests
  but startup signals are not processed yet e98e8c6

- Raise a `RuntimeError` when trying to change the status of the HTTP response
  after the headers have been sent #1480

- Fix bug with https proxy acquired cleanup #1340

- Use UTF-8 as the default encoding for multipart text parts #1484
