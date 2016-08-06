CHANGES
=======

1.0.0 (XX-XX-XXXX)
-------------------

- Change default size for client session's connection pool from
  unlimited to 20 #977

- Add IE support for cookie deletion. #994

- Remove deprecated `WebSocketResponse.wait_closed` method (BACKWARD
  INCOMPATIBLE)

- Remove deprecated `force` parameter for `ClientResponse.close`
  method (BACKWARD INCOMPATIBLE)

- Avoid using of mutable CIMultiDict kw param in make_mocked_request
  #997

- Make WebSocketResponse.close a little bit faster by avoiding new
  task creating just for timeout measurement

- Add `proxy` and `proxy_auth` params to `client.get()` and family,
  deprecate `ProxyConnector` #998

- Add support for websocket send_json and receive_json, synchronize
  server and client API for websockets #984

- Implement router shourtcuts for most useful HTTP methods, use
  `app.router.add_get()`, `app.router.add_post()` etc. instead of
  `app.router.add_route()` #986

- Support SSL connections for gunicorn worker #1003

- Move obsolete examples to legacy folder

- Switch to multidict 2.0 and title-cased strings #1015

- `{FOO}e` logger format is case-sensetive now

- Fix logger report for unix socket 8e8469b

- Rename aiohttp.websocket to aiohttp._ws_impl

- Rename aiohttp.MsgType tp aiohttp.WSMsgType

- Introduce aiohttp.WSMessage officially

- Rename Message -> WSMessage

- Remove deprecated decode param from resp.read(decode=True)

- Use 5min default client timeout #1028

- Relax HTTP method validation in UrlDispatcher #1037

- Pin minimal supported asyncio version to 3.4.2+ (`loop.is_close()`
  should be present)

- Remove aiohttp.websocket module (BACKWARD IMCOMPATIBLE)
  Please use high-level client and server approaches

- Link header for 451 status code is mandatory

- Implement lingering on server-side trasport closing #1050


0.22.5 (08-02-2016)
-------------------

- Pin miltidict version to >=1.2.2

0.22.3 (07-26-2016)
-------------------

- Do not filter cookies if unsafe flag provided #1005


0.22.2 (07-23-2016)
-------------------

- Suppress CancelledError when Timeout raises TimeoutError #970

- Don't expose `aiohttp.__version__`

- Add unsafe parameter to CookieJar #968

- Use unsafe cookie jar in test client tools

- Expose aiohttp.CookieJar name


0.22.1 (07-16-2016)
-------------------

- Large cookie expiration/max-age doesn't break an event loop from now
  (fixes #967)


0.22.0 (07-15-2016)
-------------------

- Fix bug in serving static directory #803

- Fix command line arg parsing #797

- Fix a documentation chapter about cookie usage #790

- Handle empty body with gzipped encoding #758

- Support 451 Unavailable For Legal Reasons http status  #697

- Fix Cookie share example and few small typos in docs #817

- UrlDispatcher.add_route with partial coroutine handler #814

- Optional support for aiodns #728

- Add ServiceRestart and TryAgainLater websocket close codes #828

- Fix prompt message for `web.run_app` #832

- Allow to pass None as a timeout value to disable timeout logic #834

- Fix leak of connection slot during connection erro #835

- Gunicorn worker with uvloop support `aiohttp.worker.GunicornUVLoopWebWorker` #878

- Don't send body in response to HEAD request #838

- Skip the preamble in MultipartReader #881

- Implement BasicAuth decode classmethod. #744

- Don't crash logger when transport is None #889

- Use a create_future compatibility wrapper instead of creating
  Futures directly #896

- Add test utilities to aiohttp #902

- Improve Request.__repr__ #875

- Skip DNS resolving if provided host is already an ip address #874

- Add headers to ClientSession.ws_connect #785

- Document that server can send pre-compressed data #906

- Don't add Content-Encoding and Transfer-Encoding if no body #891

- Add json() convenience methods to websocket message objects #897

- Add client_resp.raise_for_status() #908

- Implement cookie filter #799

- Include an example of middleware to handle error pages #909

- Fix error handling in StaticFileMixin #856

- Add mocked request helper #900

- Fix empty ALLOW Response header for cls based View #929

- Respect CONNECT method to implement a proxy server #847

- Add pytest_plugin #914

- Add tutorial

- Add backlog option to support more than 128 (default value in
  "create_server" function) concurrent connections #892

- Allow configuration of header size limits #912

- Separate sending file logic from StaticRoute dispatcher #901

- Drop deprecated share_cookies connector option (BACKWARD INCOMPATIBLE)

- Drop deprecated support for tuple as auth paramter.
  Use aiohttp.BasicAuth instead (BACKWARD INCOMPATIBLE)

- Remove deprecated `request.payload` property, use `content` instead.
  (BACKWARD INCOMPATIBLE)

- Drop all mentions about api changes in documentaion for versions
  older than 0.16

- Allow to override default cookie jar #963

- Add manylinux wheel builds

- Dup a socket for sendfile usage #964
