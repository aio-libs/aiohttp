CHANGES
=======

1.1.5 (2016-11-16)
------------------

- Fix static file serving in fallback mode #1401

1.1.4 (2016-11-14)
------------------

- Make `TestServer.make_url` compatible with `yarl.URL` #1389

- Generate informative exception on redirects from server which
  doesn't provide redirection headers #1396


1.1.3 (2016-11-10)
------------------

- Support *root* resources for sub-applications #1379


1.1.2 (2016-11-08)
------------------

- Allow starting variables with an underscore #1379

- Properly process UNIX sockets by gunicorn worker #1375

- Fix ordering for `FrozenList`

- Don't propagate pre and post signals to sub-application #1377

1.1.1 (2016-11-04)
------------------

- Fix documentation generation #1120

1.1.0 (2016-11-03)
------------------

- Drop deprecated `WSClientDisconnectedError` (BACKWARD INCOMPATIBLE)

- Use `yarl.URL` in client API. The change is 99% backward compatible
  but `ClientResponse.url` is an `yarl.URL` instance now. #1217

- Close idle keep-alive connections on shutdown #1222

- Modify regex in AccessLogger to accept underscore and numbers #1225

- Use `yarl.URL` in web server API. `web.Request.rel_url` and
  `web.Request.url` are added. URLs and templates are percent-encoded
  now. #1224

- Accept `yarl.URL` by server redirections #1278

- Return `yarl.URL` by `.make_url()` testing utility #1279

- Properly format IPv6 addresses by `aiohttp.web.run_app` #1139

- Use `yarl.URL` by server API #1288

  * Introduce `resource.url_for()`, deprecate `resource.url()`.

  * Implement `StaticResource`.

  * Inherit `SystemRoute` from `AbstractRoute`

  * Drop old-style routes: `Route`, `PlainRoute`, `DynamicRoute`,
    `StaticRoute`, `ResourceAdapter`.

- Revert `resp.url` back to `str`, introduce `resp.url_obj` #1292

- Raise ValueError if BasicAuth login has a ":" character #1307

- Fix bug when ClientRequest send payload file with opened as
  open('filename', 'r+b') #1306

- Enhancement to AccessLogger (pass *extra* dict) #1303

- Show more verbose message on import errors #1319

- Added save and load functionality for `CookieJar` #1219

- Added option on `StaticRoute` to follow symlinks #1299

- Force encoding of `application/json` content type to utf-8 #1339

- Fix invalid invocations of `errors.LineTooLong` #1335

- Websockets: Stop `async for` iteration when connection is closed #1144

- Ensure TestClient HTTP methods return a context manager #1318

- Raise `ClientDisconnectedError` to `FlowControlStreamReader` read function
  if `ClientSession` object is closed by client when reading data. #1323

- Document deployment without `Gunicorn` #1120

- Add deprecation warning for MD5 and SHA1 digests when used for fingerprint
  of site certs in TCPConnector. #1186

- Implement sub-applications #1301

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

- Boost performance by adding a custom time service #1350

- Extend `ClientResponse` with `content_type` and `charset`
  properties like in `web.Request`. #1349

- Disable aiodns by default #559

- Don't flap `tcp_cork` in client code, use TCP_NODELAY mode by default.

- Implement `web.Request.clone()` #1361
