CHANGES
=======

1.3.0 (2017-02-08)
------------------

- Multipart writer validates the data on append instead of on a request send #920

- Multipart reader accepts multipart messages with or without their epilogue
  to consistently handle valid and legacy behaviors #1526 #1581

- Separate read + connect + request timeouts # 1523

- Do not swallow Upgrade header #1587

- Fix polls demo run application #1487

- Ignore unknown 1XX status codes in client #1353

- Fix sub-Multipart messages missing their headers on serialization #1525

- Do not use readline when reading the content of a part
  in the multipart reader #1535
  
- Add optional flag for quoting `FormData` fields #916

- 416 Range Not Satisfiable if requested range end > file size #1588

- Having a `:` or `@` in a route does not work #1552

- Added `receive_timeout` timeout for websocket to receive complete message. #1325

- Added `heartbeat` parameter for websocket to automatically send `ping` message. #1024 #777

- Remove `web.Application` dependency from `web.UrlDispatcher` #1510

- Accepting back-pressure from slow websocket clients #1367

- Do not pause transport during set_parser stage #1211

- Lingering close doesn't terminate before timeout #1559

- `setsockopt` may raise `OSError` exception if socket is closed already #1595

- Lots of CancelledError when requests are interrupted #1565

- Allow users to specify what should happen to decoding errors
  when calling a responses `text()` method #1542

- Back port std module `http.cookies` for python3.4.2 #1566

- Maintain url's fragment in client response #1314

- Allow concurrently close WebSocket connection #754

- Gzipped responses with empty body raises ContentEncodingError #609

- Return 504 if request handle raises TimeoutError.

- Refactor how we use keep-alive and close lingering timeouts.

- Close response connection if we can not consume whole http
  message during client response release

- Abort closed ssl client transports, broken servers can keep socket open un-limit time #1568

- Log warning instead of `RuntimeError` is websocket connection is closed.

- Deprecated: `aiohttp.protocol.HttpPrefixParser`
  will be removed in 1.4 #1590

- Deprecated: Servers response's `.started`, `.start()` and `.can_start()` method
  will be removed in 1.4 #1591

- Deprecated: Adding `sub app` via `app.router.add_subapp()` is deprecated
  use `app.add_subapp()` instead, will be removed in 1.4 #1592

- Deprecated: aiohttp.get(), aiohttp.options(), aiohttp.head(), aiohttp.post(),
  aiohttp.put(), aiohttp.patch(), aiohttp.delete(), and aiohttp.ws_connect()
  will be removed in 1.4 #1593

- Deprecated: `Application.finish()` and `Application.register_on_finish()`
  will be removed in 1.4 #1602
