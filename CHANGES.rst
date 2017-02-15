CHANGES
=======

1.4.0 (XXXX-XX-XX)
------------------
- `run_app` and the Command Line Interface now support serving over Unix domain sockets for
  faster inter-process communication.

- Added `capacity` parameter for client connector object.
  Capacity is the total number of simultaneous connections.  #1601

- Deprecate connector's `limit` parameter #1601

- Dropped: `aiohttp.protocol.HttpPrefixParser`  #1590

- Dropped: Servers response's `.started`, `.start()` and `.can_start()` method  #1591

- Dropped: Adding `sub app` via `app.router.add_subapp()` is deprecated
  use `app.add_subapp()` instead #1592

- Dropped: `Application.finish()` and `Application.register_on_finish()`  #1602

- Dropped: aiohttp.get(), aiohttp.options(), aiohttp.head(), aiohttp.post(),
  aiohttp.put(), aiohttp.patch(), aiohttp.delete(), and aiohttp.ws_connect() #1593

- Dropped: `aiohttp.web.WebSocketResponse.receive_msg()` #1605

- Dropped: `ServerHttpProtocol.keep_alive_timeout` attribute and
  `keep-alive`, `keep_alive_on`, `timeout`, `log` constructor parameters #1606

- Dropped: `TCPConnector's`` `.resolve`, `.resolved_hosts`, `.clear_resolved_hosts()`
  attributes and `resolve` constructor  parameter #1607

- Dropped `ProxyConnector` #1609

- Allow string parameter for `aiohttp.CookieJar.filter_cookies()` #1636
