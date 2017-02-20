CHANGES
=======

2.0.0 (2016-03-XX)
------------------

- Connector's `limit` parameter indicates total concurrent connections.
  New `limit_per_host` added, indicates total connections per endpoint. #1601

- Change `ClientResponse.url` to `yarl.URL` instance #1654

- Add max_size parameter to web.Request reading methods #1133

- Do not close connector if client session does not own it #883

- `run_app` and the Command Line Interface now support serving over
  Unix domain sockets for faster inter-process communication.

- Implementation for Trailer headers parser is broken #1619

- Deprecate public low-level api #1657

- Dropped aiohttp.wsgi #1108

- Dropped websocket version 76 support #1160

- Dropped: `aiohttp.protocol.HttpPrefixParser`  #1590

- Dropped: Servers response's `.started`, `.start()` and `.can_start()` method  #1591

- Dropped:  Adding `sub app` via `app.router.add_subapp()` is deprecated
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
