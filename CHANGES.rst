CHANGES
=======

1.4.0 (XXXX-XX-XX)
------------------

- Dropped: `aiohttp.protocol.HttpPrefixParser`  #1590

- Dropped: Servers response's `.started`, `.start()` and `.can_start()` method  #1591

- Dropped: Adding `sub app` via `app.router.add_subapp()` is deprecated
  use `app.add_subapp()` instead #1592

- Dropped: `Application.finish()` and `Application.register_on_finish()`  #1602

- Dropped: aiohttp.get(), aiohttp.options(), aiohttp.head(), aiohttp.post(),
  aiohttp.put(), aiohttp.patch(), aiohttp.delete(), and aiohttp.ws_connect() #1593

- Dropped: `aiohttp.web.WebSocketResponse.receive_msg()` #1605

- Dropped: `ServerHttpProtocol.keep_alive_timeout` attr and
  `keep-alive`, `keep_alive_on`, `timeout`, `log` ctor parameters #1606
