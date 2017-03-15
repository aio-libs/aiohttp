Major aiohttp2.0 release!
=========================

Warning! This is not final release. It contains backward incompatible change,
please check compatibility before installing on production systems.

For this release we completely refactored low-level implementation of http handling.
Finally `uvloop` gives performance improvement. Overall performance improvement
should be around 70-90% compared to 1.x version.

We took opportunity to refactor long standing api design problem across whole package.
Client exceptions handling has been cleaned up and now much more strait forward. Client payload
management simplified and allows to extends with any custom types. Client collection pool
implementation has been redesigned as well, now there is no need for actively releasing responses,
aiohttp handles connection release automatically.

Another major change, we moved aiohttp development to public organization https://github.com/aio-libs
The aiohttp community would like to thank `Keepsafe` (https://www.getkeepsafe.com) for it's support in the early days of the project.

Alas we had to make backward incompatible changes. Please check this migration document http://aiohttp.readthedocs.io/en/latest/migration.html

Please report problems or annoyance with with api to https://github.com/aio-libs/aiohttp

You can install and test this release with::

  pip install https://github.com/aio-libs/aiohttp/archive/2.0.0rc1.tar.gz#egg=aiohttp-2.0.0rc1


CHANGES
-------


`2.0.0rc1` (2017-03-14)
-----------------------

- Properly handle payload errors #1710

- Added `ClientWebSocketResponse.get_extra_info()` #1717

- It is not possible to combine Transfer-Encoding and chunked parameter,
  same for compress and Content-Encoding #1655

- Connector's `limit` parameter indicates total concurrent connections.
  New `limit_per_host` added, indicates total connections per endpoint. #1601

- Use url's `raw_host` for name resolution #1685

- Change `ClientResponse.url` to `yarl.URL` instance #1654

- Add max_size parameter to web.Request reading methods #1133

- Web Request.post() stores data in temp files #1469

- Add the `allow_head=True` keyword argument for `add_get` #1618

- `run_app` and the Command Line Interface now support serving over
  Unix domain sockets for faster inter-process communication.

- `run_app` now supports passing a preexisting socket object. This can be useful
  e.g. for socket-based activated applications, when binding of a socket is
  done by the parent process.

- Implementation for Trailer headers parser is broken #1619

- Fix FileResponse to not fall on bad request (range out of file size)

- Fix FileResponse to correct stream video to Chromes

- Deprecate public low-level api #1657

- Deprecate `encoding` parameter for ClientSession.request() method

- Dropped aiohttp.wsgi #1108

- Dropped `version` from ClientSession.request() method

- Dropped websocket version 76 support #1160

- Dropped: `aiohttp.protocol.HttpPrefixParser`  #1590

- Dropped: Servers response's `.started`, `.start()` and `.can_start()` method  #1591

- Dropped:  Adding `sub app` via `app.router.add_subapp()` is deprecated
  use `app.add_subapp()` instead #1592

- Dropped: `Application.finish()` and `Application.register_on_finish()`  #1602

- Dropped: `web.Request.GET` and `web.Request.POST`

- Dropped: aiohttp.get(), aiohttp.options(), aiohttp.head(),
  aiohttp.post(), aiohttp.put(), aiohttp.patch(), aiohttp.delete(), and
  aiohttp.ws_connect() #1593

- Dropped: `aiohttp.web.WebSocketResponse.receive_msg()` #1605

- Dropped: `ServerHttpProtocol.keep_alive_timeout` attribute and
  `keep-alive`, `keep_alive_on`, `timeout`, `log` constructor parameters #1606

- Dropped: `TCPConnector's`` `.resolve`, `.resolved_hosts`, `.clear_resolved_hosts()`
  attributes and `resolve` constructor  parameter #1607

- Dropped `ProxyConnector` #1609
