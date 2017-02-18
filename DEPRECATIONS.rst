Deprecations
^^^^^^^^^^^^

python 3.4
----------

Waiting until major linux distributions drop python 3.4 support. Estimation fall of 2017.

  * drop aiohttp/backport_cookies.py module with python3.4 support as well.
    import SimpleCookie directly from http.cookies package

Date: 01/01/2018


WebSocket send_xx method as coroutines
--------------------------------------

WebSocket writer's methods `send_str`, `send_bytes`, `send_json` are normal methods and return
drain coroutine. Convert this methods to coroutines, so we can enable drain functionality
automatically.


Date: 01/01/2018


aiohttp.MsgType
---------------

aiohttp.MsgType is deprecated in favor to aiohttp.WSMsgType, deprecated since 1.0


Date: 07/01/2018 ?
