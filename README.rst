http client/server for asyncio
==============================

.. image:: https://raw.github.com/KeepSafe/aiohttp/master/docs/_static/aiohttp-icon-128x128.png
  :height: 64px
  :width: 64px
  :alt: aiohttp logo

.. image:: https://travis-ci.org/KeepSafe/aiohttp.svg?branch=master
  :target:  https://travis-ci.org/KeepSafe/aiohttp
  :align: right

.. image:: https://coveralls.io/repos/KeepSafe/aiohttp/badge.svg?branch=master&service=github
  :target:  https://coveralls.io/github/KeepSafe/aiohttp?branch=master
  :align: right

.. image:: https://badge.fury.io/py/aiohttp.svg
    :target: https://badge.fury.io/py/aiohttp

Features
--------

- Supports both client and server side of HTTP protocol.
- Supports both client and server Web-Sockets out-of-the-box.
- Web-server has middlewares and pluggable routing.


Getting started
---------------

Client
^^^^^^

To retrieve something from the web:

.. code-block:: python

  import aiohttp
  import asyncio

  async def get_body(client, url):
      async with client.get(url) as response:
          return await response.read()

  if __name__ == '__main__':
      loop = asyncio.get_event_loop()
      client = aiohttp.ClientSession(loop=loop)
      raw_html = loop.run_until_complete(get_body(client, 'http://python.org'))
      print(raw_html)
      client.close()


If you want to use timeouts for aiohttp client please use standard
asyncio approach:

.. code-block:: python

   yield from asyncio.wait_for(client.get(url), 10)


Server
^^^^^^

This is simple usage example:

.. code-block:: python

    import asyncio
    from aiohttp import web

    async def handle(request):
        name = request.match_info.get('name', "Anonymous")
        text = "Hello, " + name
        return web.Response(body=text.encode('utf-8'))

    async def wshandler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        async for msg in ws:
            if msg.tp == web.MsgType.text:
                ws.send_str("Hello, {}".format(msg.data))
            elif msg.tp == web.MsgType.binary:
                ws.send_bytes(msg.data)
            elif msg.tp == web.MsgType.close:
                break

        return ws


    async def init(loop):
        app = web.Application(loop=loop)
        app.router.add_route('GET', '/echo', wshandler)
        app.router.add_route('GET', '/{name}', handle)

        srv = await loop.create_server(app.make_handler(),
                                            '127.0.0.1', 8080)
        print("Server started at http://127.0.0.1:8080")
        return srv

    loop = asyncio.get_event_loop()
    loop.run_until_complete(init(loop))
    loop.run_forever()


Note: examples are written for Python 3.5+ and utilize PEP-492 aka
async/await.  If you are using Python 3.4 please replace ``await`` with
``yield from`` and ``async def`` with ``@coroutine`` e.g.::

    async def coro(...):
        ret = await f()

shoud be replaced by::

    @asyncio.coroutine
    def coro(...):
        ret = yield from f()

Documentation
-------------

http://aiohttp.readthedocs.org/

Discussion list
---------------

*aio-libs* google group: https://groups.google.com/forum/#!forum/aio-libs

Requirements
------------

- Python >= 3.4.1
- chardet https://pypi.python.org/pypi/chardet

Optionally you may install cChardet library:
https://pypi.python.org/pypi/cchardet/1.0.0


License
-------

``aiohttp`` is offered under the Apache 2 license.


Source code
------------

The latest developer version is available in a github repository:
https://github.com/KeepSafe/aiohttp

Benchmarks
----------

If you are interested in by efficiency, AsyncIO community maintains a
list of benchmarks on the official wiki:
https://github.com/python/asyncio/wiki/Benchmarks
