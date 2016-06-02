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

  async def fetch(session, url):
      with aiohttp.Timeout(10):
          async with session.get(url) as response:
              return await response.text()

  if __name__ == '__main__':
      loop = asyncio.get_event_loop()
      with aiohttp.ClientSession(loop=loop) as session:
          html = loop.run_until_complete(
              fetch(session, 'http://python.org'))
          print(html)


Server
^^^^^^

This is simple usage example:

.. code-block:: python

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


    app = web.Application()
    app.router.add_route('GET', '/echo', wshandler)
    app.router.add_route('GET', '/{name}', handle)

    web.run_app(app)


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

https://aiohttp.readthedocs.io/

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
