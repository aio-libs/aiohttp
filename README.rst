Async http client/server framework
==================================

.. image:: https://raw.githubusercontent.com/aio-libs/aiohttp/master/docs/_static/aiohttp-icon-128x128.png
  :height: 64px
  :width: 64px
  :alt: aiohttp logo

.. image:: https://travis-ci.org/aio-libs/aiohttp.svg?branch=master
  :target:  https://travis-ci.org/aio-libs/aiohttp
  :align: right

.. image:: https://codecov.io/gh/aio-libs/aiohttp/branch/master/graph/badge.svg
  :target: https://codecov.io/gh/aio-libs/aiohttp

.. image:: https://badge.fury.io/py/aiohttp.svg
    :target: https://badge.fury.io/py/aiohttp


aiohttp 2.0 release!
--------------------

For this release we completely refactored low-level implementation of http handling.
Finally `uvloop` gives performance improvement. Overall performance improvement
should be around 70-90% compared to 1.x version.

We took opportunity to refactor long standing api design problems across whole package.
Client exceptions handling has been cleaned up and now much more straight forward. Client payload
management simplified and allows to extend with any custom type. Client connection pool
implementation has been redesigned as well, now there is no need for actively releasing response objects,
aiohttp handles connection release automatically.

Another major change, we moved aiohttp development to public organization https://github.com/aio-libs

With this amount of api changes we had to make backward incompatible changes. Please check this migration document http://aiohttp.readthedocs.io/en/latest/migration.html

Please report problems or annoyance with with api to https://github.com/aio-libs/aiohttp


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
      with aiohttp.Timeout(10, loop=session.loop):
          async with session.get(url) as response:
              return await response.text()

  async def main(loop):
      async with aiohttp.ClientSession(loop=loop) as session:
          html = await fetch(session, 'http://python.org')
          print(html)

  if __name__ == '__main__':
      loop = asyncio.get_event_loop()
      loop.run_until_complete(main(loop))


Server
^^^^^^

This is simple usage example:

.. code-block:: python

    from aiohttp import web

    async def handle(request):
        name = request.match_info.get('name', "Anonymous")
        text = "Hello, " + name
        return web.Response(text=text)

    async def wshandler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        async for msg in ws:
            if msg.type == web.MsgType.text:
                await ws.send_str("Hello, {}".format(msg.data))
            elif msg.type == web.MsgType.binary:
                await ws.send_bytes(msg.data)
            elif msg.type == web.MsgType.close:
                break

        return ws


    app = web.Application()
    app.router.add_get('/echo', wshandler)
    app.router.add_get('/', handle)
    app.router.add_get('/{name}', handle)

    web.run_app(app)


Note: examples are written for Python 3.5+ and utilize PEP-492 aka
async/await.  If you are using Python 3.4 please replace ``await`` with
``yield from`` and ``async def`` with ``@coroutine`` e.g.::

    async def coro(...):
        ret = await f()

should be replaced by::

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

- Python >= 3.4.2
- async-timeout_
- chardet_
- multidict_
- yarl_

Optionally you may install the cChardet_ and aiodns_ libraries (highly
recommended for sake of speed).

.. _chardet: https://pypi.python.org/pypi/chardet
.. _aiodns: https://pypi.python.org/pypi/aiodns
.. _multidict: https://pypi.python.org/pypi/multidict
.. _yarl: https://pypi.python.org/pypi/yarl
.. _async-timeout: https://pypi.python.org/pypi/async_timeout
.. _cChardet: https://pypi.python.org/pypi/cchardet

License
-------

``aiohttp`` is offered under the Apache 2 license.


Keepsafe
--------

The aiohttp community would like to thank Keepsafe (https://www.getkeepsafe.com) for it's support in the early days of the project.


Source code
------------

The latest developer version is available in a github repository:
https://github.com/aio-libs/aiohttp

Benchmarks
----------

If you are interested in by efficiency, AsyncIO community maintains a
list of benchmarks on the official wiki:
https://github.com/python/asyncio/wiki/Benchmarks
