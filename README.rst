http client/server for asyncio
==============================

.. image:: https://raw.github.com/KeepSafe/aiohttp/master/docs/_static/aiohttp-icon-128x128.png
  :height: 64px
  :width: 64px
  :alt: aiohttp logo

.. image:: https://secure.travis-ci.org/KeepSafe/aiohttp.png
  :target:  https://secure.travis-ci.org/KeepSafe/aiohttp
  :align: right

Features
--------

- Supports both client and server side of HTTP protocol.
- Supports Web-Sockets out-of-the-box.
- Web-server has middlewares and pluggable routing.


Requirements
------------

- Python >= 3.3
- asyncio https://pypi.python.org/pypi/asyncio


License
-------

``aiohttp`` is offered under the Apache 2 license.


Documentation
-------------

http://aiohttp.readthedocs.org/

Source code
------------

The latest developer version is available in a github repository:
https://github.com/KeepSafe/aiohttp


Getting started
---------------

Client
^^^^^^

To retrieve something from the web::

  import aiohttp

  def get_body(url):
      response = yield from aiohttp.request('GET', url)
      return (yield from response.read())

You can use the get command like this anywhere in your ``asyncio``
powered program::

  response = yield from aiohttp.request('GET', 'http://python.org')
  body = yield from response.read()
  print(body)

If you want to use timeouts for aiohttp client side please use standard
asyncio approach::

   yield from asyncio.wait_for(request('GET', url), 10)

Server
^^^^^^

In aiohttp 0.12 we've added highlevel API for web HTTP server.

There is simple usage example::

    import asyncio
    from aiohttp import web


    @asyncio.coroutine
    def handle(request):
        name = request.match_info.get('name', "Anonymous")
        text = "Hello, " + name
        return web.Response(body=text.encode('utf-8'))


    @asyncio.coroutine
    def init(loop):
        app = web.Application(loop=loop)
        app.router.add_route('GET', '/{name}', handle)

        srv = yield from loop.create_server(app.make_handler(),
                                            '127.0.0.1', 8080)
        print("Server started at http://127.0.0.1:8080")
        return srv

    loop = asyncio.get_event_loop()
    loop.run_until_complete(init(loop))
    loop.run_forever()
