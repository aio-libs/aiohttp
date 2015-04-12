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
- Supports both client and server Web-Sockets out-of-the-box.
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

To retrieve something from the web:

.. code-block:: python

  import aiohttp
  import asyncio

  def get_body(url):
      response = yield from aiohttp.request('GET', url)
      return (yield from response.read())

  if __name__ == '__main__':
      loop = asyncio.get_event_loop()
      raw_html = loop.run_until_complete(get_body('http://python.org'))
      print(raw_html)


You can use the get command like this anywhere in your ``asyncio``
powered program:

.. code-block:: python

  response = yield from aiohttp.request('GET', 'http://python.org')
  body = yield from response.read()
  print(body)

If you want to use timeouts for aiohttp client side please use standard
asyncio approach:

.. code-block:: python

   yield from asyncio.wait_for(request('GET', url), 10)


Server
^^^^^^

In aiohttp 0.12 we've added highlevel API for web HTTP server.

This is simple usage example:

.. code-block:: python

    import asyncio
    from aiohttp import web


    @asyncio.coroutine
    def handle(request):
        name = request.match_info.get('name', "Anonymous")
        text = "Hello, " + name
        return web.Response(body=text.encode('utf-8'))


    @asyncio.coroutine
    def wshandler(request):
        ws = web.WebSocketResponse()
        ws.start(request)

        while True:
            msg = yield from ws.receive()

            if msg.tp == web.MsgType.text:
                ws.send_str("Hello, {}".format(msg.data))
            elif msg.tp == web.MsgType.binary:
                ws.send_bytes(msg.data)
            elif msg.tp == web.MsgType.close:
                break

        return ws


    @asyncio.coroutine
    def init(loop):
        app = web.Application(loop=loop)
        app.router.add_route('GET', '/echo', wshandler)
        app.router.add_route('GET', '/{name}', handle)

        srv = yield from loop.create_server(app.make_handler(), '127.0.0.1', 8080)
        print("Server started at http://127.0.0.1:8080")
        return srv

    loop = asyncio.get_event_loop()
    loop.run_until_complete(init(loop))
    loop.run_forever()
