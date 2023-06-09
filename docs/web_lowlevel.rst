.. currentmodule:: aiohttp.web

.. _aiohttp-web-lowlevel:

Low Level Server
================


This topic describes :mod:`aiohttp.web` based *low level* API.

Abstract
--------

Sometimes users don't need high-level concepts introduced in
:ref:`aiohttp-web`: applications, routers, middlewares and signals.

All that may be needed is supporting an asynchronous callable which accepts a
request and returns a response object.

This is done by introducing :class:`aiohttp.web.Server` class which
serves a *protocol factory* role for
:meth:`asyncio.loop.create_server` and bridges data
stream to *web handler* and sends result back.


Low level *web handler* should accept the single :class:`BaseRequest`
parameter and performs one of the following actions:

  1. Return a :class:`Response` with the whole HTTP body stored in memory.

  2. Create a :class:`StreamResponse`, send headers by
     :meth:`StreamResponse.prepare` call, send data chunks by
     :meth:`StreamResponse.write` and return finished response.

  3. Raise :class:`HTTPException` derived exception (see
     :ref:`aiohttp-web-exceptions` section).

     All other exceptions not derived from :class:`HTTPException`
     leads to *500 Internal Server Error* response.

  4. Initiate and process Web-Socket connection by
     :class:`WebSocketResponse` using (see :ref:`aiohttp-web-websockets`).


Run a Basic Low-Level Server
----------------------------

The following code demonstrates very trivial usage example::

   import asyncio
   from aiohttp import web


   async def handler(request):
       return web.Response(text="OK")


   async def main():
       server = web.Server(handler)
       runner = web.ServerRunner(server)
       await runner.setup()
       site = web.TCPSite(runner, 'localhost', 8080)
       await site.start()

       print("======= Serving on http://127.0.0.1:8080/ ======")

       # pause here for very long time by serving HTTP requests and
       # waiting for keyboard interruption
       await asyncio.sleep(100*3600)


   asyncio.run(main())


In the snippet we have ``handler`` which returns a regular
:class:`Response` with ``"OK"`` in BODY.

This *handler* is processed by ``server`` (:class:`Server` which acts
as *protocol factory*).  Network communication is created by
:ref:`runners API <aiohttp-web-app-runners-reference>` to serve
``http://127.0.0.1:8080/``.

The handler should process every request for every *path*, e.g.
``GET``, ``POST``, Web-Socket.

The example is very basic: it always return ``200 OK`` response, real
life code is much more complex usually.
