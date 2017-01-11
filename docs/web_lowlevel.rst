.. _aiohttp-web-lowlevel:

Low Level Server
================

.. currentmodule:: aiohttp.web


This topic describes :mod:`aiohttp.web` based *low level* API.

Abstract
--------

Sometimes user don't need high-level concepts introduced in
:ref:`aiohttp-web`: applications, routers, middlewares and signals.

All what is needed is supporting asynchronous callable which accepts a
request and returns a response object.

This is done by introducing :class:`aiohttp.web.Server` class which
serves a *protocol factory* role for
:meth:`asyncio.AbstractEventLoop.create_server` and bridges data
stream to *web handler* and sends result back.


Low level *web handler* should accept the single :class:`BaseRequest`
parameter and performs one of the following actions:

  1. Return a :class:`Response` with the whole HTTP body stored in memory.

  2. Create a :class:`StreamResponse`, send headers by
     :meth:`StreamResponse.prepare` call, send data chunks by
     :meth:`StreamResponse.write` / :meth:`StreamResponse.drain`,
     return finished response.

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


   async def main(loop):
       server = web.Server(handler)
       await loop.create_server(server, "127.0.0.1", 8080)
       print("======= Serving on http://127.0.0.1:8080/ ======")

       # pause here for very long time by serving HTTP requests and
       # waiting for keyboard interruption
       await asyncio.sleep(100*3600)


   loop = asyncio.get_event_loop()

   try:
       loop.run_until_complete(main(loop))
   except KeyboardInterrupt:
       pass
   loop.close()


In the snippet we have ``handler`` which returns a regular
:class:`Response` with ``"OK"`` in BODY.

This *handler* is processed by ``server`` (:class:`Server` which acts
as *protocol factory*).  Network communication is created by
``loop.create_server`` call to serve ``http://127.0.0.1:8080/``.

The handler should process every request: ``GET``, ``POST``,
Web-Socket for every *path*.

The example is very basic: it always return ``200 OK`` response, real
life code should be much more complex.


.. disqus::
  :title: aiohttp.web low-level server
