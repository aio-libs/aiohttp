.. _web:

.. highlight:: python

High-level HTTP Server
======================

.. module:: aiohttp.web

Run a simple web server
-----------------------

For implementing web server at first create request handler.

Handler is a :ref:`coroutine<coroutine>` or regular function that
accepts only *request* parameter of type :class:`aiohttp.web.Request`
and returns *response* instance::

   import asyncio
   from aiohttp import web

   @asyncio.coroutine
   def hello(request):
       return web.Response("Hello, world")

Next you have to create *application* and register *handler* in
application's router pointing *HTTP method*, *path* and *handler*::

   app = web.Application()
   app.router.add_route('GET', '/', hello)

After that create server and run *asyncio loop* as usual::

   loop = asyncio.get_event_loop()
   f = loop.create_server(app.make_handler, '0.0.0.0', '8080')
   srv = loop.run_until_complete(f)
   print('serving on', srv.sockets[0].getsockname())
   try:
       loop.run_forever()
   except KeyboardInterrupt:
       pass

That's it.


Content Type
------------

Content-Type header is case-insensitive by :rfc:`2045`, BTW.
