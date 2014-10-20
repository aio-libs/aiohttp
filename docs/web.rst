.. _web:

.. highlight:: python

High-level HTTP Server
======================

.. module:: aiohttp.web

.. versionadded:: 0.10

Run a simple web server
-----------------------

For implementing web server at first create :ref:`request handler<web-handler>`.

Handler is a :ref:`coroutine<coroutine>` or regular function that
accepts only *request* parameter of type :class:`Request`
and returns *response* instance::

   import asyncio
   from aiohttp import web

   @asyncio.coroutine
   def hello(request):
       return web.Response(request, b"Hello, world")

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

.. _web-handler:

Handler
-------

Handler is an any *callable* that accepts single :class:`Request`
argument and returns :class:`StreamResponse` or :class:`Response`
instance.

Handler **can** be a :ref:`coroutine<coroutine>`, :mod:`aiohttp.web` will
**unyield** returned result by applying ``yield from`` to handler.

Handlers can be first-class functions like::

   @asyncio.coroutine
   def hello(request):
       return web.Response(request, b"Hello, world")

   app.router.add_route('GET', '/', hello)

Sometimes you would like to group logically coupled handlers into python class.

:mod:`aiohttp.web` doesn't dictate any implementation details on that
class: library user is responsible for instantiating and
connecting routes::

   class Handler:

       def __init__(self):
           pass

       def handle_intro(self, request):
           return web.Response(request, b"Hello, world")

       @asyncio.coroutine
       def handle_greeting(self, request):
           name = request.match_info.matchdict.get('name')
           txt = "Hello, {}".format(name)
           return web.Response(request, txt.encode('utf-8')

   handler = Handler()
   app.router.add_route('GET', '/intro', handler.handle_intro)
   app.router.add_route('GET', '/greet/{name}', handler.handle_greeting)


.. _web-request:


Request
-------

Request object contains all information about incoming HTTP request.

Every :ref:`handler<web-handler>` accepts request instance as first
positional parameter.

.. note::

   You should never create :class:`Request` instance by hands --
   :mod:`aiohttp.web` does it for you.

.. class:: Request

   .. attribute:: method

      *HTTP method*, read only property.

      The value is upper-cased :class:`str` like ``"GET"``,
      ``"POST"``, ``"PUT"`` etc.

   .. attribute:: version

      *HTTP version* of request, read only property.

      Returns :class:`aiohttp.protocol.HttpVersion` instance.

   .. attribute:: host

      *HOST* header of request, read only property.

      Returns :class:`str` or ``None`` if HTTP request has no *HOST* header.

   .. attribute:: path_qs

      The URL including PATH_INFO and the query string. e.g, ``/app/blog?id=10``

      Read only :class:`str` property.

   .. attribute:: path

      The URL including *PATH INFO* without the host or scheme. e.g.,
      ``/app/blog``

      Read only :class:`str` property.

   .. attribute:: query_string

      The query string in the URL, e.g., ``id=10``

      Read only :class:`str` property.

   .. attribute:: GET

      A multidict with all the variables in the query string.

      Read only :class:`~aiohttp.multidict.MultiDict` lazy property.

   .. attribute:: headers

      A case-insensitive multidict with all headers.

      Read only :class:`~aiohttp.multidict.CaseInsensitiveMultiDict`
      lazy property.

   .. attribute:: keep_alive

      ``True`` if keep-alive connection enabled by HTTP client and
      protocol version supports it, otherwise ``False``.

      Read only :class:`bool` property.

   .. attribute:: match_info

      Read only property with :class:`~aiohttp.abc.AbstractMatchInfo`
      instance for result of route resolving.

      .. note::

         Exact type of property depends on used router.  If
         ``app.router`` is :class:`UrlDispatcher` the property contains is
         :class:`UrlMappingMatchInfo` instance.

   .. attribute:: app

      :class:`Application` instance used to call :ref:`request handler
      <web-handler>`.


Content Type
------------

Content-Type header is case-insensitive by :rfc:`2045`, BTW.
