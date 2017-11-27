FAQ
===

.. contents::
   :local:

Are there any plans for @app.route decorator like in Flask?
-----------------------------------------------------------

We have it already (*aiohttp>=2.3* required):
:ref:`aiohttp-web-alternative-routes-definition`.

The difference is: ``@app.route`` should have an ``app`` in module
global namespace, which makes *circular import hell* easy.

*aiohttp* provides a :class:`~aiohttp.web.RouteTableDef` decoupled
 from an application instance::

   routes = web.RouteTableDef()

   @routes.get('/get')
   async def handle_get(request):
       ...


   @routes.post('/post')
   async def handle_post(request):
       ...

   app.router.add_routes(routes)


Has aiohttp the Flask Blueprint or Django App concept?
------------------------------------------------------

If you're planing to write big applications, maybe you must consider
use nested applications. They acts as a Flask Blueprint or like the
Django application concept.

Using nested application you can add sub-applications to the main application.

see: :ref:`aiohttp-web-nested-applications`.


How to create route that catches urls with given prefix?
---------------------------------------------------------
Try something like::

    app.router.add_route('*', '/path/to/{tail:.+}', sink_handler)

Where first argument, star, means catch any possible method
(*GET, POST, OPTIONS*, etc), second matching ``url`` with desired prefix,
third -- handler.


Where to put my database connection so handlers can access it?
--------------------------------------------------------------

:class:`aiohttp.web.Application` object supports :class:`dict`
interface, and right place to store your database connections or any
other resource you want to share between handlers. Take a look on
following example::

    async def go(request):
        db = request.app['db']
        cursor = await db.cursor()
        await cursor.execute('SELECT 42')
        # ...
        return web.Response(status=200, text='ok')


    async def init_app(loop):
        app = Application(loop=loop)
        db = await create_connection(user='user', password='123')
        app['db'] = db
        app.router.add_get('/', go)
        return app


Why the minimal supported version is Python 3.4.2
--------------------------------------------------

As of aiohttp **v0.18.0** we dropped support for Python 3.3 up to
3.4.1.  The main reason for that is the :meth:`object.__del__` method,
which is fully working since Python 3.4.1 and we need it for proper
resource closing.

The last Python 3.3, 3.4.0 compatible version of aiohttp is
**v0.17.4**.

This should not be an issue for most aiohttp users (for example `Ubuntu`
14.04.3 LTS provides python upgraded to 3.4.3), however libraries
depending on aiohttp should consider this and either freeze aiohttp
version or drop Python 3.3 support as well.

As of aiohttp **v1.0.0** we dropped support for Python 3.4.1 up to
3.4.2+ also. The reason is: `loop.is_closed` appears in 3.4.2+

Again, it should be not an issue at 2016 Summer because all major
distributions are switched to Python 3.5 now.


How a middleware may store a data for using by web-handler later?
-----------------------------------------------------------------

:class:`aiohttp.web.Request` supports :class:`dict` interface as well
as :class:`aiohttp.web.Application`.

Just put data inside *request*::

   async def handler(request):
       request['unique_key'] = data

See https://github.com/aio-libs/aiohttp_session code for inspiration,
``aiohttp_session.get_session(request)`` method uses ``SESSION_KEY``
for saving request specific session info.


.. _aiohttp_faq_parallel_event_sources:

How to receive an incoming events from different sources in parallel?
---------------------------------------------------------------------

For example we have two event sources:

   1. WebSocket for event from end user

   2. Redis PubSub from receiving events from other parts of app for
      sending them to user via websocket.

The most native way to perform it is creation of separate task for
pubsub handling.

Parallel :meth:`aiohttp.web.WebSocketResponse.receive` calls are forbidden, only
the single task should perform websocket reading.

But other tasks may use the same websocket object for sending data to
peer::

    async def handler(request):

        ws = web.WebSocketResponse()
        await ws.prepare(request)
        task = request.app.loop.create_task(
            read_subscription(ws,
                              request.app['redis']))
        try:
            async for msg in ws:
                # handle incoming messages
                # use ws.send_str() to send data back
                ...

        finally:
            task.cancel()

    async def read_subscription(ws, redis):
        channel, = await redis.subscribe('channel:1')

        try:
            async for msg in channel.iter():
                answer = process message(msg)
                ws.send_str(answer)
        finally:
            await redis.unsubscribe('channel:1')


.. _aiohttp_faq_terminating_websockets:

How to programmatically close websocket server-side?
----------------------------------------------------


For example we have an application with two endpoints:


   1. ``/echo`` a websocket echo server that authenticates the user somehow
   2. ``/logout_user`` that when invoked needs to close all open
      websockets for that user.

One simple solution is keeping a shared registry of websocket responses
for a user in the :class:`aiohttp.web.Application` instance and
call :meth:`aiohttp.web.WebSocketResponse.close` on all of them in ``/logout_user`` handler::

    async def echo_handler(request):

        ws = web.WebSocketResponse()
        user_id = authenticate_user(request)
        await ws.prepare(request)
        request.app['websockets'][user_id].add(ws)
        try:
            async for msg in ws:
                ws.send_str(msg.data)
        finally:
            request.app['websockets'][user_id].remove(ws)

        return ws


    async def logout_handler(request):

        user_id = authenticate_user(request)

        ws_closers = [ws.close() for ws in request.app['websockets'][user_id] if not ws.closed]

        # Watch out, this will keep us from returing the response until all are closed
        ws_closers and await asyncio.gather(*ws_closers)

        return web.Response(text='OK')


    def main():
        loop = asyncio.get_event_loop()
        app = web.Application(loop=loop)
        app.router.add_route('GET', '/echo', echo_handler)
        app.router.add_route('POST', '/logout', logout_handler)
        app['websockets'] = defaultdict(set)
        web.run_app(app, host='localhost', port=8080)


How to make request from a specific IP address?
-----------------------------------------------

If your system has several IP interfaces you may choose one which will
be used used to bind socket locally::

    conn = aiohttp.TCPConnector(local_addr=('127.0.0.1', 0), loop=loop)
    async with aiohttp.ClientSession(connector=conn) as session:
        ...

.. seealso:: :class:`aiohttp.TCPConnector` and ``local_addr`` parameter.


.. _aiohttp_faq_tests_and_implicit_loop:


How to use aiohttp test features with code which works with implicit loop?
--------------------------------------------------------------------------

Passing explicit loop everywhere is the recommended way.  But
sometimes, in case you have many nested non well-written services,
this is impossible.

There is a technique based on monkey-patching your low level service
that depends on aioes, to inject the loop at that level. This way, you
just need your ``AioESService`` with the loop in its signature. An
example would be the following::

  import pytest

  from unittest.mock import patch, MagicMock

  from main import AioESService, create_app

  class TestAcceptance:

      async def test_get(self, test_client, loop):
          with patch("main.AioESService", MagicMock(
                  side_effect=lambda *args, **kwargs: AioESService(*args,
                                                                   **kwargs,
                                                                   loop=loop))):
              client = await test_client(create_app)
              resp = await client.get("/")
              assert resp.status == 200

Note how we are patching the ``AioESService`` with and instance of itself but
adding the explicit loop as an extra (you need to load the loop fixture in your
test signature).

The final code to test all this (you will need a local instance of
elasticsearch running)::

  import asyncio

  from aioes import Elasticsearch
  from aiohttp import web


  class AioESService:

      def __init__(self, loop=None):
          self.es = Elasticsearch(["127.0.0.1:9200"], loop=loop)

      async def get_info(self):
          return await self.es.info()


  class MyService:

      def __init__(self):
          self.aioes_service = AioESService()

      async def get_es_info(self):
          return await self.aioes_service.get_info()


  async def hello_aioes(request):
      my_service = MyService()
      cluster_info = await my_service.get_es_info()
      return web.Response(text="{}".format(cluster_info))


  def create_app(loop=None):

      app = web.Application(loop=loop)
      app.router.add_route('GET', '/', hello_aioes)
      return app


  if __name__ == "__main__":
      web.run_app(create_app())


And the full tests file::


  from unittest.mock import patch, MagicMock

  from main import AioESService, create_app


  class TestAioESService:

      async def test_get_info(self, loop):
          cluster_info = await AioESService("random_arg", loop=loop).get_info()
          assert isinstance(cluster_info, dict)


  class TestAcceptance:

      async def test_get(self, test_client, loop):
          with patch("main.AioESService", MagicMock(
                  side_effect=lambda *args, **kwargs: AioESService(*args,
                                                                   **kwargs,
                                                                   loop=loop))):
              client = await test_client(create_app)
              resp = await client.get("/")
              assert resp.status == 200

Note how we are using the ``side_effect`` feature for injecting the loop to the
``AioESService.__init__`` call. The use of ``**args, **kwargs`` is mandatory
in order to propagate the arguments being used by the caller.


API stability and deprecation policy
------------------------------------

aiohttp tries to not break existing users code.

Obsolete attributes and methods are marked as *deprecated* in
documentation and raises :class:`DeprecationWarning` on usage.

Deprecation period is usually a year and half.

After the period is passed out deprecated code is be removed.

Unfortunately we should break own rules if new functionality or bug
fixing forces us to do it (for example proper cookies support on
client side forced us to break backward compatibility twice).

All *backward incompatible* changes are explicitly marked in
:ref:`CHANGES <aiohttp_changes>` chapter.


How to enable gzip compression globally for the whole application?
------------------------------------------------------------------

It's impossible. Choosing what to compress and where don't apply such
time consuming operation is very tricky matter.

If you need global compression -- write own custom middleware. Or
enable compression in NGINX (you are deploying aiohttp behind reverse
proxy, is not it).


How to manage ClientSession inside web server?
----------------------------------------------

:class:`aiohttp.ClientSession` should be created once for the lifetime
of the server in order to benefit from connection pooling.

Session saves cookies internally. If you don't need cookies processing
use :class:`aiohttp.DummyCookieJar`. If you need separate cookies
for different http calls but process them in logical chains use single
:class:`aiohttp.TCPConnector` with separate
client session and ``own_connector=False``.


How to access db connection stored in app from subapplication?
--------------------------------------------------------------

Restricting access from subapplication to main (or outer) app is the
deliberate choice.

Subapplication is an isolated unit by design. If you need to share
database object please do it explicitly::

   subapp['db'] = mainapp['db']
   mainapp.add_subapp('/prefix', subapp)
