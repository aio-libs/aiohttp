Frequently Asked Questions
==========================
.. contents::
   :local:

Are there any plans for @app.route decorator like in Flask?
-----------------------------------------------------------
There are couple issues here:

* This adds huge problem name "configuration as side effect of importing".
* Route matching is order specific, it is very hard to maintain import order.
* In semi large application better to have routes table defined in one place.

For this reason feature will not be implemented. But if you really want to
use decorators just derive from web.Application and add desired method.


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

This should not be an issue for most aiohttp users (for example Ubuntu
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

    async def read_subscriptions(ws, redis):
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

Keep in mind that you can only ``.close()`` a websocket from inside
the handler task, and since the handler task is busy reading from the
websocket, it can't react to other events.

One simple solution is keeping a shared registry of websocket handler
tasks for a user in the :class:`aiohttp.web.Application` instance and
``cancel()`` them in ``/logout_user`` handler::

    async def echo_handler(request):

        ws = web.WebSocketResponse()
        user_id = authenticate_user(request)
        await ws.prepare(request)
        request.app['handlers'][user_id].add(asyncio.Task.current_task())

        try:
            async for msg in ws:
                # handle incoming messages
                ...

        except asyncio.CancelledError:
            print('websocket cancelled')
        finally:
            request.app['handlers'][user_id].remove(asyncio.Task.current_task())
        await ws.close()
        return ws

    async def logout_handler(request):

        user_id = authenticate_user(request)

        for task in request.app['handlers'][user_id]:
            task.cancel()

        # return response
        ...

    def main():
        loop = asyncio.get_event_loop()
        app = aiohttp.web.Application(loop=loop)
        app.router.add_route('GET', '/echo', echo_handler)
        app.router.add_route('POST', '/logout', logout_handler)
        app['websockets'] = defaultdict(set)
        aiohttp.web.run_app(app, host='localhost', port=8080)


How to make request from a specific IP address?
-----------------------------------------------

If your system has several IP interfaces you may choose one which will
be used used to bind socket locally::

    conn = aiohttp.TCPConnector(local_addr=('127.0.0.1, 0), loop=loop)
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
                  side_effect=lambda *args, **kwargs: AioESService(*args, **kwargs, loop=loop))):
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
                  side_effect=lambda *args, **kwargs: AioESService(*args, **kwargs, loop=loop))):
              client = await test_client(create_app)
              resp = await client.get("/")
              assert resp.status == 200

Note how we are using the ``side_effect`` feature for injecting the loop to the
``AioESService.__init__`` call. The use of ``**args, **kwargs`` is mandatory
in order to propagate the arguments being used by the caller.

.. disqus::
  :title: aiohttp FAQ
