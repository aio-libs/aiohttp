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
third - handler.


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


Why the minimal supported version is Python 3.4.1
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
   2. ``/logout_user`` that when invoked needs to close all open websockets for that user.

Keep in mind that you can only all ``.close()`` on a websocket from the handler task, while you can
safely call ``.terminate()`` from different tasks.

The simplest way to perform it is keeping a shared registry of open websocket responses for a user
in the :class:`aiohttp.web.Application`, then in ``/logout_user`` handler cycle through all the websockets for
the user and ``terminate()`` them::

    async def echo_handler(request):

        ws = web.WebSocketResponse()
        user_id = authenticate_user(request)
        await ws.prepare(request)
        request.app['websockets'][user_id].add(ws)

        try:
            async for msg in ws:
                # handle incoming messages
                ...

        except asyncio.websocket.WebSocketTerminate:
            print('websocket terminated')
        finally:
            request.app['websockets'][user_id].remove(ws)
        await ws.close()
        return ws

    async def logout_handler(request):

        user_id = authenticate_user(request)

        for ws in request.app['websockets'][user_id]:
            ws.terminate()

        # return response
        ...

    def main():
        loop = asyncio.get_event_loop()
        app = aiohttp.web.Application(loop=loop)
        app.router.add_route('GET', '/echo', echo_handler)
        app.router.add_route('POST', '/logout', logout_handler)
        app['websockets'] = defaultdict(set)
        aiohttp.web.run_app(app, host='localhost', port=8080)
