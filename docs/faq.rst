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


Why the minimal supported version is Python 3.5.3?
--------------------------------------------------

Python 3.5.2 has fixed protocol for async iterators: ``__aiter()__`` is
not a coroutine but regular function.

Python 3.5.3 is even more important: :func:`asyncio.get_event_loop`
returns the running loop instance if called from a coroutine
(previously was returning a *default* one, set by
:func:`asyncio.set_event_loop`.

The change is very crucial, in Python < 3.5.3
:func:`asyncio.get_event_loop` was not reliable, thus user *was
forced* to pass the event loop instance explicitly everywhere.

Otherwise if a future object was created for using one event loop
(e.g. default) but a coroutine was run by other loop -- the coroutine
was never awaited, task was *hung*.

Keep in mind that every ``await`` expression internally either passed
instantly or paused by waiting for a future.

It's extremely important that all tasks (coroutine runners) and
futures are using the same event loop.


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

As of aiohttp 3.0 all response objects are *dict-like* structures as
well.


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

One simple solution is keeping a shared registry of websocket
responses for a user in the :class:`aiohttp.web.Application` instance
and call :meth:`aiohttp.web.WebSocketResponse.close` on all of them in
``/logout_user`` handler::

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

        ws_closers = [ws.close()
                      for ws in request.app['websockets'][user_id]
                      if not ws.closed]

        # Watch out, this will keep us from returing the response
        # until all are closed
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


API stability and deprecation policy
------------------------------------

*aiohttp* follows strong [SemVer](https://semver.org/) schema.

Obsolete attributes and methods are marked as *deprecated* in
documentation and raises :class:`DeprecationWarning` on usage.

Let's assume now we have aiohttp ``X.Y.Z`` where ``X`` is *major* version,
``Y`` is minor version and ``Z`` is bugfix number.

E.g. now the latest released version is ``aiohttp==3.0.6``.

``3.0.7`` fixes some bugs but have no new features.

``3.1.0`` introduces new features and can deprecate some API but never
remove it, also all bug fixes from previous release are merged.

``4.0.0`` removes all deprecations collected from ``3.Y`` versions
**except** deprecations from the **last** ``3.Y`` release. These
deprecations will be removed by ``5.0.0``.

Unfortunately we have break the rules in case of found **security
vulnerability**.

If a security problem cannot be fixed without breaking backward
compatibility -- a bugfix release may do it. The probability for this
is very low but shit happens, sorry.

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
