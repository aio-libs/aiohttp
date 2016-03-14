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
        app.router.add_route('GET', '/', go)
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
