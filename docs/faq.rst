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


How to create route that catches urls with givevn prefix?
---------------------------------------------------------
Try something like::

    app.router.add_route('*', '/path/to/{tail:.+}', sink_handler)

Where first argument, star, means catch any possible method
(*GET, POST, OPTIONS*, etc), second matching ``url`` with desired prefix,
third - handler.


Where to put my database connection so handlers can access it?
--------------------------------------------------------------

``Application`` object supports ``dict`` interface, and right place to store
your database connections or any other resource you want to share between
handlers. Take a look on following example::

    async def go(request):
        db = request.app['db']
        cursor = await db.cursor()
        await cursor.execute('SELECT 42')
        # ...
        return web.Response(status=200, text='ok')


    async def init_app(loop):
        app = Application(loop=loop)
        db = await crate_connection(user='user', password='123')
        app['db'] = db
        app.router.add_route('GET', '/', go)
        return app
