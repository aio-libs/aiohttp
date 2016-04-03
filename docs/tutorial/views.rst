.. _tutorial-views:

Views
=====

Let's start from first views. Open polls/aiohttpdemo_polls/views.py and put
next Python code inside file: ::

    $ cat polls/aiohttpdemo_polls/views.py

    from aiohttp import web


    class SiteHandler:
        async def index(self, request):
            return web.Response(text='Hello Aiohttp!')

This is the simplest view possible in Aiohttp. Now we should add `index` view
to `routes.py`: ::

    $ cat polls/aiohttpdemo_polls/routes.py

    def setup_routes(app, handler, project_root):
        add_route = app.router.add_route
        add_route('GET', '/', handler.index)

Now if we open browser we can see: ::

    $ curl -X GET localhost:8080
    Hello Aiohttp!
