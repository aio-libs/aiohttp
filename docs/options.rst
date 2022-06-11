Run a Basic Server With options
----------------------------

The following code demonstrates very trivial usage example::
hello.py::

    from aiohttp import web
    from aiohttp.options import options
    async def hello(request):
        return web.Response(text=f"name={options.name}")

server.py::

    from aiohttp import web
    from aiohttp.options import define
    define(name="name", default="aiohttp", type=str)
    app = web.Application()
    app.add_routes([web.get('/', hello)])
    web.run_app(app)

