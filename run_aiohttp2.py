import asyncio
from aiohttp import web

async def hello(request):
    return web.Response(body=b"Hello, world")

app = web.Application()
app.router.add_route('GET', '/', hello)

if __name__ == '__main__':
    web.run_app(app)
