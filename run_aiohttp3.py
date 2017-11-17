import asyncio
from aiohttp import web

import uvloop
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())


async def hello(request):
    return web.Response(body=b"Hello, world")

app = web.Application()
app.router.add_route('GET', '/', hello)

if __name__ == '__main__':
    web.run_app(app)
