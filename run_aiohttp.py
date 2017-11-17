import asyncio

import ujson
from aiohttp import web


async def index(request):
    data = {'message': 'hello world'}
    body = ujson.dumps(data)
    return web.Response(body=body.encode(), content_type='application/json')


# import tokio
# asyncio.set_event_loop_policy(tokio.TokioLoopPolicy())

import uvloop
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

app = web.Application()
# app.on_startup.append(startup)
# app.on_cleanup.append(cleanup)
app.router.add_get('/', index)
# app.router.add_get('/db', db)

# web.run_app(app, port=8000)
web.run_app(app, port=8000, access_log=None)
