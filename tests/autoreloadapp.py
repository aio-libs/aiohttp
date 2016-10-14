import sys
import asyncio

from aiohttp import web


@asyncio.coroutine
def handler(request):
    sys.path.append('.')
    import watchfile
    watchfile.a
    return web.Response(body=watchfile.a)

if __name__ == '__main__':
    app = web.Application()
    app.router.add_route('GET', '/', handler)
    web.run_app(app, host=sys.argv[1], port=int(sys.argv[2]), autoreload=True) 
