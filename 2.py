from aiohttp import web

async def handle(request):
    return web.Response(text='<h1>testing</h1>', content_type='text/html')

app = web.Application()
app.router.add_get('/', handle)


if __name__ == '__main__':
    web.run_app(app, port=8001)
