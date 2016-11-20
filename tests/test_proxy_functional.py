import asyncio

from aiohttp import web


@asyncio.coroutine
def test_proxy_via_mitmdump(loop, test_client, fake_proxy):
    @asyncio.coroutine
    def handler(request):
        return web.Response(text=request.method)

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)

    client = yield from test_client(app)
    resp = yield from client.get('/', proxy=fake_proxy.url())
    assert 200 == resp.status
    assert 'X-Mitmdump' in resp.headers
    assert resp.headers['X-Mitmdump'] == '1'
    resp.close()
