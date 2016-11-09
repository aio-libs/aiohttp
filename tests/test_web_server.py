import asyncio

from aiohttp import web


@asyncio.coroutine
def test_simple_server(raw_test_server, test_client):
    @asyncio.coroutine
    def handler(request):
        return web.Response(text=str(request.rel_url))

    server = yield from raw_test_server(handler)
    client = yield from test_client(server)
    resp = yield from client.get('/path/to')
    assert resp.status == 200
    txt = yield from resp.text()
    assert txt == '/path/to'
