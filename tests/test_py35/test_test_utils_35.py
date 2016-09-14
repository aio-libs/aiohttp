import pytest

import aiohttp
from aiohttp import web
from aiohttp.test_utils import TestClient as _TestClient
from aiohttp.test_utils import TestServer as _TestServer


@pytest.fixture
def app(loop):
    async def handler(request):
        return web.Response(body=b"OK")

    app = web.Application(loop=loop)
    app.router.add_route('*', '/', handler)
    return app


async def test_server_context_manager(app, loop):
    async with _TestServer(app) as server:
        async with aiohttp.ClientSession(loop=loop) as client:
            async with client.head(server.make_url('/')) as resp:
                assert resp.status == 200


async def test_client_context_manager(app, loop):
    async with _TestClient(app) as client:
        resp = await client.head('/')
        assert resp.status == 200
