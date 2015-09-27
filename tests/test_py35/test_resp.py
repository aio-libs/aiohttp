import pytest

import aiohttp
from aiohttp import web


@pytest.mark.run_loop
async def test_await(create_server, loop):

    async def handler(request):
        return web.HTTPOk()

    app, url = await create_server()
    app.router.add_route('GET', '/', handler)
    resp = await aiohttp.get(url+'/', loop=loop)
    assert resp.status == 200
    assert resp.connection is not None
    await resp.release()
    assert resp.connection is None


@pytest.mark.run_loop
async def test_response_context_manager(create_server, loop):

    async def handler(request):
        return web.HTTPOk()

    app, url = await create_server()
    app.router.add_route('GET', '/', handler)
    resp = await aiohttp.get(url+'/', loop=loop)
    async with resp:
        assert resp.status == 200
        assert resp.connection is not None
    assert resp.connection is None
