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
    await resp.release()
