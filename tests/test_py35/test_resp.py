import pytest

import aiohttp
from aiohttp import web
from aiohttp.client import _RequestContextManager
from collections.abc import Coroutine


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


@pytest.mark.run_loop
async def test_client_api_context_manager(create_server, loop):

    async def handler(request):
        return web.HTTPOk()

    app, url = await create_server()
    app.router.add_route('GET', '/', handler)

    async with aiohttp.get(url+'/', loop=loop) as resp:
        assert resp.status == 200
        assert resp.connection is not None
    assert resp.connection is None


def test_ctx_manager_is_coroutine():
    assert issubclass(_RequestContextManager, Coroutine)
