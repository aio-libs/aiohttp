import asyncio
from collections.abc import Coroutine

import pytest

import aiohttp
from aiohttp import web
from aiohttp.client import _RequestContextManager

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


async def test_context_manager_timeout_on_release(create_server, loop):

    async def handler(request):
        resp = web.StreamResponse()
        await resp.prepare(request)
        await asyncio.sleep(10, loop=loop)
        return resp

    app, url = await create_server()
    app.router.add_route('GET', '/', handler)

    with aiohttp.ClientSession(loop=loop) as session:
        resp = await session.get(url+'/')
        with pytest.raises(asyncio.TimeoutError):
            with aiohttp.Timeout(0.01, loop=loop):
                async with resp:
                    assert resp.status == 200
                    assert resp.connection is not None
        assert resp.connection is None


async def test_iter_any(create_server, loop):

    data = b'0123456789' * 1024

    async def handler(request):
        buf = []
        async for raw in request.content.iter_any():
            buf.append(raw)
        assert b''.join(buf) == data
        return web.Response()

    app, url = await create_server()
    app.router.add_route('POST', '/', handler)

    with aiohttp.ClientSession(loop=loop) as session:
        async with await session.post(url+'/', data=data) as resp:
            assert resp.status == 200
