import asyncio
from collections.abc import Coroutine

import pytest

import aiohttp
from aiohttp import web
from aiohttp.client import _RequestContextManager

async def test_await(test_server, loop):

    async def handler(request):
        return web.HTTPOk()

    app = web.Application(loop=loop)
    app.router.add_route('GET', '/', handler)
    server = await test_server(app)
    resp = await aiohttp.get(server.make_url('/'), loop=loop)
    assert resp.status == 200
    assert resp.connection is not None
    await resp.release()
    assert resp.connection is None


async def test_response_context_manager(test_server, loop):

    async def handler(request):
        return web.HTTPOk()

    app = web.Application(loop=loop)
    app.router.add_route('GET', '/', handler)
    server = await test_server(app)
    resp = await aiohttp.get(server.make_url('/'), loop=loop)
    async with resp:
        assert resp.status == 200
        assert resp.connection is not None
    assert resp.connection is None


async def test_client_api_context_manager(test_server, loop):

    async def handler(request):
        return web.HTTPOk()

    app = web.Application(loop=loop)
    app.router.add_route('GET', '/', handler)
    server = await test_server(app)

    async with aiohttp.get(server.make_url('/'), loop=loop) as resp:
        assert resp.status == 200
        assert resp.connection is not None
    assert resp.connection is None


def test_ctx_manager_is_coroutine():
    assert issubclass(_RequestContextManager, Coroutine)


async def test_context_manager_timeout_on_release(test_server, loop):

    async def handler(request):
        resp = web.StreamResponse()
        await resp.prepare(request)
        await asyncio.sleep(10, loop=loop)
        return resp

    app = web.Application(loop=loop)
    app.router.add_route('GET', '/', handler)
    server = await test_server(app)

    with aiohttp.ClientSession(loop=loop) as session:
        resp = await session.get(server.make_url('/'))
        with pytest.raises(asyncio.TimeoutError):
            with aiohttp.Timeout(0.01, loop=loop):
                async with resp:
                    assert resp.status == 200
                    assert resp.connection is not None
        assert resp.connection is None


async def test_iter_any(test_server, loop):

    data = b'0123456789' * 1024

    async def handler(request):
        buf = []
        async for raw in request.content.iter_any():
            buf.append(raw)
        assert b''.join(buf) == data
        return web.Response()

    app = web.Application(loop=loop)
    app.router.add_route('POST', '/', handler)
    server = await test_server(app)

    with aiohttp.ClientSession(loop=loop) as session:
        async with await session.post(server.make_url('/'), data=data) as resp:
            assert resp.status == 200


async def test_iter_error_on_conn_close(test_server, loop):

    async def handler(request):
        resp_ = web.StreamResponse()
        await resp_.prepare(request)
        for _ in range(3):
            resp_.write(b'data\n')
            await resp_.drain()
            await asyncio.sleep(0.5, loop=loop)
        return resp_

    app = web.Application(loop=loop)
    app.router.add_route('GET', '/', handler)
    server = await test_server(app)

    with aiohttp.ClientSession(loop=loop) as session:
            timer_started = False
            async with await session.get(
                    server.make_url('/'),
                    headers={'Connection': 'Keep-alive'}) as resp:
                with pytest.raises(aiohttp.ClientDisconnectedError):
                    async for _ in resp.content:
                        if not timer_started:
                            loop.call_later(0.5, session.close)
                            timer_started = True
