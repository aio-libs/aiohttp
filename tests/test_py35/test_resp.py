import asyncio
from collections.abc import Coroutine

import pytest

import aiohttp
from aiohttp import web
from aiohttp.client import _RequestContextManager


async def test_await(test_server, loop):

    async def handler(request):
        resp = web.StreamResponse(headers={'content-length': str(4)})
        await resp.prepare(request)
        await resp.drain()
        await asyncio.sleep(0.01, loop=loop)
        resp.write(b'test')
        await asyncio.sleep(0.01, loop=loop)
        await resp.write_eof()
        return resp

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    server = await test_server(app)

    async with aiohttp.ClientSession(loop=loop) as session:
        resp = await session.get(server.make_url('/'))
        assert resp.status == 200
        assert resp.connection is not None
        await resp.read()
        await resp.release()
        assert resp.connection is None


async def test_response_context_manager(test_server, loop):

    async def handler(request):
        return web.HTTPOk()

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    server = await test_server(app)
    resp = await aiohttp.ClientSession(loop=loop).get(server.make_url('/'))
    async with resp:
        assert resp.status == 200
        assert resp.connection is None
    assert resp.connection is None


async def test_response_context_manager_error(test_server, loop):

    async def handler(request):
        return web.HTTPOk()

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    server = await test_server(app)
    session = aiohttp.ClientSession(loop=loop)
    cm = session.get(server.make_url('/'))
    resp = await cm
    with pytest.raises(RuntimeError):
        async with resp:
            assert resp.status == 200
            resp.content.set_exception(RuntimeError())
            await resp.read()
            assert resp.closed

    assert len(session._connector._conns) == 1


async def test_client_api_context_manager(test_server, loop):

    async def handler(request):
        return web.HTTPOk()

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    server = await test_server(app)

    async with aiohttp.ClientSession(loop=loop) as session:
        async with session.get(server.make_url('/')) as resp:
            assert resp.status == 200
            assert resp.connection is None
    assert resp.connection is None


def test_ctx_manager_is_coroutine():
    assert issubclass(_RequestContextManager, Coroutine)


async def test_context_manager_close_on_release(test_server, loop, mocker):

    async def handler(request):
        resp = web.StreamResponse()
        await resp.prepare(request)
        await resp.drain()
        await asyncio.sleep(10, loop=loop)
        return resp

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    server = await test_server(app)

    async with aiohttp.ClientSession(loop=loop) as session:
        resp = await session.get(server.make_url('/'))
        proto = resp.connection._protocol
        mocker.spy(proto, 'close')
        async with resp:
            assert resp.status == 200
            assert resp.connection is not None
        assert resp.connection is None
        assert proto.close.called


async def test_iter_any(test_server, loop):

    data = b'0123456789' * 1024

    async def handler(request):
        buf = []
        async for raw in request.content.iter_any():
            buf.append(raw)
        assert b''.join(buf) == data
        return web.Response()

    app = web.Application()
    app.router.add_route('POST', '/', handler)
    server = await test_server(app)

    async with aiohttp.ClientSession(loop=loop) as session:
        async with await session.post(server.make_url('/'), data=data) as resp:
            assert resp.status == 200
