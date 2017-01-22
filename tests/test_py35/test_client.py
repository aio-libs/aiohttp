import pytest

import aiohttp
from aiohttp import web


async def test_async_with_session(loop):
    async with aiohttp.ClientSession(loop=loop) as session:
        pass

    assert session.closed


async def test_close_resp_on_error_async_with_session(loop, test_server):
    async def handler(request):
        return web.Response()

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    server = await test_server(app)

    async with aiohttp.ClientSession(loop=loop) as session:
        with pytest.raises(RuntimeError):
            async with session.get(server.make_url('/')) as resp:
                resp.content.set_exception(RuntimeError())
                await resp.read()

        assert len(session._connector._conns) == 0


async def test_release_resp_on_normal_exit_from_cm(loop, test_server):
    async def handler(request):
        return web.Response()

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    server = await test_server(app)

    async with aiohttp.ClientSession(loop=loop) as session:
        async with session.get(server.make_url('/')) as resp:
            await resp.read()

        assert len(session._connector._conns) == 1


async def test_non_close_detached_session_on_error_cm(loop, test_server):
    async def handler(request):
        return web.Response()

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    server = await test_server(app)

    cm = aiohttp.get(server.make_url('/'), loop=loop)
    session = cm._session
    assert not session.closed
    with pytest.raises(RuntimeError):
        async with cm as resp:
            resp.content.set_exception(RuntimeError())
            await resp.read()
    assert not session.closed


async def test_close_detached_session_on_non_existing_addr(loop):
    cm = aiohttp.get('http://non-existing.example.com', loop=loop)
    session = cm._session
    assert not session.closed
    with pytest.raises(Exception):
        await cm
    assert session.closed
