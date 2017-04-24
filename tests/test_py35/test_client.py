import asyncio
from concurrent import futures
from contextlib import contextmanager

import pytest

import aiohttp
from aiohttp import web


@contextmanager
def noop_context_manager():
    yield


async def test_async_with_session(loop):
    async with aiohttp.ClientSession(loop=loop) as session:
        pass

    assert session.closed


async def test_close_resp_on_error_async_with_session(loop, test_server):
    async def handler(request):
        resp = web.StreamResponse(headers={'content-length': '100'})
        await resp.prepare(request)
        await resp.drain()
        await asyncio.sleep(0.1, loop=request.app.loop)
        return resp

    app = web.Application()
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

    app = web.Application()
    app.router.add_get('/', handler)
    server = await test_server(app)

    async with aiohttp.ClientSession(loop=loop) as session:
        async with session.get(server.make_url('/')) as resp:
            await resp.read()

        assert len(session._connector._conns) == 1


async def test_non_close_detached_session_on_error_cm(loop, test_server):
    async def handler(request):
        resp = web.StreamResponse(headers={'content-length': '100'})
        await resp.prepare(request)
        await resp.drain()
        await asyncio.sleep(0.1, loop=request.app.loop)
        return resp

    app = web.Application()
    app.router.add_get('/', handler)
    server = await test_server(app)

    session = aiohttp.ClientSession(loop=loop)
    cm = session.get(server.make_url('/'))
    assert not session.closed
    with pytest.raises(RuntimeError):
        async with cm as resp:
            resp.content.set_exception(RuntimeError())
            await resp.read()
    assert not session.closed


async def test_close_detached_session_on_non_existing_addr(loop):
    session = aiohttp.ClientSession(loop=loop)

    async with session:
        cm = session.get('http://non-existing.example.com')
        assert not session.closed
        with pytest.raises(Exception):
            await cm

    assert session.closed


async def test_aiohttp_request(loop, test_server):
    async def handler(request):
        return web.Response()

    app = web.Application()
    app.router.add_get('/', handler)
    server = await test_server(app)

    async with aiohttp.request('GET', server.make_url('/'), loop=loop) as resp:
        await resp.read()
        assert resp.status == 200

    resp = await aiohttp.request('GET', server.make_url('/'), loop=loop)
    await resp.read()
    assert resp.status == 200
    assert resp.connection is None


@pytest.mark.parametrize("rows_multiplier, conn_limit", [
    (3, None),  # passes on 1.3 and 2.x branches
    (10, None),  # REGRESSION! passes on 1.3 and fails on 2.x branches
    (3, 0),  # passes on 1.3 and 2.x branches
    (10, 0),  # passes on 1.3 and 2.x branches
    (3, 1000),  # fails on 1.3 and 2.x branches
    (10, 1000),  # fails on 1.3 and 2.x branches
])
async def test_timeout_using_conn_limit(loop, test_server,
                                        rows_multiplier, conn_limit):

    async def handler(request):
        resp = web.Response()
        await asyncio.sleep(2, loop=loop)
        return resp

    async def read_resp(session, server):
        # Not able to reproduce the issue with a local server
        url = 'http://aiohttp.readthedocs.io/en/stable/'
        async with session.get(url, timeout=4) as resp:
            await resp.read()

    app = web.Application(loop=loop)
    app.router.add_route('GET', '/', handler)
    server = await test_server(app)

    rows = []
    conn_kwargs = dict(loop=loop)
    if conn_limit is not None:
        conn_kwargs['limit'] = conn_limit
    connector = aiohttp.TCPConnector(**conn_kwargs)
    async with aiohttp.ClientSession(connector=connector,
                                     loop=loop) as session:
        for i in range(connector._limit * rows_multiplier):
            rows.append(asyncio.ensure_future(
                read_resp(session, server), loop=loop))
        await asyncio.gather(*rows)
