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


@pytest.mark.parametrize("semaphore_value, conn_limit", [
    (100, 200),
    (200, 200),
    (100, 100),
    (200, 100),
    (100, 0),
    (200, 0),
    (100, None),
    (200, None)
])
async def test_no_timeout_using_semaphore(loop, test_server,
                                          semaphore_value, conn_limit):

    async def handler(request):
        resp = web.Response()
        await asyncio.sleep(0.05, loop=loop)
        return resp

    async def read_resp(session, server, semaphore):
        async with semaphore:
            resp = await session.get(server.make_url('/'), timeout=0.1)
            await resp.read()

    app = web.Application(loop=loop)
    app.router.add_route('GET', '/', handler)
    server = await test_server(app)

    rows = []
    semaphore = asyncio.Semaphore(semaphore_value, loop=loop)
    conn_kwargs = dict(loop=loop)
    if conn_limit is not None:
        conn_kwargs['limit'] = conn_limit
    connector = aiohttp.TCPConnector(**conn_kwargs)
    # If limit is set to 0, or the semaphore is smaller than ratio
    # read_timeout/resp_timeout times connector limit: should work!
    if conn_limit == 0 or semaphore_value < 2 * connector._limit:
        context_manager = noop_context_manager()
    # Else we expect a Timeout from future
    else:
        context_manager = pytest.raises(futures.TimeoutError)
    with context_manager:
        async with aiohttp.ClientSession(connector=connector,
                                         loop=loop) as session:
            for i in range(semaphore_value * 3):
                rows.append(asyncio.ensure_future(
                    read_resp(session, server, semaphore), loop=loop))
            await asyncio.gather(*rows)
