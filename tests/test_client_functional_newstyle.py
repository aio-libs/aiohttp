"""Http client functional tests against aiohttp.web server"""

import asyncio
import pytest

import aiohttp
from aiohttp import web


class Client:
    def __init__(self, session, url):
        self._session = session
        if not url.endswith('/'):
            url += '/'
        self._url = url

    def close(self):
        self._session.close()

    def get(self, path, **kwargs):
        while path.startswith('/'):
            path = path[1:]
        url = self._url + path
        return self._session.get(url, **kwargs)


@pytest.yield_fixture
def create(create_server, loop):
    client = None

    @asyncio.coroutine
    def maker(*, debug=False, ssl_ctx=None):
        nonlocal client
        app, url = yield from create_server(debug=debug, ssl_ctx=ssl_ctx)
        client = Client(aiohttp.ClientSession(loop=loop), url)
        return app, client

    yield maker
    client.close()


@pytest.mark.run_loop
def test_keepalive_two_requests_success(create):
    @asyncio.coroutine
    def handler(request):
        body = yield from request.read()
        assert b'' == body
        return web.Response(body=b'OK')

    app, client = yield from create()
    app.router.add_route('GET', '/', handler)
    resp1 = yield from client.get('/')
    yield from resp1.read()
    resp2 = yield from client.get('/')
    yield from resp2.read()

    assert 1 == len(client._session.connector._conns)


@pytest.mark.run_loop
def test_keepalive_response_released(create):
    @asyncio.coroutine
    def handler(request):
        body = yield from request.read()
        assert b'' == body
        return web.Response(body=b'OK')

    app, client = yield from create()
    app.router.add_route('GET', '/', handler)

    resp1 = yield from client.get('/')
    yield from resp1.release()
    resp2 = yield from client.get('/')
    yield from resp2.release()

    assert 1 == len(client._session.connector._conns)


@pytest.mark.run_loop
def test_keepalive_server_force_close_connection(create):
    @asyncio.coroutine
    def handler(request):
        body = yield from request.read()
        assert b'' == body
        response = web.Response(body=b'OK')
        response.force_close()
        return response

    app, client = yield from create()
    app.router.add_route('GET', '/', handler)

    resp1 = yield from client.get('/')
    resp1.close()
    resp2 = yield from client.get('/')
    resp2.close()

    assert 0 == len(client._session.connector._conns)


@pytest.mark.run_loop
def test_HTTP_304(create):
    @asyncio.coroutine
    def handler(request):
        body = yield from request.read()
        assert b'' == body
        return web.Response(status=304)

    app, client = yield from create()
    app.router.add_route('GET', '/', handler)

    resp = yield from client.get('/')
    assert resp.status == 304
    content = yield from resp.read()
    assert content == b''


@pytest.mark.run_loop
def test_HTTP_304_WITH_BODY(create):
    @asyncio.coroutine
    def handler(request):
        body = yield from request.read()
        assert b'' == body
        return web.Response(body=b'test', status=304)

    app, client = yield from create()
    app.router.add_route('GET', '/', handler)

    resp = yield from client.get('/')
    assert resp.status == 304
    content = yield from resp.read()
    assert content == b''
