import asyncio

import pytest
from multidict import CIMultiDict, CIMultiDictProxy

import aiohttp
from aiohttp import web, web_reqrep
from aiohttp.test_utils import TestClient as _TestClient
from aiohttp.test_utils import (AioHTTPTestCase, loop_context,
                                make_mocked_request, setup_test_loop,
                                teardown_test_loop, unittest_run_loop)


def _create_example_app(loop):

    @asyncio.coroutine
    def hello(request):
        return web.Response(body=b"Hello, world")

    @asyncio.coroutine
    def websocket_handler(request):

        ws = web.WebSocketResponse()
        yield from ws.prepare(request)
        msg = yield from ws.receive()
        if msg.type == aiohttp.WSMsgType.TEXT:
            if msg.data == 'close':
                yield from ws.close()
            else:
                ws.send_str(msg.data + '/answer')

        return ws

    @asyncio.coroutine
    def cookie_handler(request):
        resp = web.Response(body=b"Hello, world")
        resp.set_cookie('cookie', 'val')
        return resp

    app = web.Application(loop=loop)
    app.router.add_route('*', '/', hello)
    app.router.add_route('*', '/websocket', websocket_handler)
    app.router.add_route('*', '/cookie', cookie_handler)
    return app


def test_full_server_scenario():
    with loop_context() as loop:
        app = _create_example_app(loop)
        with _TestClient(app) as client:

            @asyncio.coroutine
            def test_get_route():
                nonlocal client
                resp = yield from client.request("GET", "/")
                assert resp.status == 200
                text = yield from resp.text()
                assert "Hello, world" in text

            loop.run_until_complete(test_get_route())


def test_server_with_create_test_teardown():
    with loop_context() as loop:
        app = _create_example_app(loop)
        with _TestClient(app) as client:

            @asyncio.coroutine
            def test_get_route():
                resp = yield from client.request("GET", "/")
                assert resp.status == 200
                text = yield from resp.text()
                assert "Hello, world" in text

            loop.run_until_complete(test_get_route())


def test_test_client_close_is_idempotent():
    """
    a test client, called multiple times, should
    not attempt to close the server again.
    """
    loop = setup_test_loop()
    app = _create_example_app(loop)
    client = _TestClient(app)
    loop.run_until_complete(client.close())
    loop.run_until_complete(client.close())
    teardown_test_loop(loop)


class TestAioHTTPTestCase(AioHTTPTestCase):

    def get_app(self, loop):
        return _create_example_app(loop)

    @unittest_run_loop
    @asyncio.coroutine
    def test_example_with_loop(self):
        request = yield from self.client.request("GET", "/")
        assert request.status == 200
        text = yield from request.text()
        assert "Hello, world" in text

    def test_example(self):
        @asyncio.coroutine
        def test_get_route():
            resp = yield from self.client.request("GET", "/")
            assert resp.status == 200
            text = yield from resp.text()
            assert "Hello, world" in text

        self.loop.run_until_complete(test_get_route())


# these exist to test the pytest scenario
@pytest.yield_fixture
def loop():
    with loop_context() as loop:
        yield loop


@pytest.fixture
def app(loop):
    return _create_example_app(loop)


@pytest.yield_fixture
def test_client(loop, app):
    client = _TestClient(app)
    loop.run_until_complete(client.start_server())
    yield client
    loop.run_until_complete(client.close())


def test_get_route(loop, test_client):
    @asyncio.coroutine
    def test_get_route():
        resp = yield from test_client.request("GET", "/")
        assert resp.status == 200
        text = yield from resp.text()
        assert "Hello, world" in text

    loop.run_until_complete(test_get_route())


@asyncio.coroutine
def test_client_websocket(loop, test_client):
    resp = yield from test_client.ws_connect("/websocket")
    resp.send_str("foo")
    msg = yield from resp.receive()
    assert msg.type == aiohttp.WSMsgType.TEXT
    assert "foo" in msg.data
    resp.send_str("close")
    msg = yield from resp.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE


@asyncio.coroutine
def test_client_cookie(loop, test_client):
    assert not test_client.session.cookies
    yield from test_client.get("/cookie")
    assert test_client.session.cookies['cookie'].value == 'val'


@asyncio.coroutine
@pytest.mark.parametrize("method", [
    "get", "post", "options", "post", "put", "patch", "delete"
])
@asyncio.coroutine
def test_test_client_methods(method, loop, test_client):
    resp = yield from getattr(test_client, method)("/")
    assert resp.status == 200
    text = yield from resp.text()
    assert "Hello, world" in text


@asyncio.coroutine
def test_test_client_head(loop, test_client):
    resp = yield from test_client.head("/")
    assert resp.status == 200


@pytest.mark.parametrize(
    "headers", [{'token': 'x'}, CIMultiDict({'token': 'x'}), {}])
def test_make_mocked_request(headers):
    req = make_mocked_request('GET', '/', headers=headers)
    assert req.method == "GET"
    assert req.path == "/"
    assert isinstance(req, web_reqrep.Request)
    assert isinstance(req.headers, CIMultiDictProxy)
