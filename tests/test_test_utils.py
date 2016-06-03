import asyncio
import aiohttp
from aiohttp import web
from aiohttp.test_utils import (
    TestClient, loop_context,
    AioHTTPTestCase, unittest_run_loop,
    setup_test_loop, teardown_test_loop
)
import pytest


def _create_example_app(loop):

    @asyncio.coroutine
    def hello(request):
        return web.Response(body=b"Hello, world")

    @asyncio.coroutine
    def websocket_handler(request):

        ws = web.WebSocketResponse()
        yield from ws.prepare(request)
        msg = yield from ws.receive()
        if msg.tp == aiohttp.MsgType.text:
            if msg.data == 'close':
                yield from ws.close()
            else:
                ws.send_str(msg.data + '/answer')

        return ws

    app = web.Application(loop=loop)
    app.router.add_route('*', '/', hello)
    app.router.add_route('*', '/websocket', websocket_handler)
    return app


def test_full_server_scenario():
    with loop_context() as loop:
        app = _create_example_app(loop)
        with TestClient(app) as client:

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
        client = TestClient(app)

        @asyncio.coroutine
        def test_get_route():
            resp = yield from client.request("GET", "/")
            assert resp.status == 200
            text = yield from resp.text()
            assert "Hello, world" in text

        loop.run_until_complete(test_get_route())
        client.close()


def test_test_client_close_is_idempotent():
    """
    a test client, called multiple times, should
    not attempt to close the loop again.
    """
    loop = setup_test_loop()
    app = _create_example_app(loop)
    client = TestClient(app)
    client.close()
    teardown_test_loop(loop)
    client.close()


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
    client = TestClient(app)
    yield client
    client.close()


def test_get_route(loop, test_client):
    @asyncio.coroutine
    def test_get_route():
        nonlocal test_client
        resp = yield from test_client.request("GET", "/")
        assert resp.status == 200
        text = yield from resp.text()
        assert "Hello, world" in text

    loop.run_until_complete(test_get_route())


@pytest.mark.run_loop
@asyncio.coroutine
def test_client_websocket(loop, test_client):
    resp = yield from test_client.ws_connect("/websocket")
    resp.send_str("foo")
    msg = yield from resp.receive()
    assert msg.tp == aiohttp.MsgType.text
    assert "foo" in msg.data
    resp.send_str("close")
    msg = yield from resp.receive()
    assert msg.tp == aiohttp.MsgType.close


@pytest.mark.run_loop
@pytest.mark.parametrize("method", [
    "get", "post", "options", "post", "put", "patch", "delete"
])
@asyncio.coroutine
def test_test_client_methods(method, loop, test_client):
    resp = yield from getattr(test_client, method)("/")
    assert resp.status == 200
    text = yield from resp.text()
    assert "Hello, world" in text


@pytest.mark.run_loop
@asyncio.coroutine
def test_test_client_head(loop, test_client):
    resp = yield from test_client.head("/")
    assert resp.status == 200
