import asyncio
from aiohttp import web
from aiohttp.test_utils import (
    TestClient, loop_context,
    AioHTTPTestCase, run_loop
)
import pytest


def _create_example_app(loop):

    @asyncio.coroutine
    def hello(request):
        return web.Response(body=b"Hello, world")

    app = web.Application(loop=loop)
    app.router.add_route('GET', '/', hello)
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
    with loop_context() as loop:
        app = _create_example_app(loop)
        client = TestClient(app)
        client.close()
    client.close()


class TestAioHTTPTestCase(AioHTTPTestCase):

    def get_app(self, loop):
        return _create_example_app(loop)

    @run_loop
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
