import asyncio
from unittest import mock

from aiohttp import web


@asyncio.coroutine
def test_simple_server(raw_test_server, test_client):
    @asyncio.coroutine
    def handler(request):
        return web.Response(text=str(request.rel_url))

    server = yield from raw_test_server(handler)
    client = yield from test_client(server)
    resp = yield from client.get('/path/to')
    assert resp.status == 200
    txt = yield from resp.text()
    assert txt == '/path/to'


@asyncio.coroutine
def test_raw_server_not_http_exception(raw_test_server, test_client):
    exc = RuntimeError("custom runtime error")

    @asyncio.coroutine
    def handler(request):
        raise exc

    logger = mock.Mock()
    server = yield from raw_test_server(handler, logger=logger)
    client = yield from test_client(server)
    resp = yield from client.get('/path/to')
    assert resp.status == 500

    txt = yield from resp.text()
    assert "<h1>500 Internal Server Error</h1>" in txt

    logger.exception.assert_called_with(
        "Error handling request",
        exc_info=exc)


@asyncio.coroutine
def test_raw_server_not_http_exception_debug(raw_test_server, test_client):
    exc = RuntimeError("custom runtime error")

    @asyncio.coroutine
    def handler(request):
        raise exc

    logger = mock.Mock()
    server = yield from raw_test_server(handler, logger=logger, debug=True)
    client = yield from test_client(server)
    resp = yield from client.get('/path/to')
    assert resp.status == 500

    txt = yield from resp.text()
    assert "<h2>Traceback:</h2>" in txt

    logger.exception.assert_called_with(
        "Error handling request",
        exc_info=exc)


def test_create_web_server_with_implicit_loop(loop):
    asyncio.set_event_loop(loop)

    @asyncio.coroutine
    def handler(request):
        return web.Response()  # pragma: no cover

    srv = web.Server(handler)
    assert srv._loop is loop
