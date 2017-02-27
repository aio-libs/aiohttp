import asyncio
from unittest import mock

import pytest

from aiohttp import client, web


@asyncio.coroutine
def test_simple_server(raw_test_server, test_client):
    @asyncio.coroutine
    def handler(request):
        return web.Response(text=str(request.rel_url))

    server = yield from raw_test_server(handler)
    cli = yield from test_client(server)
    resp = yield from cli.get('/path/to')
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
    cli = yield from test_client(server)
    resp = yield from cli.get('/path/to')
    assert resp.status == 500

    txt = yield from resp.text()
    assert "<h1>500 Internal Server Error</h1>" in txt

    logger.exception.assert_called_with(
        "Error handling request",
        exc_info=exc)


@asyncio.coroutine
def test_raw_server_handler_timeout(raw_test_server, test_client):
    exc = asyncio.TimeoutError("error")

    @asyncio.coroutine
    def handler(request):
        raise exc

    logger = mock.Mock()
    server = yield from raw_test_server(handler, logger=logger)
    cli = yield from test_client(server)
    resp = yield from cli.get('/path/to')
    assert resp.status == 504

    yield from resp.text()
    logger.debug.assert_called_with("Request handler timed out.")


@asyncio.coroutine
def test_raw_server_do_not_swallow_exceptions(raw_test_server, test_client):
    exc = None

    @asyncio.coroutine
    def handler(request):
        raise exc

    logger = mock.Mock()
    server = yield from raw_test_server(handler, logger=logger)
    cli = yield from test_client(server)

    for _exc, msg in (
            (asyncio.CancelledError("error"),
             'Ignored premature client disconnection'),):
        exc = _exc
        with pytest.raises(client.ServerDisconnectedError):
            yield from cli.get('/path/to')

        logger.debug.assert_called_with(msg)


@asyncio.coroutine
def test_raw_server_not_http_exception_debug(raw_test_server, test_client):
    exc = RuntimeError("custom runtime error")

    @asyncio.coroutine
    def handler(request):
        raise exc

    logger = mock.Mock()
    server = yield from raw_test_server(handler, logger=logger, debug=True)
    cli = yield from test_client(server)
    resp = yield from cli.get('/path/to')
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
