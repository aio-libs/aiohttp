import asyncio
from unittest import mock

import pytest

from aiohttp import client, web


async def test_simple_server(aiohttp_raw_server, aiohttp_client):
    async def handler(request):
        return web.Response(text=str(request.rel_url))

    server = await aiohttp_raw_server(handler)
    cli = await aiohttp_client(server)
    resp = await cli.get('/path/to')
    assert resp.status == 200
    txt = await resp.text()
    assert txt == '/path/to'


async def test_raw_server_not_http_exception(aiohttp_raw_server,
                                             aiohttp_client):
    exc = RuntimeError("custom runtime error")

    async def handler(request):
        raise exc

    logger = mock.Mock()
    server = await aiohttp_raw_server(handler, logger=logger)
    cli = await aiohttp_client(server)
    resp = await cli.get('/path/to')
    assert resp.status == 500

    txt = await resp.text()
    assert "<h1>500 Internal Server Error</h1>" in txt

    logger.exception.assert_called_with(
        "Error handling request",
        exc_info=exc)


async def test_raw_server_handler_timeout(aiohttp_raw_server, aiohttp_client):
    exc = asyncio.TimeoutError("error")

    async def handler(request):
        raise exc

    logger = mock.Mock()
    server = await aiohttp_raw_server(handler, logger=logger)
    cli = await aiohttp_client(server)
    resp = await cli.get('/path/to')
    assert resp.status == 504

    await resp.text()
    logger.debug.assert_called_with("Request handler timed out.")


async def test_raw_server_do_not_swallow_exceptions(aiohttp_raw_server,
                                                    aiohttp_client):
    async def handler(request):
        raise asyncio.CancelledError()

    logger = mock.Mock()
    server = await aiohttp_raw_server(handler, logger=logger)
    cli = await aiohttp_client(server)

    with pytest.raises(client.ServerDisconnectedError):
        await cli.get('/path/to')

    logger.debug.assert_called_with('Ignored premature client disconnection')


async def test_raw_server_cancelled_in_write_eof(aiohttp_raw_server,
                                                 aiohttp_client):

    async def handler(request):
        resp = web.Response(text=str(request.rel_url))
        resp.write_eof = mock.Mock(side_effect=asyncio.CancelledError("error"))
        return resp

    logger = mock.Mock()
    server = await aiohttp_raw_server(handler, logger=logger)
    cli = await aiohttp_client(server)

    resp = await cli.get('/path/to')
    with pytest.raises(client.ClientPayloadError):
        await resp.read()

    logger.debug.assert_called_with('Ignored premature client disconnection ')


async def test_raw_server_not_http_exception_debug(aiohttp_raw_server,
                                                   aiohttp_client):
    exc = RuntimeError("custom runtime error")

    async def handler(request):
        raise exc

    logger = mock.Mock()
    server = await aiohttp_raw_server(handler, logger=logger, debug=True)
    cli = await aiohttp_client(server)
    resp = await cli.get('/path/to')
    assert resp.status == 500

    txt = await resp.text()
    assert "<h2>Traceback:</h2>" in txt

    logger.exception.assert_called_with(
        "Error handling request",
        exc_info=exc)


def test_create_web_server_with_implicit_loop(loop):
    asyncio.set_event_loop(loop)

    async def handler(request):
        return web.Response()  # pragma: no cover

    srv = web.Server(handler)
    assert srv._loop is loop
