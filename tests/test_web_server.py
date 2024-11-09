import asyncio
import socket
from contextlib import suppress
from unittest import mock

import pytest

from aiohttp import client, web


async def test_simple_server(aiohttp_raw_server, aiohttp_client) -> None:
    async def handler(request):
        return web.Response(text=str(request.rel_url))

    server = await aiohttp_raw_server(handler)
    cli = await aiohttp_client(server)
    resp = await cli.get("/path/to")
    assert resp.status == 200
    txt = await resp.text()
    assert txt == "/path/to"


async def test_unsupported_upgrade(aiohttp_raw_server, aiohttp_client) -> None:
    # don't fail if a client probes for an unsupported protocol upgrade
    # https://github.com/aio-libs/aiohttp/issues/6446#issuecomment-999032039
    async def handler(request: web.Request):
        return web.Response(body=await request.read())

    upgrade_headers = {"Connection": "Upgrade", "Upgrade": "unsupported_proto"}
    server = await aiohttp_raw_server(handler)
    cli = await aiohttp_client(server)
    test_data = b"Test"
    resp = await cli.post("/path/to", data=test_data, headers=upgrade_headers)
    assert resp.status == 200
    data = await resp.read()
    assert data == test_data


async def test_raw_server_not_http_exception(aiohttp_raw_server, aiohttp_client):
    exc = RuntimeError("custom runtime error")

    async def handler(request):
        raise exc

    logger = mock.Mock()
    server = await aiohttp_raw_server(handler, logger=logger, debug=False)
    cli = await aiohttp_client(server)
    resp = await cli.get("/path/to")
    assert resp.status == 500
    assert resp.headers["Content-Type"].startswith("text/plain")

    txt = await resp.text()
    assert txt.startswith("500 Internal Server Error")
    assert "Traceback" not in txt

    logger.exception.assert_called_with("Error handling request", exc_info=exc)


async def test_raw_server_handler_timeout(aiohttp_raw_server, aiohttp_client) -> None:
    exc = asyncio.TimeoutError("error")

    async def handler(request):
        raise exc

    logger = mock.Mock()
    server = await aiohttp_raw_server(handler, logger=logger)
    cli = await aiohttp_client(server)
    resp = await cli.get("/path/to")
    assert resp.status == 504

    await resp.text()
    logger.debug.assert_called_with("Request handler timed out.", exc_info=exc)


async def test_raw_server_do_not_swallow_exceptions(aiohttp_raw_server, aiohttp_client):
    async def handler(request):
        raise asyncio.CancelledError()

    logger = mock.Mock()
    server = await aiohttp_raw_server(handler, logger=logger)
    cli = await aiohttp_client(server)

    with pytest.raises(client.ServerDisconnectedError):
        await cli.get("/path/to")

    logger.debug.assert_called_with("Ignored premature client disconnection")


async def test_raw_server_cancelled_in_write_eof(aiohttp_raw_server, aiohttp_client):
    async def handler(request):
        resp = web.Response(text=str(request.rel_url))
        resp.write_eof = mock.Mock(side_effect=asyncio.CancelledError("error"))
        return resp

    logger = mock.Mock()
    server = await aiohttp_raw_server(handler, logger=logger)
    cli = await aiohttp_client(server)

    resp = await cli.get("/path/to")
    with pytest.raises(client.ClientPayloadError):
        await resp.read()

    logger.debug.assert_called_with("Ignored premature client disconnection")


async def test_raw_server_not_http_exception_debug(aiohttp_raw_server, aiohttp_client):
    exc = RuntimeError("custom runtime error")

    async def handler(request):
        raise exc

    logger = mock.Mock()
    server = await aiohttp_raw_server(handler, logger=logger, debug=True)
    cli = await aiohttp_client(server)
    resp = await cli.get("/path/to")
    assert resp.status == 500
    assert resp.headers["Content-Type"].startswith("text/plain")

    txt = await resp.text()
    assert "Traceback (most recent call last):\n" in txt

    logger.exception.assert_called_with("Error handling request", exc_info=exc)


async def test_raw_server_html_exception(aiohttp_raw_server, aiohttp_client):
    exc = RuntimeError("custom runtime error")

    async def handler(request):
        raise exc

    logger = mock.Mock()
    server = await aiohttp_raw_server(handler, logger=logger, debug=False)
    cli = await aiohttp_client(server)
    resp = await cli.get("/path/to", headers={"Accept": "text/html"})
    assert resp.status == 500
    assert resp.headers["Content-Type"].startswith("text/html")

    txt = await resp.text()
    assert txt == (
        "<html><head><title>500 Internal Server Error</title></head><body>\n"
        "<h1>500 Internal Server Error</h1>\n"
        "Server got itself in trouble\n"
        "</body></html>\n"
    )

    logger.exception.assert_called_with("Error handling request", exc_info=exc)


async def test_raw_server_html_exception_debug(aiohttp_raw_server, aiohttp_client):
    exc = RuntimeError("custom runtime error")

    async def handler(request):
        raise exc

    logger = mock.Mock()
    server = await aiohttp_raw_server(handler, logger=logger, debug=True)
    cli = await aiohttp_client(server)
    resp = await cli.get("/path/to", headers={"Accept": "text/html"})
    assert resp.status == 500
    assert resp.headers["Content-Type"].startswith("text/html")

    txt = await resp.text()
    assert txt.startswith(
        "<html><head><title>500 Internal Server Error</title></head><body>\n"
        "<h1>500 Internal Server Error</h1>\n"
        "<h2>Traceback:</h2>\n"
        "<pre>Traceback (most recent call last):\n"
    )

    logger.exception.assert_called_with("Error handling request", exc_info=exc)


async def test_handler_cancellation(unused_port_socket: socket.socket) -> None:
    event = asyncio.Event()
    sock = unused_port_socket
    port = sock.getsockname()[1]

    async def on_request(_: web.Request) -> web.Response:
        nonlocal event
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            event.set()
            raise
        else:
            raise web.HTTPInternalServerError()

    app = web.Application()
    app.router.add_route("GET", "/", on_request)

    runner = web.AppRunner(app, handler_cancellation=True)
    await runner.setup()

    site = web.SockSite(runner, sock=sock)

    await site.start()
    assert runner.server is not None
    try:
        assert runner.server.handler_cancellation, "Flag was not propagated"

        async with client.ClientSession(
            timeout=client.ClientTimeout(total=0.1)
        ) as sess:
            with pytest.raises(asyncio.TimeoutError):
                await sess.get(f"http://127.0.0.1:{port}/")

        with suppress(asyncio.TimeoutError):
            await asyncio.wait_for(event.wait(), timeout=1)
        assert event.is_set(), "Request handler hasn't been cancelled"
    finally:
        await asyncio.gather(runner.shutdown(), site.stop())


async def test_no_handler_cancellation(unused_port_socket: socket.socket) -> None:
    timeout_event = asyncio.Event()
    done_event = asyncio.Event()
    sock = unused_port_socket
    port = sock.getsockname()[1]
    started = False

    async def on_request(_: web.Request) -> web.Response:
        nonlocal done_event, started, timeout_event
        started = True
        await asyncio.wait_for(timeout_event.wait(), timeout=5)
        done_event.set()
        return web.Response()

    app = web.Application()
    app.router.add_route("GET", "/", on_request)

    runner = web.AppRunner(app)
    await runner.setup()

    site = web.SockSite(runner, sock=sock)

    await site.start()
    try:
        async with client.ClientSession(
            timeout=client.ClientTimeout(total=0.2)
        ) as sess:
            with pytest.raises(asyncio.TimeoutError):
                await sess.get(f"http://127.0.0.1:{port}/")
        await asyncio.sleep(0.1)
        timeout_event.set()

        with suppress(asyncio.TimeoutError):
            await asyncio.wait_for(done_event.wait(), timeout=1)
        assert started
        assert done_event.is_set()
    finally:
        await asyncio.gather(runner.shutdown(), site.stop())
