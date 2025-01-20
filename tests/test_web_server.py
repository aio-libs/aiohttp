import asyncio
import socket
from contextlib import suppress
from typing import NoReturn
from unittest import mock

import pytest

from aiohttp import client, web
from aiohttp.http_exceptions import BadHttpMethod, BadStatusLine
from aiohttp.pytest_plugin import AiohttpClient, AiohttpRawServer


async def test_simple_server(
    aiohttp_raw_server: AiohttpRawServer, aiohttp_client: AiohttpClient
) -> None:
    async def handler(request: web.BaseRequest) -> web.Response:
        return web.Response(text=str(request.rel_url))

    server = await aiohttp_raw_server(handler)
    cli = await aiohttp_client(server)
    resp = await cli.get("/path/to")
    assert resp.status == 200
    txt = await resp.text()
    assert txt == "/path/to"


async def test_unsupported_upgrade(
    aiohttp_raw_server: AiohttpRawServer, aiohttp_client: AiohttpClient
) -> None:
    # don't fail if a client probes for an unsupported protocol upgrade
    # https://github.com/aio-libs/aiohttp/issues/6446#issuecomment-999032039
    async def handler(request: web.BaseRequest) -> web.Response:
        return web.Response(body=await request.read())

    upgrade_headers = {"Connection": "Upgrade", "Upgrade": "unsupported_proto"}
    server = await aiohttp_raw_server(handler)
    cli = await aiohttp_client(server)
    test_data = b"Test"
    resp = await cli.post("/path/to", data=test_data, headers=upgrade_headers)
    assert resp.status == 200
    data = await resp.read()
    assert data == test_data


async def test_raw_server_not_http_exception(
    aiohttp_raw_server: AiohttpRawServer,
    aiohttp_client: AiohttpClient,
    loop: asyncio.AbstractEventLoop,
) -> None:
    # disable debug mode not to print traceback
    loop.set_debug(False)

    exc = RuntimeError("custom runtime error")

    async def handler(request: web.BaseRequest) -> NoReturn:
        raise exc

    logger = mock.Mock()
    server = await aiohttp_raw_server(handler, logger=logger)
    cli = await aiohttp_client(server)
    resp = await cli.get("/path/to")
    assert resp.status == 500
    assert resp.headers["Content-Type"].startswith("text/plain")

    txt = await resp.text()
    assert txt.startswith("500 Internal Server Error")
    assert "Traceback" not in txt

    logger.exception.assert_called_with(
        "Error handling request from %s", cli.host, exc_info=exc
    )


async def test_raw_server_logs_invalid_method_with_loop_debug(
    aiohttp_raw_server: AiohttpRawServer,
    aiohttp_client: AiohttpClient,
    loop: asyncio.AbstractEventLoop,
) -> None:
    exc = BadHttpMethod(b"\x16\x03\x03\x01F\x01".decode(), "error")

    async def handler(request: web.BaseRequest) -> NoReturn:
        raise exc

    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    logger = mock.Mock()
    server = await aiohttp_raw_server(handler, logger=logger)
    cli = await aiohttp_client(server)
    resp = await cli.get("/path/to")
    assert resp.status == 500
    assert resp.headers["Content-Type"].startswith("text/plain")

    txt = await resp.text()
    assert "Traceback (most recent call last):\n" in txt

    # BadHttpMethod should be logged as debug
    # on the first request since the client may
    # be probing for TLS/SSL support which is
    # expected to fail
    logger.debug.assert_called_with(
        "Error handling request from %s", cli.host, exc_info=exc
    )
    logger.debug.reset_mock()

    # Now make another connection to the server
    # to make sure that the exception is logged
    # at debug on a second fresh connection
    cli2 = await aiohttp_client(server)
    resp = await cli2.get("/path/to")
    assert resp.status == 500
    assert resp.headers["Content-Type"].startswith("text/plain")
    # BadHttpMethod should be logged as debug
    # on the first request since the client may
    # be probing for TLS/SSL support which is
    # expected to fail
    logger.debug.assert_called_with(
        "Error handling request from %s", cli.host, exc_info=exc
    )


async def test_raw_server_logs_invalid_method_without_loop_debug(
    aiohttp_raw_server: AiohttpRawServer,
    aiohttp_client: AiohttpClient,
    loop: asyncio.AbstractEventLoop,
) -> None:
    exc = BadHttpMethod(b"\x16\x03\x03\x01F\x01".decode(), "error")

    async def handler(request: web.BaseRequest) -> NoReturn:
        raise exc

    loop = asyncio.get_event_loop()
    loop.set_debug(False)
    logger = mock.Mock()
    server = await aiohttp_raw_server(handler, logger=logger)
    cli = await aiohttp_client(server)
    resp = await cli.get("/path/to")
    assert resp.status == 500
    assert resp.headers["Content-Type"].startswith("text/plain")

    txt = await resp.text()
    assert "Traceback (most recent call last):\n" not in txt

    # BadHttpMethod should be logged as debug
    # on the first request since the client may
    # be probing for TLS/SSL support which is
    # expected to fail
    logger.debug.assert_called_with(
        "Error handling request from %s", cli.host, exc_info=exc
    )


async def test_raw_server_logs_invalid_method_second_request(
    aiohttp_raw_server: AiohttpRawServer,
    aiohttp_client: AiohttpClient,
    loop: asyncio.AbstractEventLoop,
) -> None:
    exc = BadHttpMethod(b"\x16\x03\x03\x01F\x01".decode(), "error")
    request_count = 0

    async def handler(request: web.BaseRequest) -> web.Response:
        nonlocal request_count
        request_count += 1
        if request_count == 2:
            raise exc
        return web.Response()

    loop = asyncio.get_event_loop()
    loop.set_debug(False)
    logger = mock.Mock()
    server = await aiohttp_raw_server(handler, logger=logger)
    cli = await aiohttp_client(server)
    resp = await cli.get("/path/to")
    assert resp.status == 200
    resp = await cli.get("/path/to")
    assert resp.status == 500
    assert resp.headers["Content-Type"].startswith("text/plain")
    # BadHttpMethod should be logged as an exception
    # if its not the first request since we know
    # that the client already was speaking HTTP
    logger.exception.assert_called_with(
        "Error handling request from %s", cli.host, exc_info=exc
    )


async def test_raw_server_logs_bad_status_line_as_exception(
    aiohttp_raw_server: AiohttpRawServer,
    aiohttp_client: AiohttpClient,
    loop: asyncio.AbstractEventLoop,
) -> None:
    exc = BadStatusLine(b"\x16\x03\x03\x01F\x01".decode(), "error")

    async def handler(request: web.BaseRequest) -> NoReturn:
        raise exc

    loop = asyncio.get_event_loop()
    loop.set_debug(False)
    logger = mock.Mock()
    server = await aiohttp_raw_server(handler, logger=logger)
    cli = await aiohttp_client(server)
    resp = await cli.get("/path/to")
    assert resp.status == 500
    assert resp.headers["Content-Type"].startswith("text/plain")

    txt = await resp.text()
    assert "Traceback (most recent call last):\n" not in txt

    logger.exception.assert_called_with(
        "Error handling request from %s", cli.host, exc_info=exc
    )


async def test_raw_server_handler_timeout(
    aiohttp_raw_server: AiohttpRawServer, aiohttp_client: AiohttpClient
) -> None:
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    exc = asyncio.TimeoutError("error")

    async def handler(request: web.BaseRequest) -> NoReturn:
        raise exc

    logger = mock.Mock()
    server = await aiohttp_raw_server(handler, logger=logger)
    cli = await aiohttp_client(server)
    resp = await cli.get("/path/to")
    assert resp.status == 504

    await resp.text()
    logger.debug.assert_called_with("Request handler timed out.", exc_info=exc)


async def test_raw_server_do_not_swallow_exceptions(
    aiohttp_raw_server: AiohttpRawServer, aiohttp_client: AiohttpClient
) -> None:
    async def handler(request: web.BaseRequest) -> NoReturn:
        raise asyncio.CancelledError()

    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    logger = mock.Mock()
    server = await aiohttp_raw_server(handler, logger=logger)
    cli = await aiohttp_client(server)

    with pytest.raises(client.ServerDisconnectedError):
        await cli.get("/path/to")

    logger.debug.assert_called_with("Ignored premature client disconnection")


async def test_raw_server_cancelled_in_write_eof(
    aiohttp_raw_server: AiohttpRawServer, aiohttp_client: AiohttpClient
) -> None:
    class MyResponse(web.Response):
        async def write_eof(self, data: bytes = b"") -> NoReturn:
            raise asyncio.CancelledError("error")

    async def handler(request: web.BaseRequest) -> MyResponse:
        resp = MyResponse(text=str(request.rel_url))
        return resp

    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    logger = mock.Mock()
    server = await aiohttp_raw_server(handler, logger=logger)
    cli = await aiohttp_client(server)

    resp = await cli.get("/path/to")
    with pytest.raises(client.ClientPayloadError):
        await resp.read()

    logger.debug.assert_called_with("Ignored premature client disconnection")


async def test_raw_server_not_http_exception_debug(
    aiohttp_raw_server: AiohttpRawServer, aiohttp_client: AiohttpClient
) -> None:
    exc = RuntimeError("custom runtime error")

    async def handler(request: web.BaseRequest) -> NoReturn:
        raise exc

    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    logger = mock.Mock()
    server = await aiohttp_raw_server(handler, logger=logger)
    cli = await aiohttp_client(server)
    resp = await cli.get("/path/to")
    assert resp.status == 500
    assert resp.headers["Content-Type"].startswith("text/plain")

    txt = await resp.text()
    assert "Traceback (most recent call last):\n" in txt

    logger.exception.assert_called_with(
        "Error handling request from %s", cli.host, exc_info=exc
    )


async def test_raw_server_html_exception(
    aiohttp_raw_server: AiohttpRawServer,
    aiohttp_client: AiohttpClient,
    loop: asyncio.AbstractEventLoop,
) -> None:
    # disable debug mode not to print traceback
    loop.set_debug(False)

    exc = RuntimeError("custom runtime error")

    async def handler(request: web.BaseRequest) -> NoReturn:
        raise exc

    logger = mock.Mock()
    server = await aiohttp_raw_server(handler, logger=logger)
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

    logger.exception.assert_called_with(
        "Error handling request from %s", cli.host, exc_info=exc
    )


async def test_raw_server_html_exception_debug(
    aiohttp_raw_server: AiohttpRawServer, aiohttp_client: AiohttpClient
) -> None:
    exc = RuntimeError("custom runtime error")

    async def handler(request: web.BaseRequest) -> NoReturn:
        raise exc

    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    logger = mock.Mock()
    server = await aiohttp_raw_server(handler, logger=logger)
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

    logger.exception.assert_called_with(
        "Error handling request from %s", cli.host, exc_info=exc
    )


async def test_handler_cancellation(unused_port_socket: socket.socket) -> None:
    event = asyncio.Event()
    sock = unused_port_socket
    port = sock.getsockname()[1]

    async def on_request(request: web.Request) -> web.Response:
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
            timeout=client.ClientTimeout(total=0.15)
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

    async def on_request(request: web.Request) -> web.Response:
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
