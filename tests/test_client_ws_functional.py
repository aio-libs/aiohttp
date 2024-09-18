import asyncio
import sys
from typing import Any, NoReturn
from unittest import mock

import pytest

import aiohttp
from aiohttp import ClientConnectionResetError, ServerTimeoutError, WSMsgType, hdrs, web
from aiohttp.client_ws import ClientWSTimeout
from aiohttp.http import WSCloseCode
from aiohttp.pytest_plugin import AiohttpClient

if sys.version_info >= (3, 11):
    import asyncio as async_timeout
else:
    import async_timeout


async def test_send_recv_text(aiohttp_client) -> None:
    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        msg = await ws.receive_str()
        await ws.send_str(msg + "/answer")
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect("/")
    await resp.send_str("ask")

    assert resp.get_extra_info("socket") is not None

    data = await resp.receive_str()
    assert data == "ask/answer"
    await resp.close()

    assert resp.get_extra_info("socket") is None


async def test_send_recv_bytes_bad_type(aiohttp_client) -> None:
    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        msg = await ws.receive_str()
        await ws.send_str(msg + "/answer")
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect("/")
    await resp.send_str("ask")

    with pytest.raises(TypeError):
        await resp.receive_bytes()
        await resp.close()


async def test_send_recv_bytes(aiohttp_client) -> None:
    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        msg = await ws.receive_bytes()
        await ws.send_bytes(msg + b"/answer")
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect("/")

    await resp.send_bytes(b"ask")

    data = await resp.receive_bytes()
    assert data == b"ask/answer"

    await resp.close()


async def test_send_recv_text_bad_type(aiohttp_client) -> None:
    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        msg = await ws.receive_bytes()
        await ws.send_bytes(msg + b"/answer")
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect("/")

    await resp.send_bytes(b"ask")

    with pytest.raises(TypeError):
        await resp.receive_str()

        await resp.close()


async def test_send_recv_json(aiohttp_client) -> None:
    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        data = await ws.receive_json()
        await ws.send_json({"response": data["request"]})
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect("/")
    payload = {"request": "test"}
    await resp.send_json(payload)

    data = await resp.receive_json()
    assert data["response"] == payload["request"]
    await resp.close()


async def test_ping_pong(aiohttp_client) -> None:
    loop = asyncio.get_event_loop()
    closed = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        msg = await ws.receive_bytes()
        await ws.ping()
        await ws.send_bytes(msg + b"/answer")
        try:
            await ws.close()
        finally:
            closed.set_result(1)
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect("/")

    await resp.ping()
    await resp.send_bytes(b"ask")

    msg = await resp.receive()
    assert msg.type == aiohttp.WSMsgType.BINARY
    assert msg.data == b"ask/answer"

    msg = await resp.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE

    await resp.close()
    await closed


async def test_ping_pong_manual(aiohttp_client) -> None:
    loop = asyncio.get_event_loop()
    closed = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        msg = await ws.receive_bytes()
        await ws.ping()
        await ws.send_bytes(msg + b"/answer")
        try:
            await ws.close()
        finally:
            closed.set_result(1)
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect("/", autoping=False)

    await resp.ping()
    await resp.send_bytes(b"ask")

    msg = await resp.receive()
    assert msg.type == aiohttp.WSMsgType.PONG

    msg = await resp.receive()
    assert msg.type == aiohttp.WSMsgType.PING
    await resp.pong()

    msg = await resp.receive()
    assert msg.data == b"ask/answer"

    msg = await resp.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE

    await closed


async def test_close(aiohttp_client) -> None:
    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        await ws.receive_bytes()
        await ws.send_str("test")

        await ws.receive()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect("/")

    await resp.send_bytes(b"ask")

    closed = await resp.close()
    assert closed
    assert resp.closed
    assert resp.close_code == 1000

    msg = await resp.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSED


async def test_concurrent_close(aiohttp_client) -> None:
    client_ws = None

    async def handler(request):
        nonlocal client_ws
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        await ws.receive_bytes()
        await ws.send_str("test")

        await client_ws.close()

        msg = await ws.receive()
        assert msg.type is aiohttp.WSMsgType.CLOSE
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    ws = client_ws = await client.ws_connect("/")

    await ws.send_bytes(b"ask")

    msg = await ws.receive()
    assert msg.type is aiohttp.WSMsgType.CLOSING

    await asyncio.sleep(0.01)
    msg = await ws.receive()
    assert msg.type is aiohttp.WSMsgType.CLOSED


async def test_concurrent_close_multiple_tasks(aiohttp_client: Any) -> None:
    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        await ws.receive_bytes()
        await ws.send_str("test")

        msg = await ws.receive()
        assert msg.type is aiohttp.WSMsgType.CLOSE
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    ws = await client.ws_connect("/")

    await ws.send_bytes(b"ask")

    task1 = asyncio.create_task(ws.close())
    task2 = asyncio.create_task(ws.close())

    msg = await ws.receive()
    assert msg.type is aiohttp.WSMsgType.CLOSED

    await task1
    await task2

    msg = await ws.receive()
    assert msg.type is aiohttp.WSMsgType.CLOSED


async def test_concurrent_task_close(aiohttp_client) -> None:
    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.receive()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    client = await aiohttp_client(app)
    async with client.ws_connect("/") as resp:
        # wait for the message in a separate task
        task = asyncio.create_task(resp.receive())

        # Make sure we start to wait on receiving message before closing the connection
        await asyncio.sleep(0.1)

        closed = await resp.close()

        await task

        assert closed
        assert resp.closed
        assert resp.close_code == 1000


async def test_close_from_server(aiohttp_client) -> None:
    loop = asyncio.get_event_loop()
    closed = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        try:
            await ws.receive_bytes()
            await ws.close()
        finally:
            closed.set_result(1)
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect("/")

    await resp.send_bytes(b"ask")

    msg = await resp.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE
    assert resp.closed

    msg = await resp.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSED

    await closed


async def test_close_manual(aiohttp_client) -> None:
    loop = asyncio.get_event_loop()
    closed = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        await ws.receive_bytes()
        await ws.send_str("test")

        try:
            await ws.close()
        finally:
            closed.set_result(1)
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect("/", autoclose=False)
    await resp.send_bytes(b"ask")

    msg = await resp.receive()
    assert msg.data == "test"

    msg = await resp.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE
    assert msg.data == 1000
    assert msg.extra == ""
    assert not resp.closed

    await resp.close()
    await closed
    assert resp.closed


async def test_close_timeout_sock_close_read(aiohttp_client) -> None:
    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.receive_bytes()
        await ws.send_str("test")
        await asyncio.sleep(1)
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    timeout = ClientWSTimeout(ws_close=0.2)
    resp = await client.ws_connect("/", timeout=timeout, autoclose=False)

    await resp.send_bytes(b"ask")

    msg = await resp.receive()
    assert msg.data == "test"
    assert msg.type == aiohttp.WSMsgType.TEXT

    msg = await resp.close()
    assert resp.closed
    assert isinstance(resp.exception(), asyncio.TimeoutError)


async def test_close_timeout_deprecated(aiohttp_client) -> None:
    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.receive_bytes()
        await ws.send_str("test")
        await asyncio.sleep(1)
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    with pytest.warns(
        DeprecationWarning,
        match="parameter 'timeout' of type 'float' "
        "is deprecated, please use "
        r"'timeout=ClientWSTimeout\(ws_close=...\)'",
    ):
        resp = await client.ws_connect("/", timeout=0.2, autoclose=False)

    await resp.send_bytes(b"ask")

    msg = await resp.receive()
    assert msg.data == "test"
    assert msg.type == aiohttp.WSMsgType.TEXT

    msg = await resp.close()
    assert resp.closed
    assert isinstance(resp.exception(), asyncio.TimeoutError)


async def test_close_cancel(aiohttp_client) -> None:
    loop = asyncio.get_event_loop()

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.receive_bytes()
        await ws.send_str("test")
        await asyncio.sleep(10)

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect("/", autoclose=False)

    await resp.send_bytes(b"ask")

    text = await resp.receive()
    assert text.data == "test"

    t = loop.create_task(resp.close())
    await asyncio.sleep(0.1)
    t.cancel()
    await asyncio.sleep(0.1)
    assert resp.closed
    assert resp.exception() is None


async def test_override_default_headers(aiohttp_client) -> None:
    async def handler(request):
        assert request.headers[hdrs.SEC_WEBSOCKET_VERSION] == "8"
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.send_str("answer")
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    headers = {hdrs.SEC_WEBSOCKET_VERSION: "8"}
    client = await aiohttp_client(app)
    resp = await client.ws_connect("/", headers=headers)
    msg = await resp.receive()
    assert msg.data == "answer"
    await resp.close()


async def test_additional_headers(aiohttp_client) -> None:
    async def handler(request):
        assert request.headers["x-hdr"] == "xtra"
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        await ws.send_str("answer")
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect("/", headers={"x-hdr": "xtra"})
    msg = await resp.receive()
    assert msg.data == "answer"
    await resp.close()


async def test_recv_protocol_error(aiohttp_client) -> None:
    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        await ws.receive_str()
        ws._writer.transport.write(b"01234" * 100)
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect("/")
    await resp.send_str("ask")

    msg = await resp.receive()
    assert msg.type == aiohttp.WSMsgType.ERROR
    assert type(msg.data) is aiohttp.WebSocketError
    assert msg.data.code == aiohttp.WSCloseCode.PROTOCOL_ERROR
    assert str(msg.data) == "Received frame with non-zero reserved bits"
    assert msg.extra is None
    await resp.close()


async def test_recv_timeout(aiohttp_client) -> None:
    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        await ws.receive_str()

        await asyncio.sleep(0.1)

        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect("/")
    await resp.send_str("ask")

    with pytest.raises(asyncio.TimeoutError):
        async with async_timeout.timeout(0.01):
            await resp.receive()

    await resp.close()


async def test_receive_timeout_sock_read(aiohttp_client) -> None:
    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.receive()
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    client = await aiohttp_client(app)
    receive_timeout = ClientWSTimeout(ws_receive=0.1)
    resp = await client.ws_connect("/", timeout=receive_timeout)

    with pytest.raises(asyncio.TimeoutError):
        await resp.receive(timeout=0.05)

    await resp.close()


async def test_receive_timeout_deprecation(aiohttp_client) -> None:

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.receive()
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    client = await aiohttp_client(app)
    with pytest.warns(
        DeprecationWarning,
        match="float parameter 'receive_timeout' "
        "is deprecated, please use parameter "
        r"'timeout=ClientWSTimeout\(ws_receive=...\)'",
    ):
        resp = await client.ws_connect("/", receive_timeout=0.1)

    with pytest.raises(asyncio.TimeoutError):
        await resp.receive(timeout=0.05)

    await resp.close()


async def test_custom_receive_timeout(aiohttp_client) -> None:
    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.receive()
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    client = await aiohttp_client(app)
    resp = await client.ws_connect("/")

    with pytest.raises(asyncio.TimeoutError):
        await resp.receive(0.05)

    await resp.close()


async def test_heartbeat(aiohttp_client) -> None:
    ping_received = False

    async def handler(request):
        nonlocal ping_received
        ws = web.WebSocketResponse(autoping=False)
        await ws.prepare(request)
        msg = await ws.receive()
        if msg.type == aiohttp.WSMsgType.ping:
            ping_received = True
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    client = await aiohttp_client(app)
    resp = await client.ws_connect("/", heartbeat=0.01)
    await asyncio.sleep(0.1)
    await resp.receive()
    await resp.close()

    assert ping_received


async def test_heartbeat_connection_closed(aiohttp_client: AiohttpClient) -> None:
    """Test that the connection is closed while ping is in progress."""

    async def handler(request: web.Request) -> NoReturn:
        ws = web.WebSocketResponse(autoping=False)
        await ws.prepare(request)
        await ws.receive()
        assert False

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    client = await aiohttp_client(app)
    resp = await client.ws_connect("/", heartbeat=0.1)
    ping_count = 0
    # We patch write here to simulate a connection reset error
    # since if we closed the connection normally, the client would
    # would cancel the heartbeat task and we wouldn't get a ping
    assert resp._conn is not None
    with mock.patch.object(
        resp._conn.transport, "write", side_effect=ClientConnectionResetError
    ), mock.patch.object(resp._writer, "ping", wraps=resp._writer.ping) as ping:
        await resp.receive()
        ping_count = ping.call_count
    # Connection should be closed roughly after 1.5x heartbeat.
    await asyncio.sleep(0.2)
    assert ping_count == 1
    assert resp.close_code is WSCloseCode.ABNORMAL_CLOSURE


async def test_heartbeat_no_pong(aiohttp_client: AiohttpClient) -> None:
    """Test that the connection is closed if no pong is received without sending messages."""
    ping_received = False

    async def handler(request):
        nonlocal ping_received
        ws = web.WebSocketResponse(autoping=False)
        await ws.prepare(request)
        msg = await ws.receive()
        if msg.type == aiohttp.WSMsgType.ping:
            ping_received = True
        await ws.receive()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    client = await aiohttp_client(app)
    resp = await client.ws_connect("/", heartbeat=0.1)

    # Connection should be closed roughly after 1.5x heartbeat.
    await asyncio.sleep(0.2)
    assert ping_received
    assert resp.close_code is WSCloseCode.ABNORMAL_CLOSURE


async def test_heartbeat_no_pong_after_receive_many_messages(
    aiohttp_client: AiohttpClient,
) -> None:
    """Test that the connection is closed if no pong is received after receiving many messages."""
    ping_received = False

    async def handler(request: web.Request) -> NoReturn:
        nonlocal ping_received
        ws = web.WebSocketResponse(autoping=False)
        await ws.prepare(request)
        for _ in range(5):
            await ws.send_str("test")
        await asyncio.sleep(0.05)
        for _ in range(5):
            await ws.send_str("test")
        msg = await ws.receive()
        ping_received = msg.type is aiohttp.WSMsgType.PING
        await ws.receive()
        assert False

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    client = await aiohttp_client(app)
    resp = await client.ws_connect("/", heartbeat=0.1)

    for _ in range(10):
        test_msg = await resp.receive()
        assert test_msg.data == "test"
    # Connection should be closed roughly after 1.5x heartbeat.

    await asyncio.sleep(0.2)
    assert ping_received
    assert resp.close_code is WSCloseCode.ABNORMAL_CLOSURE


async def test_heartbeat_no_pong_after_send_many_messages(
    aiohttp_client: AiohttpClient,
) -> None:
    """Test that the connection is closed if no pong is received after sending many messages."""
    ping_received = False

    async def handler(request: web.Request) -> NoReturn:
        nonlocal ping_received
        ws = web.WebSocketResponse(autoping=False)
        await ws.prepare(request)
        for _ in range(10):
            msg = await ws.receive()
            assert msg.data == "test"
            assert msg.type is aiohttp.WSMsgType.TEXT
        msg = await ws.receive()
        ping_received = msg.type is aiohttp.WSMsgType.PING
        await ws.receive()
        assert False

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    client = await aiohttp_client(app)
    resp = await client.ws_connect("/", heartbeat=0.1)

    for _ in range(5):
        await resp.send_str("test")
    await asyncio.sleep(0.05)
    for _ in range(5):
        await resp.send_str("test")
    # Connection should be closed roughly after 1.5x heartbeat.
    await asyncio.sleep(0.2)
    assert ping_received
    assert resp.close_code is WSCloseCode.ABNORMAL_CLOSURE


async def test_heartbeat_no_pong_concurrent_receive(
    aiohttp_client: AiohttpClient,
) -> None:
    ping_received = False

    async def handler(request):
        nonlocal ping_received
        ws = web.WebSocketResponse(autoping=False)
        await ws.prepare(request)
        msg = await ws.receive()
        ping_received = msg.type is aiohttp.WSMsgType.PING
        ws._reader.feed_eof = lambda: None
        await asyncio.sleep(10.0)

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    client = await aiohttp_client(app)
    resp = await client.ws_connect("/", heartbeat=0.1)
    resp._reader.feed_eof = lambda: None

    # Connection should be closed roughly after 1.5x heartbeat.
    msg = await resp.receive(5.0)
    assert ping_received
    assert resp.close_code is WSCloseCode.ABNORMAL_CLOSURE
    assert msg
    assert msg.type is WSMsgType.ERROR
    assert isinstance(msg.data, ServerTimeoutError)


async def test_close_websocket_while_ping_inflight(
    aiohttp_client: AiohttpClient,
) -> None:
    """Test closing the websocket while a ping is in-flight."""
    ping_received = False

    async def handler(request: web.Request) -> NoReturn:
        nonlocal ping_received
        ws = web.WebSocketResponse(autoping=False)
        await ws.prepare(request)
        msg = await ws.receive()
        assert msg.type is aiohttp.WSMsgType.BINARY
        msg = await ws.receive()
        ping_received = msg.type is aiohttp.WSMsgType.PING
        await ws.receive()
        assert False

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    client = await aiohttp_client(app)
    resp = await client.ws_connect("/", heartbeat=0.1)
    await resp.send_bytes(b"ask")

    cancelled = False
    ping_stated = False

    async def delayed_ping() -> None:
        nonlocal cancelled, ping_stated
        ping_stated = True
        try:
            await asyncio.sleep(1)
        except asyncio.CancelledError:
            cancelled = True
            raise

    with mock.patch.object(resp._writer, "ping", delayed_ping):
        await asyncio.sleep(0.1)

    await resp.close()
    await asyncio.sleep(0)
    assert ping_stated is True
    assert cancelled is True


async def test_send_recv_compress(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        msg = await ws.receive_str()
        await ws.send_str(msg + "/answer")
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect("/", compress=15)
    await resp.send_str("ask")

    assert resp.compress == 15

    data = await resp.receive_str()
    assert data == "ask/answer"

    await resp.close()
    assert resp.get_extra_info("socket") is None


async def test_send_recv_compress_wbits(aiohttp_client) -> None:
    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        msg = await ws.receive_str()
        await ws.send_str(msg + "/answer")
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect("/", compress=9)
    await resp.send_str("ask")

    # Client indicates supports wbits 15
    # Server supports wbit 15 for decode
    assert resp.compress == 15

    data = await resp.receive_str()
    assert data == "ask/answer"

    await resp.close()
    assert resp.get_extra_info("socket") is None


async def test_send_recv_compress_wbit_error(aiohttp_client) -> None:
    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        msg = await ws.receive_bytes()
        await ws.send_bytes(msg + b"/answer")
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    with pytest.raises(ValueError):
        await client.ws_connect("/", compress=1)


async def test_ws_client_async_for(aiohttp_client) -> None:
    items = ["q1", "q2", "q3"]

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        for i in items:
            await ws.send_str(i)
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    client = await aiohttp_client(app)
    resp = await client.ws_connect("/")
    it = iter(items)
    async for msg in resp:
        assert msg.data == next(it)

    with pytest.raises(StopIteration):
        next(it)

    assert resp.closed


async def test_ws_async_with(aiohttp_server) -> None:
    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        msg = await ws.receive()
        await ws.send_str(msg.data + "/answer")
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    server = await aiohttp_server(app)

    async with aiohttp.ClientSession() as client:
        async with client.ws_connect(server.make_url("/")) as ws:
            await ws.send_str("request")
            msg = await ws.receive()
            assert msg.data == "request/answer"

        assert ws.closed


async def test_ws_async_with_send(aiohttp_server) -> None:
    # send_xxx methods have to return awaitable objects

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        msg = await ws.receive()
        await ws.send_str(msg.data + "/answer")
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    server = await aiohttp_server(app)

    async with aiohttp.ClientSession() as client:
        async with client.ws_connect(server.make_url("/")) as ws:
            await ws.send_str("request")
            msg = await ws.receive()
            assert msg.data == "request/answer"

        assert ws.closed


async def test_ws_async_with_shortcut(aiohttp_server) -> None:
    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        msg = await ws.receive()
        await ws.send_str(msg.data + "/answer")
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    server = await aiohttp_server(app)

    async with aiohttp.ClientSession() as client:
        async with client.ws_connect(server.make_url("/")) as ws:
            await ws.send_str("request")
            msg = await ws.receive()
            assert msg.data == "request/answer"

        assert ws.closed


async def test_closed_async_for(aiohttp_client) -> None:
    loop = asyncio.get_event_loop()
    closed = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        try:
            await ws.send_bytes(b"started")
            await ws.receive_bytes()
        finally:
            closed.set_result(1)
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect("/")

    messages = []
    async for msg in resp:
        messages.append(msg)
        if b"started" == msg.data:
            await resp.send_bytes(b"ask")
            await resp.close()

    assert 1 == len(messages)
    assert messages[0].type == aiohttp.WSMsgType.BINARY
    assert messages[0].data == b"started"
    assert resp.closed

    await closed


async def test_peer_connection_lost(aiohttp_client) -> None:
    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        msg = await ws.receive_str()
        assert msg == "ask"
        await ws.send_str("answer")
        request.transport.close()
        await asyncio.sleep(10)
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect("/")
    await resp.send_str("ask")
    assert "answer" == await resp.receive_str()

    msg = await resp.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSED
    await resp.close()


async def test_peer_connection_lost_iter(aiohttp_client) -> None:
    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        msg = await ws.receive_str()
        assert msg == "ask"
        await ws.send_str("answer")
        request.transport.close()
        await asyncio.sleep(100)
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect("/")
    await resp.send_str("ask")
    async for msg in resp:
        assert "answer" == msg.data

    await resp.close()


async def test_ws_connect_with_wrong_ssl_type(aiohttp_client: AiohttpClient) -> None:
    app = web.Application()
    session = await aiohttp_client(app)

    with pytest.raises(TypeError, match="ssl should be SSLContext, .*"):
        await session.ws_connect("/", ssl=42)
