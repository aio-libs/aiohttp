import asyncio
import json
import sys
from typing import List, NoReturn, Optional
from unittest import mock

import pytest

import aiohttp
from aiohttp import (
    ClientConnectionResetError,
    ServerTimeoutError,
    WSMessageTypeError,
    WSMsgType,
    hdrs,
    web,
)
from aiohttp._websocket.models import WSMessageBinary
from aiohttp._websocket.reader import WebSocketDataQueue
from aiohttp.client_ws import ClientWSTimeout
from aiohttp.http import WSCloseCode
from aiohttp.pytest_plugin import AiohttpClient, AiohttpServer

if sys.version_info >= (3, 11):
    import asyncio as async_timeout
else:
    import async_timeout


class PatchableWebSocketDataQueue(WebSocketDataQueue):
    """A WebSocketDataQueue that can be patched."""


async def test_send_recv_text(aiohttp_client: AiohttpClient) -> None:
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
    resp = await client.ws_connect("/")
    await resp.send_str("ask")

    assert resp.get_extra_info("socket") is not None

    data = await resp.receive_str()
    assert data == "ask/answer"
    await resp.close()

    assert resp.get_extra_info("socket") is None


async def test_send_recv_bytes_bad_type(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> NoReturn:
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        msg = await ws.receive_str()
        await ws.send_str(msg + "/answer")
        await ws.close()
        assert False

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect("/")
    await resp.send_str("ask")

    with pytest.raises(WSMessageTypeError):
        await resp.receive_bytes()
        await resp.close()


async def test_recv_bytes_after_close(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> NoReturn:
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        await ws.close()
        assert False

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect("/")

    with pytest.raises(
        WSMessageTypeError,
        match=f"Received message {WSMsgType.CLOSE}:.+ is not WSMsgType.BINARY",
    ):
        await resp.receive_bytes()
        await resp.close()


async def test_send_recv_bytes(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.WebSocketResponse:
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


async def test_send_recv_text_bad_type(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> NoReturn:
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        msg = await ws.receive_bytes()
        await ws.send_bytes(msg + b"/answer")
        await ws.close()
        assert False

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect("/")

    await resp.send_bytes(b"ask")

    with pytest.raises(WSMessageTypeError):
        await resp.receive_str()

        await resp.close()


async def test_recv_text_after_close(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> NoReturn:
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        await ws.close()
        assert False

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect("/")

    with pytest.raises(
        WSMessageTypeError,
        match=f"Received message {WSMsgType.CLOSE}:.+ is not WSMsgType.TEXT",
    ):
        await resp.receive_str()
        await resp.close()


async def test_send_recv_json(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.WebSocketResponse:
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


async def test_send_recv_json_bytes(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.send_bytes(json.dumps({"response": "x"}).encode())
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect("/")
    data = await resp.receive()
    assert isinstance(data, WSMessageBinary)
    assert data.json() == {"response": "x"}
    await resp.close()


async def test_send_recv_frame(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        msg = await ws.receive()
        assert msg.type is WSMsgType.BINARY
        await ws.send_frame(msg.data, msg.type)
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect("/")
    await resp.send_frame(b"test", WSMsgType.BINARY)

    data = await resp.receive()
    assert data.data == b"test"
    assert data.type is WSMsgType.BINARY
    await resp.close()


async def test_ping_pong(aiohttp_client: AiohttpClient) -> None:
    loop = asyncio.get_event_loop()
    closed = loop.create_future()

    async def handler(request: web.Request) -> web.WebSocketResponse:
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


async def test_ping_pong_manual(aiohttp_client: AiohttpClient) -> None:
    loop = asyncio.get_event_loop()
    closed = loop.create_future()

    async def handler(request: web.Request) -> web.WebSocketResponse:
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


async def test_close(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.WebSocketResponse:
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


async def test_concurrent_task_close(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.WebSocketResponse:
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


async def test_concurrent_close(aiohttp_client: AiohttpClient) -> None:
    client_ws: Optional[aiohttp.ClientWebSocketResponse] = None

    async def handler(request: web.Request) -> web.WebSocketResponse:
        nonlocal client_ws
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        await ws.receive_bytes()
        await ws.send_str("test")

        assert client_ws is not None
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


async def test_concurrent_close_multiple_tasks(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.WebSocketResponse:
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


async def test_close_from_server(aiohttp_client: AiohttpClient) -> None:
    loop = asyncio.get_event_loop()
    closed = loop.create_future()

    async def handler(request: web.Request) -> web.WebSocketResponse:
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


async def test_close_manual(aiohttp_client: AiohttpClient) -> None:
    loop = asyncio.get_event_loop()
    closed = loop.create_future()

    async def handler(request: web.Request) -> web.WebSocketResponse:
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


async def test_close_timeout_sock_close_read(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> NoReturn:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.receive_bytes()
        await ws.send_str("test")
        await asyncio.sleep(1)
        assert False

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    timeout = ClientWSTimeout(ws_close=0.2)
    resp = await client.ws_connect("/", timeout=timeout, autoclose=False)

    await resp.send_bytes(b"ask")

    msg = await resp.receive()
    assert msg.data == "test"
    assert msg.type == aiohttp.WSMsgType.TEXT

    await resp.close()
    assert resp.closed
    assert isinstance(resp.exception(), asyncio.TimeoutError)


async def test_close_timeout_deprecated(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> NoReturn:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.receive_bytes()
        await ws.send_str("test")
        await asyncio.sleep(1)
        assert False

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

    await resp.close()
    assert resp.closed
    assert isinstance(resp.exception(), asyncio.TimeoutError)


async def test_close_cancel(aiohttp_client: AiohttpClient) -> None:
    loop = asyncio.get_event_loop()

    async def handler(request: web.Request) -> NoReturn:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.receive_bytes()
        await ws.send_str("test")
        await asyncio.sleep(10)
        assert False

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


async def test_override_default_headers(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.WebSocketResponse:
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


async def test_additional_headers(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.WebSocketResponse:
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


async def test_recv_protocol_error(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        await ws.receive_str()
        assert ws._writer is not None
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


async def test_recv_timeout(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> NoReturn:
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        await ws.receive_str()

        await asyncio.sleep(0.1)
        assert False

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect("/")
    await resp.send_str("ask")

    with pytest.raises(asyncio.TimeoutError):
        async with async_timeout.timeout(0.01):
            await resp.receive()

    await resp.close()


async def test_receive_timeout_sock_read(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.WebSocketResponse:
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


async def test_receive_timeout_deprecation(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.WebSocketResponse:
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


async def test_custom_receive_timeout(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.WebSocketResponse:
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


async def test_heartbeat(aiohttp_client: AiohttpClient) -> None:
    ping_received = False

    async def handler(request: web.Request) -> NoReturn:
        nonlocal ping_received
        ws = web.WebSocketResponse(autoping=False)
        await ws.prepare(request)
        msg = await ws.receive()
        assert msg.type == aiohttp.WSMsgType.PING
        ping_received = True
        await ws.close()
        assert False

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
    ), mock.patch.object(
        resp._writer, "send_frame", wraps=resp._writer.send_frame
    ) as send_frame:
        await resp.receive()
        ping_count = send_frame.call_args_list.count(mock.call(b"", WSMsgType.PING))
    # Connection should be closed roughly after 1.5x heartbeat.
    await asyncio.sleep(0.2)
    assert ping_count == 1
    assert resp.close_code is WSCloseCode.ABNORMAL_CLOSURE


async def test_heartbeat_no_pong(aiohttp_client: AiohttpClient) -> None:
    """Test that the connection is closed if no pong is received without sending messages."""
    ping_received = False

    async def handler(request: web.Request) -> NoReturn:
        nonlocal ping_received
        ws = web.WebSocketResponse(autoping=False)
        await ws.prepare(request)
        msg = await ws.receive()
        assert msg.type == aiohttp.WSMsgType.PING
        ping_received = True
        await ws.receive()
        assert False

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

    async def handler(request: web.Request) -> NoReturn:
        nonlocal ping_received
        ws = web.WebSocketResponse(autoping=False)
        with mock.patch(
            "aiohttp.web_ws.WebSocketDataQueue", PatchableWebSocketDataQueue
        ):
            await ws.prepare(request)
        msg = await ws.receive()
        ping_received = msg.type is aiohttp.WSMsgType.PING
        with mock.patch.object(
            ws._reader, "feed_eof", autospec=True, spec_set=True, return_value=None
        ):
            await asyncio.sleep(10.0)
        assert False

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    with mock.patch("aiohttp.client.WebSocketDataQueue", PatchableWebSocketDataQueue):
        client = await aiohttp_client(app)
        resp = await client.ws_connect("/", heartbeat=0.1)
    with mock.patch.object(
        resp._reader, "feed_eof", autospec=True, spec_set=True, return_value=None
    ):
        # Connection should be closed roughly after 1.5x heartbeat.
        msg = await resp.receive(5.0)
        assert ping_received
        assert resp.close_code is WSCloseCode.ABNORMAL_CLOSURE
        assert msg.type is WSMsgType.ERROR
        assert isinstance(msg.data, ServerTimeoutError)


async def test_close_websocket_while_ping_inflight(
    aiohttp_client: AiohttpClient, loop: asyncio.AbstractEventLoop
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
    ping_started = loop.create_future()

    async def delayed_send_frame(
        message: bytes, opcode: int, compress: Optional[int] = None
    ) -> None:
        assert opcode == WSMsgType.PING
        nonlocal cancelled, ping_started
        ping_started.set_result(None)
        try:
            await asyncio.sleep(1)
        except asyncio.CancelledError:
            cancelled = True
            raise

    with mock.patch.object(resp._writer, "send_frame", delayed_send_frame):
        async with async_timeout.timeout(1):
            await ping_started

    await resp.close()
    await asyncio.sleep(0)
    assert ping_started.result() is None
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


async def test_send_recv_compress_wbits(aiohttp_client: AiohttpClient) -> None:
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
    resp = await client.ws_connect("/", compress=9)
    await resp.send_str("ask")

    # Client indicates supports wbits 15
    # Server supports wbit 15 for decode
    assert resp.compress == 15

    data = await resp.receive_str()
    assert data == "ask/answer"

    await resp.close()
    assert resp.get_extra_info("socket") is None


async def test_send_recv_compress_wbit_error(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.WebSocketResponse:
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


async def test_ws_client_async_for(aiohttp_client: AiohttpClient) -> None:
    items = ["q1", "q2", "q3"]

    async def handler(request: web.Request) -> web.WebSocketResponse:
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


async def test_ws_async_with(aiohttp_server: AiohttpServer) -> None:
    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        msg = await ws.receive()
        assert msg.type is WSMsgType.TEXT
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


async def test_ws_async_with_send(aiohttp_server: AiohttpServer) -> None:
    # send_xxx methods have to return awaitable objects

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        msg = await ws.receive()
        assert msg.type is WSMsgType.TEXT
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


async def test_ws_async_with_shortcut(aiohttp_server: AiohttpServer) -> None:
    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        msg = await ws.receive()
        assert msg.type is WSMsgType.TEXT
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


async def test_closed_async_for(aiohttp_client: AiohttpClient) -> None:
    loop = asyncio.get_event_loop()
    closed = loop.create_future()

    async def handler(request: web.Request) -> web.WebSocketResponse:
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
        assert b"started" == msg.data
        await resp.send_bytes(b"ask")
        await resp.close()

    assert 1 == len(messages)
    assert messages[0].type == aiohttp.WSMsgType.BINARY
    assert messages[0].data == b"started"
    assert resp.closed

    await closed


async def test_peer_connection_lost(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> NoReturn:
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        msg = await ws.receive_str()
        assert msg == "ask"
        await ws.send_str("answer")
        assert request.transport is not None
        request.transport.close()
        await asyncio.sleep(10)
        assert False

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect("/")
    await resp.send_str("ask")
    assert "answer" == await resp.receive_str()

    msg = await resp.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSED
    await resp.close()


async def test_peer_connection_lost_iter(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> NoReturn:
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        msg = await ws.receive_str()
        assert msg == "ask"
        await ws.send_str("answer")
        assert request.transport is not None
        request.transport.close()
        await asyncio.sleep(100)
        assert False

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


async def test_websocket_connection_not_closed_properly(
    aiohttp_client: AiohttpClient,
) -> None:
    """Test that closing the connection via __del__ does not raise an exception."""

    async def handler(request: web.Request) -> NoReturn:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.close()
        assert False

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect("/")
    assert resp._conn is not None
    # Simulate the connection not being closed properly
    # https://github.com/aio-libs/aiohttp/issues/9880
    resp._conn.release()

    # Clean up so the test does not leak
    await resp.close()


async def test_websocket_connection_cancellation(
    aiohttp_client: AiohttpClient, loop: asyncio.AbstractEventLoop
) -> None:
    """Test canceling the WebSocket connection task does not raise an exception in __del__."""

    async def handler(request: web.Request) -> NoReturn:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.close()
        assert False

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    sync_future: "asyncio.Future[List[aiohttp.ClientWebSocketResponse]]" = (
        loop.create_future()
    )
    client = await aiohttp_client(app)

    async def websocket_task() -> None:
        resp = await client.ws_connect("/")
        assert resp is not None  # ensure we hold a reference to the websocket
        # The test harness will cleanup the unclosed websocket
        # for us, so we need to copy the websockets to ensure
        # we can control the cleanup
        sync_future.set_result(client._websockets.copy())
        client._websockets.clear()
        await asyncio.sleep(0)

    task = loop.create_task(websocket_task())
    websockets = await sync_future
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    websocket = websockets.pop()
    # Call the `__del__` methods manually since when it gets gc'd it not reproducible
    del websocket._response

    # Cleanup properly
    websocket._response = mock.Mock()
    await websocket.close()
