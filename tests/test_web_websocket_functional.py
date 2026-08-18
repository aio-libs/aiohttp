# HTTP websocket server functional tests

import asyncio
import contextlib
import gc
import json
import socket
import sys
import weakref
from typing import Literal, NoReturn
from unittest import mock

import pytest
from pytest_aiohttp import AiohttpClient, AiohttpServer

import aiohttp
from aiohttp import WSServerHandshakeError, hdrs, web
from aiohttp.http import WSCloseCode, WSMsgType
from aiohttp.web_protocol import MAX_MSG_QUEUE_SIZE


async def test_websocket_can_prepare(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> NoReturn:
        ws = web.WebSocketResponse()
        assert not ws.can_prepare(request)
        raise web.HTTPUpgradeRequired()

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    resp = await client.get("/")
    assert resp.status == 426


async def test_pipelined_request_after_failed_websocket_upgrade(
    aiohttp_server: AiohttpServer,
) -> None:
    """Pipelined HTTP request runs after a declined websocket upgrade.

    The parser flips into upgraded mode when it sees the ``Upgrade``
    header and buffers any trailing bytes in ``_message_tail``. If the
    handler declines the upgrade, ``finish_response()`` must replay the
    tail through the parser so the pipelined request is dispatched
    instead of stalling until the keep-alive timeout fires.
    """

    async def upgrade_handler(request: web.Request) -> NoReturn:
        raise web.HTTPUpgradeRequired()

    async def second_handler(request: web.Request) -> web.Response:
        return web.Response(text="second-ok")

    app = web.Application()
    app.router.add_route("GET", "/", upgrade_handler)
    app.router.add_route("GET", "/second", second_handler)
    server = await aiohttp_server(app)

    # Need to use a raw writer in order to send the pipelined request.
    reader, writer = await asyncio.open_connection(server.host, server.port)
    try:
        writer.write(
            b"GET / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            b"Sec-WebSocket-Version: 13\r\n"
            b"\r\n"
            b"GET /second HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"\r\n"
        )
        await writer.drain()

        # Without the fix the second request is dropped and this read hangs
        data = await asyncio.wait_for(reader.readuntil(b"second-ok"), timeout=5)
    finally:
        writer.close()
        await writer.wait_closed()

    assert b"426" in data


async def test_stashed_frames_survive_connection_loss(
    unused_port_socket: socket.socket,
) -> None:
    """Frames stashed by receive-queue backpressure outlive the connection.

    A peer can pack far more complete frames into one read than the queue's
    high-water mark allows, so the parser stops part-way and leaves the rest
    in its tail. ``connection_lost()`` then drops the protocol's reference to
    the parser, so only ``WebSocketResponse._parser`` keeps it alive; without
    that the queue's weak link dies with the connection and every stashed
    frame is silently lost.
    """
    sent = 8000
    # (frames queued when the parser stalled, frames delivered in total)
    received: asyncio.Future[tuple[int, int]] = (
        asyncio.get_running_loop().create_future()
    )

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        try:
            queue = ws._reader
            assert queue is not None

            # Wait for the parser to stall with frames still stashed in its
            # tail. The transport is paused from here, so the peer's FIN
            # cannot be observed until reading resumes.
            for _ in range(1000):  # pragma: no branch
                if queue._stalled_reader is not None:
                    break
                await asyncio.sleep(0.01)
            assert queue._stalled_reader is not None, "parser never stalled"
            stalled = len(queue._buffer)

            # Tear the connection down for real: closing the transport is
            # what drives connection_lost(), which drops the protocol's only
            # reference to the parser, leaving ws._parser holding it.
            protocol = request.protocol
            transport = protocol.transport
            assert transport is not None
            transport.close()
            for _ in range(1000):  # pragma: no branch
                if protocol._payload_parser is None:
                    break
                await asyncio.sleep(0)
            assert protocol._payload_parser is None, "connection_lost never ran"

            count = 0
            while (msg := await ws.receive()).type is WSMsgType.TEXT:
                count += 1
            # A clean drain ends with the queue's close, not an error.
            assert msg.type is WSMsgType.CLOSED

            received.set_result((stalled, count))
        except Exception as exc:  # pragma: no cover
            # Surface handler failures instead of an opaque timeout.
            received.set_exception(exc)
            raise
        return ws

    # A plain AppRunner, not the aiohttp_server fixture: TestServer forces
    # handler_cancellation=True, which kills the handler on connection loss.
    # Production defaults to False, and that is the case where the stash
    # still has to be drainable.
    app = web.Application()
    app.router.add_route("GET", "/ws", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    try:
        await web.SockSite(runner, unused_port_socket).start()
        port = unused_port_socket.getsockname()[1]

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(_RAW_UPGRADE)
            await writer.drain()
            await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)

            # Written as one call, but whether it arrives as one read is the
            # kernel's choice.
            writer.write(b"\x81\x80\x00\x00\x00\x00" * sent)
            await writer.drain()

            stalled, count = await asyncio.wait_for(received, timeout=10)
            assert stalled < count <= sent
        finally:
            writer.close()
            with contextlib.suppress(ConnectionResetError):
                await writer.wait_closed()
    finally:
        await runner.cleanup()


async def test_partial_pipelined_request_after_failed_websocket_upgrade(
    aiohttp_server: AiohttpServer,
) -> None:
    """Partial pipelined bytes are preserved across finish_response.

    Only part of the second request rides along with the upgrade, so
    feed_data() in finish_response() returns no messages and the parser
    keeps the partial bytes in its internal buffer. When the remainder
    arrives via data_received() the request is completed and dispatched.
    """

    async def upgrade_handler(request: web.Request) -> NoReturn:
        raise web.HTTPUpgradeRequired()

    async def second_handler(request: web.Request) -> web.Response:
        return web.Response(text="second-ok")

    app = web.Application()
    app.router.add_route("GET", "/", upgrade_handler)
    app.router.add_route("GET", "/second", second_handler)
    server = await aiohttp_server(app)

    reader, writer = await asyncio.open_connection(server.host, server.port)
    try:
        writer.write(
            b"GET / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            b"Sec-WebSocket-Version: 13\r\n"
            b"\r\n"
            b"GET /second HTT"  # truncated mid-request
        )
        await writer.drain()

        first = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
        assert b"426" in first

        writer.write(b"P/1.1\r\nHost: localhost\r\n\r\n")
        await writer.drain()

        await asyncio.wait_for(reader.readuntil(b"second-ok"), timeout=5)
    finally:
        writer.close()
        await writer.wait_closed()


def _raw_get(path: str) -> bytes:
    return f"GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode("ascii")


_RAW_UPGRADE = (
    b"GET /ws HTTP/1.1\r\n"
    b"Host: localhost\r\n"
    b"Upgrade: websocket\r\n"
    b"Connection: Upgrade\r\n"
    b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    b"Sec-WebSocket-Version: 13\r\n"
    b"\r\n"
)


def _masked_text_frame(payload: bytes) -> bytes:
    """Build a client text frame; frames sent to a server must be masked."""
    assert len(payload) < 126
    mask = b"\x37\xfa\x21\x3d"
    return (
        b"\x81"
        + bytes((0x80 | len(payload),))
        + mask
        + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    )


async def test_websocket_frames_pipelined_behind_request_burst(
    aiohttp_server: AiohttpServer,
) -> None:
    """A websocket upgraded from within a request burst still reads frames.

    The parser stops at the upgrade request and buffers everything after it,
    which is websocket data once the handshake succeeds. Answering the requests
    queued ahead of the upgrade must neither consume that buffer as HTTP nor
    leave the transport paused by the pipeline queue after switching protocols.
    """
    # More than the queue holds, so reading pauses and the parser buffers.
    pipelined_requests = MAX_MSG_QUEUE_SIZE + 8
    handled: list[str] = []

    async def handler(request: web.Request) -> web.Response:
        handled.append(request.path)
        return web.Response()

    async def ws_handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.send_str(await ws.receive_str())
        return ws

    app = web.Application()
    app.router.add_get("/ws", ws_handler)
    app.router.add_get("/{tail:.*}", handler)
    server = await aiohttp_server(app)

    reader, writer = await asyncio.open_connection(server.host, server.port)
    try:
        writer.write(
            b"".join(_raw_get(f"/r{i}") for i in range(pipelined_requests))
            + _RAW_UPGRADE
            + _masked_text_frame(b"frame-ok")
        )
        await writer.drain()

        # Without the fix the frame is eaten by the http parser and the paused
        # transport is never resumed, so nothing is echoed back.
        await asyncio.wait_for(reader.readuntil(b"\x81\x08frame-ok"), timeout=10)
    finally:
        writer.close()
        with contextlib.suppress(ConnectionResetError, BrokenPipeError):
            await writer.wait_closed()

    assert handled == [f"/r{i}" for i in range(pipelined_requests)]


async def test_pipelined_request_after_declined_upgrade_behind_burst(
    aiohttp_server: AiohttpServer,
) -> None:
    """A declined upgrade replays its tail even when queued behind a request.

    Only the upgrade request's own response settles whether the buffered bytes
    are websocket data or pipelined HTTP, so an earlier request completing must
    leave them alone and the declining response still has to replay them.
    """
    handled: list[str] = []

    async def handler(request: web.Request) -> web.Response:
        handled.append(request.path)
        return web.Response(text=f"{request.path[1:]}-ok")

    async def ws_handler(request: web.Request) -> NoReturn:
        raise web.HTTPUpgradeRequired()

    app = web.Application()
    app.router.add_get("/ws", ws_handler)
    app.router.add_get("/{tail:.*}", handler)
    server = await aiohttp_server(app)

    reader, writer = await asyncio.open_connection(server.host, server.port)
    try:
        writer.write(_raw_get("/first") + _RAW_UPGRADE + _raw_get("/second"))
        await writer.drain()

        # Without the replay the trailing request stalls until keep-alive expires.
        data = await asyncio.wait_for(reader.readuntil(b"second-ok"), timeout=10)
    finally:
        writer.close()
        with contextlib.suppress(ConnectionResetError, BrokenPipeError):
            await writer.wait_closed()

    assert handled == ["/first", "/second"]
    assert data.count(b"HTTP/1.1 200 OK") == 2, data
    assert b"426" in data, data


async def test_pipelined_request_after_two_declined_upgrades(
    aiohttp_server: AiohttpServer,
) -> None:
    """A second upgrade inside a replayed tail buffers its own remainder again.

    Replaying a declined upgrade's tail can turn up another upgrade request,
    which puts the parser back into upgraded mode. Losing that leaves the bytes
    behind the second upgrade buffered with nothing left to replay them.
    """
    handled: list[str] = []

    async def handler(request: web.Request) -> web.Response:
        handled.append(request.path)
        return web.Response(text="second-ok")

    async def ws_handler(request: web.Request) -> NoReturn:
        raise web.HTTPUpgradeRequired()

    app = web.Application()
    app.router.add_get("/ws", ws_handler)
    app.router.add_get("/{tail:.*}", handler)
    server = await aiohttp_server(app)

    reader, writer = await asyncio.open_connection(server.host, server.port)
    try:
        writer.write(_RAW_UPGRADE + _RAW_UPGRADE + _raw_get("/second"))
        await writer.drain()

        data = await asyncio.wait_for(reader.readuntil(b"second-ok"), timeout=10)
    finally:
        writer.close()
        with contextlib.suppress(ConnectionResetError, BrokenPipeError):
            await writer.wait_closed()

    assert handled == ["/second"]
    assert data.count(b"HTTP/1.1 426 ") == 2, data


async def test_handshake_connection_header_substring_not_a_token(
    aiohttp_client: AiohttpClient,
) -> None:
    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    resp = await client.get(
        "/",
        headers={
            "Upgrade": "websocket",
            "Connection": "keep-alive, notupgrade",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version": "13",
        },
    )
    assert resp.status == 400


async def test_websocket_json(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        assert ws.can_prepare(request)

        await ws.prepare(request)
        msg = await ws.receive()

        assert msg.type is WSMsgType.TEXT
        msg_json = msg.json()
        answer = msg_json["test"]
        await ws.send_str(answer)

        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect("/")
    expected_value = "value"
    payload = '{"test": "%s"}' % expected_value
    await ws.send_str(payload)

    resp = await ws.receive()
    assert resp.data == expected_value

    await ws.receive()  # Handle close


async def test_websocket_json_invalid_message(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        with pytest.raises(ValueError):
            await ws.receive_json()
        await ws.send_str("ValueError was raised")
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect("/")
    payload = "NOT A VALID JSON STRING"
    await ws.send_str(payload)

    data = await ws.receive_str()
    assert "ValueError was raised" in data

    await ws.receive()  # Handle close


async def test_websocket_send_json(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        data = await ws.receive_json()
        await ws.send_json(data)

        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect("/")
    expected_value = "value"
    await ws.send_json({"test": expected_value})

    data = await ws.receive_json()
    assert data["test"] == expected_value

    await ws.receive()  # Handle close


async def test_websocket_receive_json(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        data = await ws.receive_json()
        answer = data["test"]
        await ws.send_str(answer)

        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect("/")
    expected_value = "value"
    payload = '{"test": "%s"}' % expected_value
    await ws.send_str(payload)

    resp = await ws.receive()
    assert resp.data == expected_value

    await ws.receive()  # Handle close


async def test_send_recv_text(aiohttp_client: AiohttpClient) -> None:
    closed = asyncio.get_running_loop().create_future()

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        msg = await ws.receive_str()
        await ws.send_str(msg + "/answer")
        await ws.close()
        closed.set_result(1)
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect("/")
    await ws.send_str("ask")
    msg = await ws.receive()
    assert msg.type == aiohttp.WSMsgType.TEXT
    assert "ask/answer" == msg.data

    msg = await ws.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE
    assert msg.data == WSCloseCode.OK
    assert msg.extra == ""

    assert ws.closed
    assert ws.close_code == WSCloseCode.OK

    await closed


async def test_send_recv_bytes(aiohttp_client: AiohttpClient) -> None:
    closed = asyncio.get_running_loop().create_future()

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        msg = await ws.receive_bytes()
        await ws.send_bytes(msg + b"/answer")
        await ws.close()
        closed.set_result(1)
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect("/")
    await ws.send_bytes(b"ask")
    msg = await ws.receive()
    assert msg.type == aiohttp.WSMsgType.BINARY
    assert b"ask/answer" == msg.data

    msg = await ws.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE
    assert msg.data == WSCloseCode.OK
    assert msg.extra == ""

    assert ws.closed
    assert ws.close_code == WSCloseCode.OK

    await closed


async def test_send_recv_json(aiohttp_client: AiohttpClient) -> None:
    closed = asyncio.get_running_loop().create_future()

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        data = await ws.receive_json()
        await ws.send_json({"response": data["request"]})
        await ws.close()
        closed.set_result(1)
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect("/")

    await ws.send_str('{"request": "test"}')
    msg = await ws.receive()
    assert msg.type is WSMsgType.TEXT
    data = msg.json()
    assert msg.type == aiohttp.WSMsgType.TEXT
    assert data["response"] == "test"

    msg = await ws.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE
    assert msg.data == WSCloseCode.OK
    assert msg.extra == ""

    await ws.close()

    await closed


async def test_close_timeout(aiohttp_client: AiohttpClient) -> None:
    aborted = asyncio.get_running_loop().create_future()
    elapsed = 1e10  # something big

    async def handler(request: web.Request) -> web.WebSocketResponse:
        nonlocal elapsed
        ws = web.WebSocketResponse(timeout=0.1)
        await ws.prepare(request)
        assert "request" == (await ws.receive_str())
        await ws.send_str("reply")
        assert ws._loop is not None
        begin = ws._loop.time()
        assert await ws.close()
        elapsed = ws._loop.time() - begin
        assert ws.close_code == WSCloseCode.ABNORMAL_CLOSURE
        assert isinstance(ws.exception(), asyncio.TimeoutError)
        aborted.set_result(1)
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect("/")
    await ws.send_str("request")
    assert "reply" == (await ws.receive_str())

    # The server closes here.  Then the client sends bogus messages with an
    # interval shorter than server-side close timeout, to make the server
    # hanging indefinitely.
    await asyncio.sleep(0.08)
    msg = await ws._reader.read()
    assert msg.type == WSMsgType.CLOSE

    await asyncio.sleep(0.08)
    assert await aborted

    assert elapsed < 0.25, "close() should have returned before at most 2x timeout."

    await ws.close()


async def test_concurrent_close(aiohttp_client: AiohttpClient) -> None:
    srv_ws = None

    async def handler(request: web.Request) -> web.WebSocketResponse:
        nonlocal srv_ws
        ws = srv_ws = web.WebSocketResponse(autoclose=False, protocols=("foo", "bar"))
        await ws.prepare(request)

        msg = await ws.receive()
        assert msg.type == WSMsgType.CLOSING

        await asyncio.sleep(0)

        msg = await ws.receive()
        assert msg.type == WSMsgType.CLOSED

        return ws

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect("/", autoclose=False, protocols=("eggs", "bar"))

    assert srv_ws is not None
    await srv_ws.close(code=WSCloseCode.INVALID_TEXT)

    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSE

    await asyncio.sleep(0)
    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSED


async def test_concurrent_close_multiple_tasks(aiohttp_client: AiohttpClient) -> None:
    srv_ws = None

    async def handler(request: web.Request) -> web.WebSocketResponse:
        nonlocal srv_ws
        ws = srv_ws = web.WebSocketResponse(autoclose=False, protocols=("foo", "bar"))
        await ws.prepare(request)

        msg = await ws.receive()
        assert msg.type == WSMsgType.CLOSING

        await asyncio.sleep(0)

        msg = await ws.receive()
        assert msg.type == WSMsgType.CLOSED

        return ws

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect("/", autoclose=False, protocols=("eggs", "bar"))

    assert srv_ws is not None
    task1 = asyncio.create_task(srv_ws.close(code=WSCloseCode.INVALID_TEXT))
    task2 = asyncio.create_task(srv_ws.close(code=WSCloseCode.INVALID_TEXT))

    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSE

    await task1
    await task2

    await asyncio.sleep(0)
    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSED


async def test_close_op_code_from_client(aiohttp_client: AiohttpClient) -> None:
    srv_ws: web.WebSocketResponse | None = None

    async def handler(request: web.Request) -> web.WebSocketResponse:
        nonlocal srv_ws
        ws = srv_ws = web.WebSocketResponse(protocols=("foo", "bar"))
        await ws.prepare(request)

        msg = await ws.receive()
        assert msg.type == WSMsgType.CLOSE
        await asyncio.sleep(0)
        return ws

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect("/", protocols=("eggs", "bar"))

    await ws._writer.send_frame(b"", WSMsgType.CLOSE)

    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSE

    await asyncio.sleep(0)
    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSED


async def test_auto_pong_with_closing_by_peer(aiohttp_client: AiohttpClient) -> None:
    closed = asyncio.get_running_loop().create_future()

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.receive()

        msg = await ws.receive()
        assert msg.type == WSMsgType.CLOSE
        assert msg.data == WSCloseCode.OK
        assert msg.extra == "exit message"
        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect("/", autoclose=False, autoping=False)
    await ws.ping()
    await ws.send_str("ask")

    msg = await ws.receive()
    assert msg.type == WSMsgType.PONG
    await ws.close(code=WSCloseCode.OK, message=b"exit message")
    await closed


async def test_ping(aiohttp_client: AiohttpClient) -> None:
    closed = asyncio.get_running_loop().create_future()

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        await ws.ping(b"data")
        await ws.receive()
        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect("/", autoping=False)

    msg = await ws.receive()
    assert msg.type == WSMsgType.PING
    assert msg.data == b"data"
    await ws.pong()
    await ws.close()
    await closed


async def test_client_ping(aiohttp_client: AiohttpClient) -> None:
    closed = asyncio.get_running_loop().create_future()

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        await ws.receive()
        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect("/", autoping=False)

    await ws.ping(b"data")
    msg = await ws.receive()
    assert msg.type == WSMsgType.PONG
    assert msg.data == b"data"
    await ws.pong()
    await ws.close()


async def test_pong(aiohttp_client: AiohttpClient) -> None:
    closed = asyncio.get_running_loop().create_future()

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(autoping=False)
        await ws.prepare(request)

        msg = await ws.receive()
        assert msg.type == WSMsgType.PING
        await ws.pong(b"data")

        msg = await ws.receive()
        assert msg.type == WSMsgType.CLOSE
        assert msg.data == WSCloseCode.OK
        assert msg.extra == "exit message"
        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect("/", autoping=False)

    await ws.ping(b"data")
    msg = await ws.receive()
    assert msg.type == WSMsgType.PONG
    assert msg.data == b"data"

    await ws.close(code=WSCloseCode.OK, message=b"exit message")

    await closed


async def test_change_status(aiohttp_client: AiohttpClient) -> None:
    closed = asyncio.get_running_loop().create_future()

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        ws.set_status(200)
        assert 200 == ws.status
        await ws.prepare(request)
        assert 101 == ws.status
        await ws.close()
        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect("/", autoping=False)

    await ws.close()
    await closed
    await ws.close()


async def test_handle_protocol(aiohttp_client: AiohttpClient) -> None:
    closed = asyncio.get_running_loop().create_future()

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(protocols=("foo", "bar"))
        await ws.prepare(request)
        await ws.close()
        assert "bar" == ws.ws_protocol
        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect("/", protocols=("eggs", "bar"))

    await ws.close()
    await closed


async def test_server_close_handshake(aiohttp_client: AiohttpClient) -> None:
    closed = asyncio.get_running_loop().create_future()

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(protocols=("foo", "bar"))
        await ws.prepare(request)
        await ws.close()
        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect("/", autoclose=False, protocols=("eggs", "bar"))

    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSE
    await ws.close()
    await closed


async def test_client_close_handshake(aiohttp_client: AiohttpClient) -> None:
    closed = asyncio.get_running_loop().create_future()

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(autoclose=False, protocols=("foo", "bar"))
        await ws.prepare(request)

        msg = await ws.receive()
        assert msg.type == WSMsgType.CLOSE
        assert not ws.closed
        await ws.close()
        assert ws.closed
        assert ws.close_code == WSCloseCode.INVALID_TEXT  # type: ignore[unreachable]

        msg = await ws.receive()
        assert msg.type == WSMsgType.CLOSED

        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect("/", autoclose=False, protocols=("eggs", "bar"))

    await ws.close(code=WSCloseCode.INVALID_TEXT)
    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSED
    await closed


async def test_server_close_handshake_server_eats_client_messages(
    aiohttp_client: AiohttpClient,
) -> None:
    closed = asyncio.get_running_loop().create_future()

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(protocols=("foo", "bar"))
        await ws.prepare(request)
        await ws.close()
        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect(
        "/", autoclose=False, autoping=False, protocols=("eggs", "bar")
    )

    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSE

    await ws.send_str("text")
    await ws.send_bytes(b"bytes")
    await ws.ping()

    await ws.close()
    await closed


async def test_receive_timeout(aiohttp_client: AiohttpClient) -> None:
    raised = False

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(receive_timeout=0.1)
        await ws.prepare(request)

        try:
            await ws.receive()
        except asyncio.TimeoutError:
            nonlocal raised
            raised = True

        await ws.close()
        return ws

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect("/")
    await ws.receive()
    await ws.close()
    assert raised


async def test_custom_receive_timeout(aiohttp_client: AiohttpClient) -> None:
    raised = False

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(receive_timeout=None)
        await ws.prepare(request)

        try:
            await ws.receive(0.1)
        except asyncio.TimeoutError:
            nonlocal raised
            raised = True

        await ws.close()
        return ws

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect("/")
    await ws.receive()
    await ws.close()
    assert raised


async def test_heartbeat(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(heartbeat=0.05)
        await ws.prepare(request)
        await ws.receive()
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_get("/", handler)

    client = await aiohttp_client(app)
    ws = await client.ws_connect("/", autoping=False)
    msg = await ws.receive()

    assert msg.type == aiohttp.WSMsgType.PING

    await ws.close()


async def test_heartbeat_no_pong(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(heartbeat=0.05)
        await ws.prepare(request)

        await ws.receive()
        return ws

    app = web.Application()
    app.router.add_get("/", handler)

    client = await aiohttp_client(app)
    ws = await client.ws_connect("/", autoping=False)
    msg = await ws.receive()
    assert msg.type == aiohttp.WSMsgType.PING
    await ws.close()


async def test_heartbeat_connection_closed(aiohttp_client: AiohttpClient) -> None:
    """Test that the connection is closed while ping is in progress."""
    ping_count = 0

    async def handler(request: web.Request) -> NoReturn:
        nonlocal ping_count
        ws_server = web.WebSocketResponse(heartbeat=0.05)
        await ws_server.prepare(request)
        # We patch write here to simulate a connection reset error
        # since if we closed the connection normally, the server would
        # would cancel the heartbeat task and we wouldn't get a ping
        assert ws_server._req is not None
        assert ws_server._writer is not None
        with (
            mock.patch.object(
                ws_server._req.transport, "write", side_effect=ConnectionResetError
            ),
            mock.patch.object(
                ws_server._writer, "send_frame", wraps=ws_server._writer.send_frame
            ) as send_frame,
        ):
            try:
                await ws_server.receive()
            finally:
                ping_count = send_frame.call_args_list.count(
                    mock.call(b"", WSMsgType.PING)
                )
        assert False

    app = web.Application()
    app.router.add_get("/", handler)

    client = await aiohttp_client(app)
    ws = await client.ws_connect("/", autoping=False)
    msg = await ws.receive()
    assert msg.type is aiohttp.WSMsgType.CLOSED
    assert msg.extra is None
    assert ws.close_code == WSCloseCode.ABNORMAL_CLOSURE
    assert ping_count == 1
    await ws.close()


async def test_heartbeat_failure_ends_receive(aiohttp_client: AiohttpClient) -> None:
    """Test that no heartbeat response to the server ends the receive call."""
    ws_server_close_code = None
    ws_server_exception = None

    async def handler(request: web.Request) -> NoReturn:
        nonlocal ws_server_close_code, ws_server_exception
        ws_server = web.WebSocketResponse(heartbeat=0.05)
        await ws_server.prepare(request)
        try:
            await ws_server.receive()
        finally:
            ws_server_close_code = ws_server.close_code
            ws_server_exception = ws_server.exception()
        assert False

    app = web.Application()
    app.router.add_get("/", handler)

    client = await aiohttp_client(app)
    ws = await client.ws_connect("/", autoping=False)
    msg = await ws.receive()
    assert msg.type is aiohttp.WSMsgType.PING
    msg = await ws.receive()
    assert msg.type is aiohttp.WSMsgType.CLOSED
    assert ws.close_code == WSCloseCode.ABNORMAL_CLOSURE
    assert ws_server_close_code == WSCloseCode.ABNORMAL_CLOSURE
    assert isinstance(ws_server_exception, asyncio.TimeoutError)
    assert str(ws_server_exception) == "No PONG received after 0.025 seconds"
    await ws.close()


async def test_heartbeat_no_pong_send_many_messages(
    aiohttp_client: AiohttpClient,
) -> None:
    """Test no pong after sending many messages."""

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(heartbeat=0.05)
        await ws.prepare(request)
        for _ in range(10):
            await ws.send_str("test")

        await ws.receive()
        return ws

    app = web.Application()
    app.router.add_get("/", handler)

    client = await aiohttp_client(app)
    ws = await client.ws_connect("/", autoping=False)
    for _ in range(10):
        msg = await ws.receive()
        assert msg.type is aiohttp.WSMsgType.TEXT
        assert msg.data == "test"

    msg = await ws.receive()
    assert msg.type is aiohttp.WSMsgType.PING
    await ws.close()


async def test_heartbeat_no_pong_receive_many_messages(
    aiohttp_client: AiohttpClient,
) -> None:
    """Test no pong after receiving many messages."""

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(heartbeat=0.05)
        await ws.prepare(request)
        for _ in range(10):
            server_msg = await ws.receive()
            assert server_msg.type is aiohttp.WSMsgType.TEXT

        await ws.receive()
        return ws

    app = web.Application()
    app.router.add_get("/", handler)

    client = await aiohttp_client(app)
    ws = await client.ws_connect("/", autoping=False)
    for _ in range(10):
        await ws.send_str("test")

    msg = await ws.receive()
    assert msg.type is aiohttp.WSMsgType.PING
    await ws.close()


async def test_server_ws_async_for(aiohttp_server: AiohttpServer) -> None:
    closed = asyncio.get_running_loop().create_future()

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        async for msg in ws:
            assert msg.type == aiohttp.WSMsgType.TEXT
            s = msg.data
            await ws.send_str(s + "/answer")
        await ws.close()
        closed.set_result(1)
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    server = await aiohttp_server(app)

    async with aiohttp.ClientSession() as sm:
        async with sm.ws_connect(server.make_url("/")) as resp:
            items = ["q1", "q2", "q3"]
            for item in items:
                await resp.send_str(item)
                msg = await resp.receive()
                assert msg.type == aiohttp.WSMsgType.TEXT
                assert item + "/answer" == msg.data

            await resp.close()
            await closed


async def test_closed_async_for(aiohttp_client: AiohttpClient) -> None:
    closed = asyncio.get_running_loop().create_future()

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        messages = []
        async for msg in ws:
            messages.append(msg)
            assert "stop" == msg.data
            await ws.send_str("stopping")
            await ws.close()

        assert 1 == len(messages)
        assert messages[0].type == WSMsgType.TEXT
        assert messages[0].data == "stop"

        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect("/")
    await ws.send_str("stop")
    msg = await ws.receive()
    assert msg.type == WSMsgType.TEXT
    assert msg.data == "stopping"

    await ws.close()
    await closed


async def test_websocket_disable_keepalive(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.StreamResponse:
        ws = web.WebSocketResponse()
        if not ws.can_prepare(request):
            return web.Response(text="OK")
        assert request.protocol._keepalive
        await ws.prepare(request)
        assert not request.protocol._keepalive
        assert not request.protocol._keepalive_handle  # type: ignore[unreachable]

        await ws.send_str("OK")
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    resp = await client.get("/")
    txt = await resp.text()
    assert txt == "OK"

    ws = await client.ws_connect("/")
    data = await ws.receive_str()
    assert data == "OK"

    await ws.receive()  # Handle close


async def test_receive_str_nonstring(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        assert ws.can_prepare(request)

        await ws.prepare(request)
        await ws.send_bytes(b"answer")
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect("/")
    with pytest.raises(TypeError):
        await ws.receive_str()

    await ws.receive()  # Handle close


async def test_receive_bytes_nonbytes(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> NoReturn:
        ws = web.WebSocketResponse()
        assert ws.can_prepare(request)

        await ws.prepare(request)
        await ws.send_str("answer")
        assert False

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect("/")
    with pytest.raises(TypeError):
        await ws.receive_bytes()


async def test_bug3380(aiohttp_client: AiohttpClient) -> None:
    async def handle_null(request: web.Request) -> web.Response:
        return web.json_response({"err": None})

    async def ws_handler(request: web.Request) -> web.Response:
        return web.Response(status=401)

    app = web.Application()
    app.router.add_route("GET", "/ws", ws_handler)
    app.router.add_route("GET", "/api/null", handle_null)

    client = await aiohttp_client(app)

    resp = await client.get("/api/null")
    assert (await resp.json()) == {"err": None}
    resp.close()

    with pytest.raises(WSServerHandshakeError):
        await client.ws_connect("/ws")

    resp = await client.get("/api/null", timeout=aiohttp.ClientTimeout(total=1))
    assert (await resp.json()) == {"err": None}
    resp.close()


async def test_receive_being_cancelled_keeps_connection_open(
    aiohttp_client: AiohttpClient,
) -> None:
    closed = asyncio.get_running_loop().create_future()

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(autoping=False)
        await ws.prepare(request)

        task = asyncio.create_task(ws.receive())
        await asyncio.sleep(0)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

        msg = await ws.receive()
        assert msg.type == WSMsgType.PING
        await asyncio.sleep(0)
        await ws.pong(b"data")

        msg = await ws.receive()
        assert msg.type == WSMsgType.CLOSE
        assert msg.data == WSCloseCode.OK
        assert msg.extra == "exit message"
        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect("/", autoping=False)

    await asyncio.sleep(0)
    await ws.ping(b"data")

    msg = await ws.receive()
    assert msg.type == WSMsgType.PONG
    assert msg.data == b"data"

    await ws.close(code=WSCloseCode.OK, message=b"exit message")

    await closed


async def test_receive_timeout_keeps_connection_open(
    aiohttp_client: AiohttpClient,
) -> None:
    loop = asyncio.get_running_loop()
    closed = loop.create_future()
    timed_out = loop.create_future()

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(autoping=False)
        await ws.prepare(request)

        task = asyncio.create_task(ws.receive(sys.float_info.min))
        with contextlib.suppress(asyncio.TimeoutError):
            await task

        timed_out.set_result(None)

        msg = await ws.receive()
        assert msg.type == WSMsgType.PING
        await asyncio.sleep(0)
        await ws.pong(b"data")

        msg = await ws.receive()
        assert msg.type == WSMsgType.CLOSE
        assert msg.data == WSCloseCode.OK
        assert msg.extra == "exit message"
        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect("/", autoping=False)

    await timed_out
    await ws.ping(b"data")

    msg = await ws.receive()
    assert msg.type == WSMsgType.PONG
    assert msg.data == b"data"

    await ws.close(code=WSCloseCode.OK, message=b"exit message")

    await closed


async def test_websocket_shutdown(aiohttp_client: AiohttpClient) -> None:
    """Test that the client websocket gets the close message when the server is shutting down."""
    url = "/ws"
    app = web.Application()
    websockets = web.AppKey("websockets", weakref.WeakSet[web.WebSocketResponse])
    app[websockets] = weakref.WeakSet()

    # need for send signal shutdown server
    shutdown_websockets = web.AppKey(
        "shutdown_websockets", weakref.WeakSet[web.WebSocketResponse]
    )
    app[shutdown_websockets] = weakref.WeakSet()

    async def websocket_handler(request: web.Request) -> web.WebSocketResponse:
        websocket = web.WebSocketResponse()
        await websocket.prepare(request)
        request.app[websockets].add(websocket)
        request.app[shutdown_websockets].add(websocket)

        try:
            async for message in websocket:
                assert message.type is WSMsgType.TEXT
                await websocket.send_json({"ok": True, "message": message.json()})
        finally:
            request.app[websockets].discard(websocket)

        return websocket

    async def on_shutdown(app: web.Application) -> None:
        while app[shutdown_websockets]:
            websocket = app[shutdown_websockets].pop()
            await websocket.close(
                code=aiohttp.WSCloseCode.GOING_AWAY,
                message=b"Server shutdown",
            )

    app.router.add_get(url, websocket_handler)
    app.on_shutdown.append(on_shutdown)

    client = await aiohttp_client(app)

    websocket = await client.ws_connect(url)

    message = {"message": "hi"}
    await websocket.send_json(message)
    reply = await websocket.receive_json()
    assert reply == {"ok": True, "message": message}

    await app.shutdown()

    assert websocket.closed is False

    reply = await websocket.receive()

    assert reply.type is aiohttp.http.WSMsgType.CLOSE
    assert reply.data == aiohttp.WSCloseCode.GOING_AWAY
    assert reply.extra == "Server shutdown"

    assert websocket.closed is True


async def test_ws_close_return_code(aiohttp_client: AiohttpClient) -> None:
    """Test that the close code is returned when the server closes the connection."""

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
    await resp.send_str("some data")
    msg = await resp.receive()
    assert msg.type is aiohttp.WSMsgType.CLOSE
    assert resp.close_code == WSCloseCode.OK


async def test_abnormal_closure_when_server_does_not_receive(
    aiohttp_client: AiohttpClient,
) -> None:
    """Test abnormal closure when the server closes and a message is pending."""

    async def handler(request: web.Request) -> web.WebSocketResponse:
        # Setting close timeout to 0, otherwise the server waits for a
        # close response for 10 seconds by default.
        # This would make the client's autoclose in resp.receive() to succeed,
        # closing the connection cleanly from both sides.
        ws = web.WebSocketResponse(timeout=0)
        await ws.prepare(request)
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect("/")
    await resp.send_str("some data")
    await asyncio.sleep(0.1)
    msg = await resp.receive()
    assert msg.type is aiohttp.WSMsgType.CLOSE
    assert resp.close_code == WSCloseCode.ABNORMAL_CLOSURE


async def test_abnormal_closure_when_client_does_not_close(
    aiohttp_client: AiohttpClient,
) -> None:
    """Test abnormal closure when the server closes and the client doesn't respond."""
    close_code: WSCloseCode | None = None

    async def handler(request: web.Request) -> web.WebSocketResponse:
        # Setting a short close timeout
        ws = web.WebSocketResponse(timeout=0.1)
        await ws.prepare(request)
        await ws.close()

        nonlocal close_code
        assert ws.close_code is not None
        close_code = WSCloseCode(ws.close_code)

        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    async with client.ws_connect("/", autoclose=False):
        await asyncio.sleep(0.2)
    await client.server.close()
    assert close_code == WSCloseCode.ABNORMAL_CLOSURE


async def test_normal_closure_while_client_sends_msg(
    aiohttp_client: AiohttpClient,
) -> None:
    """Test normal closure when the server closes and the client responds properly."""
    close_code: WSCloseCode | None = None
    got_close_code = asyncio.Event()

    async def handler(request: web.Request) -> web.WebSocketResponse:
        # Setting a longer close timeout to avoid race conditions
        ws = web.WebSocketResponse(timeout=1.0)
        await ws.prepare(request)
        await ws.close()

        nonlocal close_code
        assert ws.close_code is not None
        close_code = WSCloseCode(ws.close_code)
        got_close_code.set()

        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    async with client.ws_connect("/", autoclose=False) as ws:
        # send text and close message during server close timeout
        await asyncio.sleep(0.1)
        await ws.send_str("Hello")
        await ws.close()
    # wait for close code to be received by server
    await asyncio.wait(
        [
            asyncio.create_task(asyncio.sleep(0.5)),
            asyncio.create_task(got_close_code.wait()),
        ],
        return_when=asyncio.FIRST_COMPLETED,
    )
    await client.server.close()
    assert close_code == WSCloseCode.OK


async def test_websocket_prepare_timeout_close_issue(
    aiohttp_client: AiohttpClient,
) -> None:
    """Test that WebSocket can handle prepare with early returns.

    This is a regression test for issue #6009 where the prepared property
    incorrectly checked _payload_writer instead of _writer.
    """

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        assert ws.can_prepare(request)
        await ws.prepare(request)
        await ws.send_str("test")
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/ws", handler)
    client = await aiohttp_client(app)

    # Connect via websocket
    ws = await client.ws_connect("/ws")
    msg = await ws.receive()
    assert msg.type is WSMsgType.TEXT
    assert msg.data == "test"
    await ws.close()


async def test_websocket_prepare_timeout_from_issue_reproducer(
    aiohttp_client: AiohttpClient,
) -> None:
    """Test websocket behavior when prepare is interrupted.

    This test verifies the fix for issue #6009 where close() would
    fail after prepare() was interrupted.
    """
    prepare_complete = asyncio.Event()
    close_complete = asyncio.Event()

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()

        # Prepare the websocket
        await ws.prepare(request)
        prepare_complete.set()

        # Send a message to confirm connection works
        await ws.send_str("connected")

        # Wait for client to close
        msg = await ws.receive()
        assert msg.type is WSMsgType.CLOSE
        await ws.close()
        close_complete.set()

        return ws

    app = web.Application()
    app.router.add_route("GET", "/ws", handler)
    client = await aiohttp_client(app)

    # Connect and verify the connection works
    ws = await client.ws_connect("/ws")
    await prepare_complete.wait()

    msg = await ws.receive()
    assert msg.type is WSMsgType.TEXT
    assert msg.data == "connected"

    # Close the connection
    await ws.close()
    await close_complete.wait()


async def test_websocket_prepared_property(aiohttp_client: AiohttpClient) -> None:
    """Test that WebSocketResponse.prepared property correctly reflects state."""
    prepare_called = asyncio.Event()

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()

        # Initially not prepared
        initial_state = ws.prepared
        assert not initial_state

        # After prepare() is called, should be prepared
        await ws.prepare(request)
        prepare_called.set()

        # Check prepared state
        prepared_state = ws.prepared
        assert prepared_state

        # Send a message to verify the connection works
        await ws.send_str("test")
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect("/")
    await prepare_called.wait()
    msg = await ws.receive()
    assert msg.type is WSMsgType.TEXT
    assert msg.data == "test"
    await ws.close()


async def test_receive_text_as_bytes_server_side(aiohttp_client: AiohttpClient) -> None:
    """Test server receiving TEXT messages as raw bytes with decode_text=False."""

    async def websocket_handler(
        request: web.Request,
    ) -> web.WebSocketResponse[Literal[False]]:
        ws: web.WebSocketResponse[Literal[False]] = web.WebSocketResponse(
            decode_text=False
        )
        await ws.prepare(request)

        # Receive TEXT message as bytes
        msg = await ws.receive()
        assert msg.type is aiohttp.WSMsgType.TEXT
        assert isinstance(msg.data, bytes)
        assert msg.data == b"test message"

        # Send response
        await ws.send_bytes(msg.data + b"/reply")
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", websocket_handler)
    client = await aiohttp_client(app)

    async with client.ws_connect("/") as ws:
        await ws.send_str("test message")

        msg = await ws.receive()
        assert msg.type is aiohttp.WSMsgType.BINARY
        assert msg.data == b"test message/reply"

        await ws.close()


async def test_receive_text_as_bytes_server_iteration(
    aiohttp_client: AiohttpClient,
) -> None:
    """Test server iterating over WebSocket with decode_text=False."""

    async def websocket_handler(
        request: web.Request,
    ) -> web.WebSocketResponse[Literal[False]]:
        ws: web.WebSocketResponse[Literal[False]] = web.WebSocketResponse(
            decode_text=False
        )
        await ws.prepare(request)

        async for msg in ws:
            if msg.type is aiohttp.WSMsgType.TEXT:
                # msg.data should be bytes
                assert isinstance(msg.data, bytes)
                # Echo back
                await ws.send_bytes(msg.data)
            else:
                assert msg.type is aiohttp.WSMsgType.BINARY
                assert isinstance(msg.data, bytes)
                await ws.send_bytes(msg.data)

        return ws

    app = web.Application()
    app.router.add_route("GET", "/", websocket_handler)
    client = await aiohttp_client(app)

    async with client.ws_connect("/") as ws:
        # Send TEXT message
        await ws.send_str("hello")
        msg = await ws.receive()
        assert msg.type is aiohttp.WSMsgType.BINARY
        assert msg.data == b"hello"

        # Send BINARY message
        await ws.send_bytes(b"world")
        msg = await ws.receive()
        assert msg.type is aiohttp.WSMsgType.BINARY
        assert msg.data == b"world"

        await ws.close()


async def test_server_decode_text_default_true(aiohttp_client: AiohttpClient) -> None:
    """Test that server decode_text defaults to True for backward compatibility."""

    async def websocket_handler(request: web.Request) -> web.WebSocketResponse:
        # No decode_text parameter - should default to True
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        msg = await ws.receive()
        assert msg.type is aiohttp.WSMsgType.TEXT
        assert isinstance(msg.data, str)
        assert msg.data == "test"

        await ws.send_str(msg.data + "/reply")
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", websocket_handler)
    client = await aiohttp_client(app)

    async with client.ws_connect("/") as ws:
        await ws.send_str("test")

        msg = await ws.receive()
        assert msg.type is aiohttp.WSMsgType.TEXT
        assert isinstance(msg.data, str)
        assert msg.data == "test/reply"

        await ws.close()


async def test_server_receive_str_returns_bytes_with_decode_text_false(
    aiohttp_client: AiohttpClient,
) -> None:
    """Test that server receive_str() returns bytes when decode_text=False."""

    async def websocket_handler(
        request: web.Request,
    ) -> web.WebSocketResponse[Literal[False]]:
        ws: web.WebSocketResponse[Literal[False]] = web.WebSocketResponse(
            decode_text=False
        )
        await ws.prepare(request)

        # receive_str() should return bytes when decode_text=False
        data = await ws.receive_str()
        assert isinstance(data, bytes)
        assert data == b"hello server"

        await ws.send_str("got bytes")
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", websocket_handler)
    client = await aiohttp_client(app)

    async with client.ws_connect("/") as ws:
        await ws.send_str("hello server")
        msg = await ws.receive()
        assert msg.data == "got bytes"


async def test_server_receive_str_returns_str_with_decode_text_true(
    aiohttp_client: AiohttpClient,
) -> None:
    """Test that server receive_str() returns str when decode_text=True (default)."""

    async def websocket_handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()  # decode_text=True by default
        await ws.prepare(request)

        # receive_str() should return str when decode_text=True
        data = await ws.receive_str()
        assert isinstance(data, str)
        assert data == "hello server"

        await ws.send_str("got string")
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", websocket_handler)
    client = await aiohttp_client(app)

    async with client.ws_connect("/") as ws:
        await ws.send_str("hello server")
        msg = await ws.receive()
        assert msg.data == "got string"


async def test_server_receive_json_with_orjson_style_loads(
    aiohttp_client: AiohttpClient,
) -> None:
    """Test server receive_json() with orjson-style loads that accepts bytes."""

    def orjson_style_loads(data: bytes) -> dict[str, str]:
        """Mock orjson.loads that accepts bytes."""
        assert isinstance(data, bytes)
        result: dict[str, str] = json.loads(data)
        return result

    async def websocket_handler(
        request: web.Request,
    ) -> web.WebSocketResponse[Literal[False]]:
        ws: web.WebSocketResponse[Literal[False]] = web.WebSocketResponse(
            decode_text=False
        )
        await ws.prepare(request)

        # receive_json() with orjson-style loads should work with bytes
        data = await ws.receive_json(loads=orjson_style_loads)
        assert data == {"test": "value"}

        await ws.send_str("success")
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", websocket_handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect("/")
    await ws.send_str('{"test": "value"}')
    msg = await ws.receive()
    assert msg.type is aiohttp.WSMsgType.TEXT
    assert msg.data == "success"
    await ws.close()


async def test_prepare_after_client_disconnect(aiohttp_client: AiohttpClient) -> None:
    """Test ConnectionResetError when client disconnects before ws.prepare().

    Reproduces the race condition where:
    - Client connects and sends a WebSocket upgrade request
    - Handler starts async work (e.g. authentication) before calling ws.prepare()
    - Client disconnects while the handler is busy
    - Handler then calls ws.prepare() → ConnectionResetError (not AssertionError)
    """
    handler_started = asyncio.Event()
    captured_protocol = None

    async def handler(request: web.Request) -> web.Response:
        nonlocal captured_protocol
        ws = web.WebSocketResponse()
        captured_protocol = request._protocol
        handler_started.set()
        # Simulate async work (e.g., auth check) during which client disconnects.
        await asyncio.sleep(0)
        with pytest.raises(ConnectionResetError, match="Connection lost"):
            await ws.prepare(request)
        return web.Response(status=503)

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    request_task = asyncio.create_task(
        client.session.get(
            client.make_url("/"),
            headers={
                hdrs.UPGRADE: "websocket",
                hdrs.CONNECTION: "Upgrade",
                hdrs.SEC_WEBSOCKET_KEY: "dGhlIHNhbXBsZSBub25jZQ==",
                hdrs.SEC_WEBSOCKET_VERSION: "13",
            },
        )
    )

    # Wait until the handler is running but has not yet called ws.prepare().
    await handler_started.wait()
    assert captured_protocol is not None

    # Simulate the client disconnecting abruptly.
    captured_protocol.force_close()

    # Yield so the handler can resume and hit the ConnectionResetError.
    await asyncio.sleep(0)

    with contextlib.suppress(
        aiohttp.ServerDisconnectedError, aiohttp.ClientConnectionResetError
    ):
        await request_task


async def test_stalled_parser_outlives_connection_lost(
    aiohttp_client: AiohttpClient,
) -> None:
    """Frames the parser stopped short of are delivered after the peer vanishes.

    Once the queue is over its high-water mark the parser stops mid-read and
    parks the rest of the read on itself, reachable from the queue only through
    a weak reference. Connection loss releases the protocol's reference to the
    parser, so the response has to be the owner or those frames are collected
    and the handler silently sees a short stream.
    """
    sent = 8000
    received: asyncio.Future[int] = asyncio.get_running_loop().create_future()

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        try:
            protocol = request.protocol
            transport = request.transport
            assert transport is not None
            # Empty masked client->server TEXT frames: six bytes on the wire,
            # but each one is charged MSG_SIZE_OVERHEAD in the queue, so a
            # single read crosses the high-water mark and the parser stalls
            # part way through.
            protocol.data_received(b"\x81\x80\x00\x00\x00\x00" * sent)
            queue = ws._reader
            assert queue is not None
            assert queue._stalled_reader is not None, "parser never stalled"

            # Simulate the peer vanishing: the socket is gone and the
            # protocol drops its reference to the parser, as the event loop
            # would do it. Detach the handler task first: TestServer forces
            # handler_cancellation=True (production defaults to False), and
            # the cancellation would land on this very task at its next yield.
            protocol._task_handler = None
            transport.abort()
            protocol.connection_lost(None)
            for _ in range(3):  # PyPy can need more than one pass
                gc.collect()

            count = 0
            while (await ws.receive()).type is not WSMsgType.CLOSED:
                count += 1
            # Exhausting the queue releases the parser and its stash.
            assert ws._parser is None
            received.set_result(count)
        except Exception as exc:  # pragma: no cover
            # Surface handler failures instead of an opaque timeout.
            received.set_exception(exc)
            raise
        return ws

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)
    await client.ws_connect("/")

    assert await asyncio.wait_for(received, 10) == sent
