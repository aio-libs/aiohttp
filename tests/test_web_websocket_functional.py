# HTTP websocket server functional tests

import asyncio
import contextlib
import sys
import weakref
from typing import Any, NoReturn, Optional
from unittest import mock

import pytest

import aiohttp
from aiohttp import web
from aiohttp.http import WSCloseCode, WSMsgType
from aiohttp.pytest_plugin import AiohttpClient


async def test_websocket_can_prepare(loop, aiohttp_client) -> None:
    async def handler(request):
        ws = web.WebSocketResponse()
        if not ws.can_prepare(request):
            raise web.HTTPUpgradeRequired()

        return web.Response()

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    resp = await client.get("/")
    assert resp.status == 426


async def test_websocket_json(loop, aiohttp_client) -> None:
    async def handler(request):
        ws = web.WebSocketResponse()
        if not ws.can_prepare(request):
            return web.HTTPUpgradeRequired()

        await ws.prepare(request)
        msg = await ws.receive()

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


async def test_websocket_json_invalid_message(loop, aiohttp_client) -> None:
    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        try:
            await ws.receive_json()
        except ValueError:
            await ws.send_str("ValueError was raised")
        else:
            raise Exception("No Exception")
        finally:
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


async def test_websocket_send_json(loop, aiohttp_client) -> None:
    async def handler(request):
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


async def test_websocket_receive_json(loop, aiohttp_client) -> None:
    async def handler(request):
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


async def test_send_recv_text(loop, aiohttp_client) -> None:

    closed = loop.create_future()

    async def handler(request):
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


async def test_send_recv_bytes(loop, aiohttp_client) -> None:

    closed = loop.create_future()

    async def handler(request):
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


async def test_send_recv_json(loop, aiohttp_client) -> None:
    closed = loop.create_future()

    async def handler(request):
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
    data = msg.json()
    assert msg.type == aiohttp.WSMsgType.TEXT
    assert data["response"] == "test"

    msg = await ws.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE
    assert msg.data == WSCloseCode.OK
    assert msg.extra == ""

    await ws.close()

    await closed


async def test_close_timeout(loop, aiohttp_client) -> None:
    aborted = loop.create_future()
    elapsed = 1e10  # something big

    async def handler(request):
        nonlocal elapsed
        ws = web.WebSocketResponse(timeout=0.1)
        await ws.prepare(request)
        assert "request" == (await ws.receive_str())
        await ws.send_str("reply")
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


async def test_concurrent_close(loop, aiohttp_client) -> None:

    srv_ws = None

    async def handler(request):
        nonlocal srv_ws
        ws = srv_ws = web.WebSocketResponse(autoclose=False, protocols=("foo", "bar"))
        await ws.prepare(request)

        msg = await ws.receive()
        assert msg.type == WSMsgType.CLOSING

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

    await srv_ws.close(code=WSCloseCode.INVALID_TEXT)

    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSE

    await asyncio.sleep(0)
    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSED


async def test_concurrent_close_multiple_tasks(loop: Any, aiohttp_client: Any) -> None:
    srv_ws = None

    async def handler(request):
        nonlocal srv_ws
        ws = srv_ws = web.WebSocketResponse(autoclose=False, protocols=("foo", "bar"))
        await ws.prepare(request)

        msg = await ws.receive()
        assert msg.type == WSMsgType.CLOSING

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

    task1 = asyncio.create_task(srv_ws.close(code=WSCloseCode.INVALID_TEXT))
    task2 = asyncio.create_task(srv_ws.close(code=WSCloseCode.INVALID_TEXT))

    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSE

    await task1
    await task2

    await asyncio.sleep(0)
    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSED


async def test_close_op_code_from_client(loop: Any, aiohttp_client: Any) -> None:
    srv_ws: Optional[web.WebSocketResponse] = None

    async def handler(request):
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

    ws: web.WebSocketResponse = await client.ws_connect("/", protocols=("eggs", "bar"))

    await ws._writer.send_frame(b"", WSMsgType.CLOSE)

    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSE

    await asyncio.sleep(0)
    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSED


async def test_auto_pong_with_closing_by_peer(loop: Any, aiohttp_client: Any) -> None:
    closed = loop.create_future()

    async def handler(request):
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
    await ws.close(code=WSCloseCode.OK, message="exit message")
    await closed


async def test_ping(loop, aiohttp_client) -> None:

    closed = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        await ws.ping("data")
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


async def aiohttp_client_ping(loop, aiohttp_client):

    closed = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        await ws.receive()
        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect("/", autoping=False)

    await ws.ping("data")
    msg = await ws.receive()
    assert msg.type == WSMsgType.PONG
    assert msg.data == b"data"
    await ws.pong()
    await ws.close()


async def test_pong(loop, aiohttp_client) -> None:

    closed = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse(autoping=False)
        await ws.prepare(request)

        msg = await ws.receive()
        assert msg.type == WSMsgType.PING
        await ws.pong("data")

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

    await ws.ping("data")
    msg = await ws.receive()
    assert msg.type == WSMsgType.PONG
    assert msg.data == b"data"

    await ws.close(code=WSCloseCode.OK, message="exit message")

    await closed


async def test_change_status(loop, aiohttp_client) -> None:

    closed = loop.create_future()

    async def handler(request):
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


async def test_handle_protocol(loop, aiohttp_client) -> None:

    closed = loop.create_future()

    async def handler(request):
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


async def test_server_close_handshake(loop, aiohttp_client) -> None:

    closed = loop.create_future()

    async def handler(request):
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


async def aiohttp_client_close_handshake(loop, aiohttp_client):

    closed = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse(autoclose=False, protocols=("foo", "bar"))
        await ws.prepare(request)

        msg = await ws.receive()
        assert msg.type == WSMsgType.CLOSE
        assert not ws.closed
        await ws.close()
        assert ws.closed
        assert ws.close_code == WSCloseCode.INVALID_TEXT

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


async def test_server_close_handshake_server_eats_client_messages(loop, aiohttp_client):
    closed = loop.create_future()

    async def handler(request):
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


async def test_receive_timeout(loop, aiohttp_client) -> None:
    raised = False

    async def handler(request):
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


async def test_custom_receive_timeout(loop, aiohttp_client) -> None:
    raised = False

    async def handler(request):
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


async def test_heartbeat(loop, aiohttp_client) -> None:
    async def handler(request):
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

    assert msg.type == aiohttp.WSMsgType.ping

    await ws.close()


async def test_heartbeat_no_pong(loop, aiohttp_client) -> None:
    async def handler(request):
        ws = web.WebSocketResponse(heartbeat=0.05)
        await ws.prepare(request)

        await ws.receive()
        return ws

    app = web.Application()
    app.router.add_get("/", handler)

    client = await aiohttp_client(app)
    ws = await client.ws_connect("/", autoping=False)
    msg = await ws.receive()
    assert msg.type == aiohttp.WSMsgType.ping
    await ws.close()


async def test_heartbeat_connection_closed(
    loop: asyncio.AbstractEventLoop, aiohttp_client: AiohttpClient
) -> None:
    """Test that the connection is closed while ping is in progress."""
    ping_count = 0

    async def handler(request: web.Request) -> NoReturn:
        nonlocal ping_count
        ws_server = web.WebSocketResponse(heartbeat=0.05)
        await ws_server.prepare(request)
        # We patch write here to simulate a connection reset error
        # since if we closed the connection normally, the server would
        # would cancel the heartbeat task and we wouldn't get a ping
        with mock.patch.object(
            ws_server._req.transport, "write", side_effect=ConnectionResetError
        ), mock.patch.object(
            ws_server._writer, "send_frame", wraps=ws_server._writer.send_frame
        ) as send_frame:
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


async def test_heartbeat_failure_ends_receive(
    loop: asyncio.AbstractEventLoop, aiohttp_client: AiohttpClient
) -> None:
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
    await ws.close()


async def test_heartbeat_no_pong_send_many_messages(
    loop: Any, aiohttp_client: Any
) -> None:
    """Test no pong after sending many messages."""

    async def handler(request):
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
    loop: Any, aiohttp_client: Any
) -> None:
    """Test no pong after receiving many messages."""

    async def handler(request):
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


async def test_server_ws_async_for(loop: Any, aiohttp_server: Any) -> None:
    closed = loop.create_future()

    async def handler(request):
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


async def test_closed_async_for(loop, aiohttp_client) -> None:

    closed = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        messages = []
        async for msg in ws:
            messages.append(msg)
            if "stop" == msg.data:
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


async def test_websocket_disable_keepalive(loop, aiohttp_client) -> None:
    async def handler(request):
        ws = web.WebSocketResponse()
        if not ws.can_prepare(request):
            return web.Response(text="OK")
        assert request.protocol._keepalive
        await ws.prepare(request)
        assert not request.protocol._keepalive
        assert not request.protocol._keepalive_handle

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


async def test_bug3380(loop, aiohttp_client) -> None:
    async def handle_null(request):
        return aiohttp.web.json_response({"err": None})

    async def ws_handler(request):
        return web.Response(status=401)

    app = web.Application()
    app.router.add_route("GET", "/ws", ws_handler)
    app.router.add_route("GET", "/api/null", handle_null)

    client = await aiohttp_client(app)

    resp = await client.get("/api/null")
    assert (await resp.json()) == {"err": None}
    resp.close()

    with pytest.raises(aiohttp.WSServerHandshakeError):
        await client.ws_connect("/ws")

    resp = await client.get("/api/null", timeout=1)
    assert (await resp.json()) == {"err": None}
    resp.close()


async def test_receive_being_cancelled_keeps_connection_open(
    loop: Any, aiohttp_client: Any
) -> None:
    closed = loop.create_future()

    async def handler(request):
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
        await ws.pong("data")

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
    await ws.ping("data")

    msg = await ws.receive()
    assert msg.type == WSMsgType.PONG
    assert msg.data == b"data"

    await ws.close(code=WSCloseCode.OK, message="exit message")

    await closed


async def test_receive_timeout_keeps_connection_open(
    loop: Any, aiohttp_client: Any
) -> None:
    closed = loop.create_future()
    timed_out = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse(autoping=False)
        await ws.prepare(request)

        task = asyncio.create_task(ws.receive(sys.float_info.min))
        with contextlib.suppress(asyncio.TimeoutError):
            await task

        timed_out.set_result(None)

        msg = await ws.receive()
        assert msg.type == WSMsgType.PING
        await asyncio.sleep(0)
        await ws.pong("data")

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
    await ws.ping("data")

    msg = await ws.receive()
    assert msg.type == WSMsgType.PONG
    assert msg.data == b"data"

    await ws.close(code=WSCloseCode.OK, message="exit message")

    await closed


async def test_websocket_shutdown(aiohttp_client: AiohttpClient) -> None:
    """Test that the client websocket gets the close message when the server is shutting down."""
    url = "/ws"
    app = web.Application()
    websockets = web.AppKey("websockets", weakref.WeakSet)
    app[websockets] = weakref.WeakSet()

    # need for send signal shutdown server
    shutdown_websockets = web.AppKey("shutdown_websockets", weakref.WeakSet)
    app[shutdown_websockets] = weakref.WeakSet()

    async def websocket_handler(request: web.Request) -> web.WebSocketResponse:
        websocket = web.WebSocketResponse()
        await websocket.prepare(request)
        request.app[websockets].add(websocket)
        request.app[shutdown_websockets].add(websocket)

        try:
            async for message in websocket:
                await websocket.send_json({"ok": True, "message": message.json()})
        finally:
            request.app[websockets].discard(websocket)

        return websocket

    async def on_shutdown(app: web.Application) -> None:
        while app[shutdown_websockets]:
            websocket = app[shutdown_websockets].pop()
            await websocket.close(
                code=aiohttp.WSCloseCode.GOING_AWAY,
                message="Server shutdown",
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
        ws = web.WebSocketResponse()
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
