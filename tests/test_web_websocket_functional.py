# type: ignore
# HTTP websocket server functional tests

import asyncio
from typing import Any

import pytest

import aiohttp
from aiohttp import WSServerHandshakeError, web
from aiohttp.http import WSCloseCode, WSMsgType


async def test_websocket_can_prepare(loop: Any, aiohttp_client: Any) -> None:
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


async def test_websocket_json(loop: Any, aiohttp_client: Any) -> None:
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


async def test_websocket_json_invalid_message(loop: Any, aiohttp_client: Any) -> None:
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


async def test_websocket_send_json(loop: Any, aiohttp_client: Any) -> None:
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


async def test_websocket_receive_json(loop: Any, aiohttp_client: Any) -> None:
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


async def test_send_recv_text(loop: Any, aiohttp_client: Any) -> None:

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


async def test_send_recv_bytes(loop: Any, aiohttp_client: Any) -> None:

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


async def test_send_recv_json(loop: Any, aiohttp_client: Any) -> None:
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


async def test_close_timeout(loop: Any, aiohttp_client: Any) -> None:
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
    # internval shorter than server-side close timeout, to make the server
    # hanging indefinitely.
    await asyncio.sleep(0.08)
    msg = await ws._reader.read()
    assert msg.type == WSMsgType.CLOSE

    await asyncio.sleep(0.08)
    assert await aborted

    assert elapsed < 0.25, "close() should have returned before " "at most 2x timeout."

    await ws.close()


async def test_concurrent_close(loop: Any, aiohttp_client: Any) -> None:

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


async def test_ping(loop: Any, aiohttp_client: Any) -> None:

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


async def aiohttp_client_ping(loop: Any, aiohttp_client: Any):

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


async def test_pong(loop: Any, aiohttp_client: Any) -> None:

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


async def test_change_status(loop: Any, aiohttp_client: Any) -> None:

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


async def test_handle_protocol(loop: Any, aiohttp_client: Any) -> None:

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


async def test_server_close_handshake(loop: Any, aiohttp_client: Any) -> None:

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


async def aiohttp_client_close_handshake(loop: Any, aiohttp_client: Any):

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


async def test_server_close_handshake_server_eats_client_messages(
    loop: Any, aiohttp_client: Any
):
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


async def test_receive_timeout(loop: Any, aiohttp_client: Any) -> None:
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


async def test_custom_receive_timeout(loop: Any, aiohttp_client: Any) -> None:
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


async def test_heartbeat(loop: Any, aiohttp_client: Any) -> None:
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

    assert msg.type == aiohttp.WSMsgType.PING

    await ws.close()


async def test_heartbeat_no_pong(loop: Any, aiohttp_client: Any) -> None:
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
    assert msg.type == aiohttp.WSMsgType.PING
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


async def test_closed_async_for(loop: Any, aiohttp_client: Any) -> None:

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


async def test_websocket_disable_keepalive(loop: Any, aiohttp_client: Any) -> None:
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


async def test_receive_str_nonstring(loop: Any, aiohttp_client: Any) -> None:
    async def handler(request):
        ws = web.WebSocketResponse()
        if not ws.can_prepare(request):
            return web.HTTPUpgradeRequired()

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


async def test_receive_bytes_nonbytes(loop: Any, aiohttp_client: Any) -> None:
    async def handler(request):
        ws = web.WebSocketResponse()
        if not ws.can_prepare(request):
            return web.HTTPUpgradeRequired()

        await ws.prepare(request)
        await ws.send_bytes("answer")
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect("/")
    with pytest.raises(TypeError):
        await ws.receive_bytes()


async def test_bug3380(loop: Any, aiohttp_client: Any) -> None:
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

    with pytest.raises(WSServerHandshakeError):
        await client.ws_connect("/ws")

    resp = await client.get("/api/null", timeout=1)
    assert (await resp.json()) == {"err": None}
    resp.close()
