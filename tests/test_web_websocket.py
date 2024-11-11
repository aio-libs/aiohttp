import asyncio
import time
from typing import Any
from unittest import mock

import aiosignal
import pytest
from multidict import CIMultiDict

from aiohttp import WSMessage, WSMessageTypeError, WSMsgType, web
from aiohttp.http import WS_CLOSED_MESSAGE
from aiohttp.streams import EofStream
from aiohttp.test_utils import make_mocked_coro, make_mocked_request
from aiohttp.web import HTTPBadRequest, WebSocketResponse
from aiohttp.web_ws import WebSocketReady


@pytest.fixture
def app(loop):
    ret = mock.Mock()
    ret.loop = loop
    ret._debug = False
    ret.on_response_prepare = aiosignal.Signal(ret)
    ret.on_response_prepare.freeze()
    return ret


@pytest.fixture
def protocol():
    ret = mock.Mock()
    ret.set_parser.return_value = ret
    return ret


@pytest.fixture
def make_request(app, protocol):
    def maker(method, path, headers=None, protocols=False):
        if headers is None:
            headers = CIMultiDict(
                {
                    "HOST": "server.example.com",
                    "UPGRADE": "websocket",
                    "CONNECTION": "Upgrade",
                    "SEC-WEBSOCKET-KEY": "dGhlIHNhbXBsZSBub25jZQ==",
                    "ORIGIN": "http://example.com",
                    "SEC-WEBSOCKET-VERSION": "13",
                }
            )
        if protocols:
            headers["SEC-WEBSOCKET-PROTOCOL"] = "chat, superchat"

        return make_mocked_request(
            method, path, headers, app=app, protocol=protocol, loop=app.loop
        )

    return maker


async def test_nonstarted_ping() -> None:
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.ping()


async def test_nonstarted_pong() -> None:
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.pong()


async def test_nonstarted_send_frame() -> None:
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.send_frame(b"string", WSMsgType.TEXT)


async def test_nonstarted_send_str() -> None:
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.send_str("string")


async def test_nonstarted_send_bytes() -> None:
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.send_bytes(b"bytes")


async def test_nonstarted_send_json() -> None:
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.send_json({"type": "json"})


async def test_nonstarted_close() -> None:
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.close()


async def test_nonstarted_receive_str() -> None:
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.receive_str()


async def test_nonstarted_receive_bytes() -> None:
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.receive_bytes()


async def test_nonstarted_receive_json() -> None:
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.receive_json()


async def test_receive_str_nonstring(make_request) -> None:
    req = make_request("GET", "/")
    ws = WebSocketResponse()
    await ws.prepare(req)

    async def receive():
        return WSMessage(WSMsgType.BINARY, b"data", b"")

    ws.receive = receive

    with pytest.raises(TypeError):
        await ws.receive_str()


async def test_receive_bytes_nonsbytes(make_request) -> None:
    req = make_request("GET", "/")
    ws = WebSocketResponse()
    await ws.prepare(req)

    async def receive():
        return WSMessage(WSMsgType.TEXT, "data", b"")

    ws.receive = receive

    with pytest.raises(TypeError):
        await ws.receive_bytes()


async def test_send_str_nonstring(make_request) -> None:
    req = make_request("GET", "/")
    ws = WebSocketResponse()
    await ws.prepare(req)
    with pytest.raises(TypeError):
        await ws.send_str(b"bytes")


async def test_send_bytes_nonbytes(make_request) -> None:
    req = make_request("GET", "/")
    ws = WebSocketResponse()
    await ws.prepare(req)
    with pytest.raises(TypeError):
        await ws.send_bytes("string")


async def test_send_json_nonjson(make_request) -> None:
    req = make_request("GET", "/")
    ws = WebSocketResponse()
    await ws.prepare(req)
    with pytest.raises(TypeError):
        await ws.send_json(set())


async def test_write_non_prepared() -> None:
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.write(b"data")


async def test_heartbeat_timeout(make_request: Any) -> None:
    """Verify the transport is closed when the heartbeat timeout is reached."""
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    req = make_request("GET", "/")
    lowest_time = time.get_clock_info("monotonic").resolution
    req._protocol._timeout_ceil_threshold = lowest_time
    ws = WebSocketResponse(heartbeat=lowest_time, timeout=lowest_time)
    await ws.prepare(req)
    ws._req.transport.close.side_effect = lambda: future.set_result(None)
    await future
    assert ws.closed


def test_websocket_ready() -> None:
    websocket_ready = WebSocketReady(True, "chat")
    assert websocket_ready.ok is True
    assert websocket_ready.protocol == "chat"


def test_websocket_not_ready() -> None:
    websocket_ready = WebSocketReady(False, None)
    assert websocket_ready.ok is False
    assert websocket_ready.protocol is None


def test_websocket_ready_unknown_protocol() -> None:
    websocket_ready = WebSocketReady(True, None)
    assert websocket_ready.ok is True
    assert websocket_ready.protocol is None


def test_bool_websocket_ready() -> None:
    websocket_ready = WebSocketReady(True, None)
    assert bool(websocket_ready) is True


def test_bool_websocket_not_ready() -> None:
    websocket_ready = WebSocketReady(False, None)
    assert bool(websocket_ready) is False


def test_can_prepare_ok(make_request) -> None:
    req = make_request("GET", "/", protocols=True)
    ws = WebSocketResponse(protocols=("chat",))
    assert WebSocketReady(True, "chat") == ws.can_prepare(req)


def test_can_prepare_unknown_protocol(make_request) -> None:
    req = make_request("GET", "/")
    ws = WebSocketResponse()
    assert WebSocketReady(True, None) == ws.can_prepare(req)


def test_can_prepare_without_upgrade(make_request) -> None:
    req = make_request("GET", "/", headers=CIMultiDict({}))
    ws = WebSocketResponse()
    assert WebSocketReady(False, None) == ws.can_prepare(req)


async def test_can_prepare_started(make_request) -> None:
    req = make_request("GET", "/")
    ws = WebSocketResponse()
    await ws.prepare(req)
    with pytest.raises(RuntimeError) as ctx:
        ws.can_prepare(req)

    assert "Already started" in str(ctx.value)


def test_closed_after_ctor() -> None:
    ws = WebSocketResponse()
    assert not ws.closed
    assert ws.close_code is None


async def test_raise_writer_limit(make_request) -> None:
    """Test the writer limit can be adjusted."""
    req = make_request("GET", "/")
    ws = WebSocketResponse(writer_limit=1234567)
    await ws.prepare(req)
    assert ws._reader is not None
    assert ws._writer is not None
    assert ws._writer._limit == 1234567
    ws._reader.feed_data(WS_CLOSED_MESSAGE, 0)
    await ws.close()


async def test_send_str_closed(make_request) -> None:
    req = make_request("GET", "/")
    ws = WebSocketResponse()
    await ws.prepare(req)
    ws._reader.feed_data(WS_CLOSED_MESSAGE, 0)
    await ws.close()
    assert len(ws._req.transport.close.mock_calls) == 1

    with pytest.raises(ConnectionError):
        await ws.send_str("string")


async def test_recv_str_closed(make_request) -> None:
    req = make_request("GET", "/")
    ws = web.WebSocketResponse()
    await ws.prepare(req)
    assert ws._reader is not None
    ws._reader.feed_data(WS_CLOSED_MESSAGE, 0)
    await ws.close()

    with pytest.raises(
        WSMessageTypeError,
        match=f"Received message {WSMsgType.CLOSED}:.+ is not WSMsgType.TEXT",
    ):
        await ws.receive_str()


async def test_send_bytes_closed(make_request) -> None:
    req = make_request("GET", "/")
    ws = WebSocketResponse()
    await ws.prepare(req)
    ws._reader.feed_data(WS_CLOSED_MESSAGE, 0)
    await ws.close()

    with pytest.raises(ConnectionError):
        await ws.send_bytes(b"bytes")


async def test_recv_bytes_closed(make_request) -> None:
    req = make_request("GET", "/")
    ws = web.WebSocketResponse()
    await ws.prepare(req)
    assert ws._reader is not None
    ws._reader.feed_data(WS_CLOSED_MESSAGE, 0)
    await ws.close()

    with pytest.raises(
        WSMessageTypeError,
        match=f"Received message {WSMsgType.CLOSED}:.+ is not WSMsgType.BINARY",
    ):
        await ws.receive_bytes()


async def test_send_json_closed(make_request) -> None:
    req = make_request("GET", "/")
    ws = WebSocketResponse()
    await ws.prepare(req)
    ws._reader.feed_data(WS_CLOSED_MESSAGE, 0)
    await ws.close()

    with pytest.raises(ConnectionError):
        await ws.send_json({"type": "json"})


async def test_send_frame_closed(make_request) -> None:
    req = make_request("GET", "/")
    ws = WebSocketResponse()
    await ws.prepare(req)
    assert ws._reader is not None
    ws._reader.feed_data(WS_CLOSED_MESSAGE, 0)
    await ws.close()

    with pytest.raises(ConnectionError):
        await ws.send_frame(b'{"type": "json"}', WSMsgType.TEXT)


async def test_ping_closed(make_request) -> None:
    req = make_request("GET", "/")
    ws = WebSocketResponse()
    await ws.prepare(req)
    ws._reader.feed_data(WS_CLOSED_MESSAGE, 0)
    await ws.close()

    with pytest.raises(ConnectionError):
        await ws.ping()


async def test_pong_closed(make_request, mocker) -> None:
    req = make_request("GET", "/")
    ws = WebSocketResponse()
    await ws.prepare(req)
    ws._reader.feed_data(WS_CLOSED_MESSAGE, 0)
    await ws.close()

    with pytest.raises(ConnectionError):
        await ws.pong()


async def test_close_idempotent(make_request) -> None:
    req = make_request("GET", "/")
    ws = WebSocketResponse()
    await ws.prepare(req)
    ws._reader.feed_data(WS_CLOSED_MESSAGE, 0)
    assert await ws.close(code=1, message="message1")
    assert ws.closed
    assert len(ws._req.transport.close.mock_calls) == 1

    assert not (await ws.close(code=2, message="message2"))


async def test_prepare_post_method_ok(make_request) -> None:
    req = make_request("POST", "/")
    ws = WebSocketResponse()
    await ws.prepare(req)
    assert ws.prepared


async def test_prepare_without_upgrade(make_request) -> None:
    req = make_request("GET", "/", headers=CIMultiDict({}))
    ws = WebSocketResponse()
    with pytest.raises(HTTPBadRequest):
        await ws.prepare(req)


async def test_wait_closed_before_start() -> None:
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.close()


async def test_write_eof_not_started() -> None:
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.write_eof()


async def test_write_eof_idempotent(make_request) -> None:
    req = make_request("GET", "/")
    ws = WebSocketResponse()
    await ws.prepare(req)
    assert len(ws._req.transport.close.mock_calls) == 0

    ws._reader.feed_data(WS_CLOSED_MESSAGE, 0)
    await ws.close()

    await ws.write_eof()
    await ws.write_eof()
    await ws.write_eof()
    assert len(ws._req.transport.close.mock_calls) == 1


async def test_receive_eofstream_in_reader(make_request, loop) -> None:
    req = make_request("GET", "/")
    ws = WebSocketResponse()
    await ws.prepare(req)

    ws._reader = mock.Mock()
    exc = EofStream()
    res = loop.create_future()
    res.set_exception(exc)
    ws._reader.read = make_mocked_coro(res)
    ws._payload_writer.drain = mock.Mock()
    ws._payload_writer.drain.return_value = loop.create_future()
    ws._payload_writer.drain.return_value.set_result(True)

    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSED
    assert ws.closed


async def test_receive_exception_in_reader(make_request: Any, loop: Any) -> None:
    req = make_request("GET", "/")
    ws = WebSocketResponse()
    await ws.prepare(req)

    ws._reader = mock.Mock()
    exc = Exception()
    res = loop.create_future()
    res.set_exception(exc)
    ws._reader.read = make_mocked_coro(res)
    ws._payload_writer.drain = mock.Mock()
    ws._payload_writer.drain.return_value = loop.create_future()
    ws._payload_writer.drain.return_value.set_result(True)

    msg = await ws.receive()
    assert msg.type == WSMsgType.ERROR
    assert ws.closed
    assert len(ws._req.transport.close.mock_calls) == 1


async def test_receive_close_but_left_open(make_request: Any, loop: Any) -> None:
    req = make_request("GET", "/")
    ws = WebSocketResponse()
    await ws.prepare(req)
    close_message = WSMessage(WSMsgType.CLOSE, 1000, "close")

    ws._reader = mock.Mock()
    ws._reader.read = mock.AsyncMock(return_value=close_message)
    ws._payload_writer.drain = mock.Mock()
    ws._payload_writer.drain.return_value = loop.create_future()
    ws._payload_writer.drain.return_value.set_result(True)

    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSE
    assert ws.closed
    assert len(ws._req.transport.close.mock_calls) == 1


async def test_receive_closing(make_request: Any, loop: Any) -> None:
    req = make_request("GET", "/")
    ws = WebSocketResponse()
    await ws.prepare(req)
    closing_message = WSMessage(WSMsgType.CLOSING, 1000, "closing")

    ws._reader = mock.Mock()
    read_mock = mock.AsyncMock(return_value=closing_message)
    ws._reader.read = read_mock
    ws._payload_writer.drain = mock.Mock()
    ws._payload_writer.drain.return_value = loop.create_future()
    ws._payload_writer.drain.return_value.set_result(True)

    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSING
    assert not ws.closed

    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSING
    assert not ws.closed

    ws._cancel(ConnectionResetError("Connection lost"))

    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSING


async def test_close_after_closing(make_request: Any, loop: Any) -> None:
    req = make_request("GET", "/")
    ws = WebSocketResponse()
    await ws.prepare(req)
    closing_message = WSMessage(WSMsgType.CLOSING, 1000, "closing")

    ws._reader = mock.Mock()
    ws._reader.read = mock.AsyncMock(return_value=closing_message)
    ws._payload_writer.drain = mock.Mock()
    ws._payload_writer.drain.return_value = loop.create_future()
    ws._payload_writer.drain.return_value.set_result(True)

    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSING
    assert not ws.closed
    assert len(ws._req.transport.close.mock_calls) == 0

    await ws.close()
    assert ws.closed
    assert len(ws._req.transport.close.mock_calls) == 1


async def test_receive_timeouterror(make_request: Any, loop: Any) -> None:
    req = make_request("GET", "/")
    ws = WebSocketResponse()
    await ws.prepare(req)
    assert len(ws._req.transport.close.mock_calls) == 0

    ws._reader = mock.Mock()
    res = loop.create_future()
    res.set_exception(asyncio.TimeoutError())
    ws._reader.read = make_mocked_coro(res)

    with pytest.raises(asyncio.TimeoutError):
        await ws.receive()

    # Should not close the connection on timeout
    assert len(ws._req.transport.close.mock_calls) == 0


async def test_multiple_receive_on_close_connection(make_request) -> None:
    req = make_request("GET", "/")
    ws = WebSocketResponse()
    await ws.prepare(req)
    ws._reader.feed_data(WS_CLOSED_MESSAGE, 0)
    await ws.close()

    await ws.receive()
    await ws.receive()
    await ws.receive()
    await ws.receive()

    with pytest.raises(RuntimeError):
        await ws.receive()


async def test_concurrent_receive(make_request) -> None:
    req = make_request("GET", "/")
    ws = WebSocketResponse()
    await ws.prepare(req)
    ws._waiting = True

    with pytest.raises(RuntimeError):
        await ws.receive()


async def test_close_exc(make_request) -> None:

    req = make_request("GET", "/")
    ws = WebSocketResponse()
    await ws.prepare(req)
    assert len(ws._req.transport.close.mock_calls) == 0

    exc = ValueError()
    ws._writer = mock.Mock()
    ws._writer.close.side_effect = exc
    await ws.close()
    assert ws.closed
    assert ws.exception() is exc
    assert len(ws._req.transport.close.mock_calls) == 1

    ws._closed = False
    ws._writer.close.side_effect = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        await ws.close()


async def test_prepare_twice_idempotent(make_request) -> None:
    req = make_request("GET", "/")
    ws = WebSocketResponse()

    impl1 = await ws.prepare(req)
    impl2 = await ws.prepare(req)
    assert impl1 is impl2


async def test_send_with_per_message_deflate(make_request, mocker) -> None:
    req = make_request("GET", "/")
    ws = WebSocketResponse()
    await ws.prepare(req)
    with mock.patch.object(ws._writer, "send_frame", autospec=True, spec_set=True) as m:
        await ws.send_str("string", compress=15)
        m.assert_called_with(b"string", WSMsgType.TEXT, compress=15)

        await ws.send_bytes(b"bytes", compress=0)
        m.assert_called_with(b"bytes", WSMsgType.BINARY, compress=0)

        await ws.send_json("[{}]", compress=9)
        m.assert_called_with(b'"[{}]"', WSMsgType.TEXT, compress=9)

        await ws.send_frame(b"[{}]", WSMsgType.TEXT, compress=9)
        m.assert_called_with(b"[{}]", WSMsgType.TEXT, compress=9)


async def test_no_transfer_encoding_header(make_request, mocker) -> None:
    req = make_request("GET", "/")
    ws = WebSocketResponse()
    await ws._start(req)

    assert "Transfer-Encoding" not in ws.headers


@pytest.mark.parametrize(
    "ws_transport, expected_result",
    [
        (
            mock.MagicMock(
                transport=mock.MagicMock(
                    get_extra_info=lambda name, default=None: {"test": "existent"}.get(
                        name, default
                    )
                )
            ),
            "existent",
        ),
        (None, "default"),
        (mock.MagicMock(transport=None), "default"),
    ],
)
async def test_get_extra_info(
    make_request, mocker, ws_transport, expected_result
) -> None:
    valid_key = "test"
    default_value = "default"

    req = make_request("GET", "/")
    ws = WebSocketResponse()

    await ws.prepare(req)
    ws._writer = ws_transport

    assert ws.get_extra_info(valid_key, default_value) == expected_result
