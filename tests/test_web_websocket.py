import asyncio
import time
from typing import Optional, Protocol
from unittest import mock

import aiosignal
import pytest
from multidict import CIMultiDict
from pytest_mock import MockerFixture

from aiohttp import WSMsgType, web
from aiohttp.http import WS_CLOSED_MESSAGE
from aiohttp.http_websocket import WSMessageClose, WSMessageClosing
from aiohttp.streams import EofStream
from aiohttp.test_utils import make_mocked_coro, make_mocked_request
from aiohttp.web_ws import WebSocketReady


class _RequestMaker(Protocol):
    def __call__(
        self,
        method: str,
        path: str,
        headers: Optional[CIMultiDict[str]] = None,
        protocols: bool = False,
    ) -> web.Request: ...


@pytest.fixture
def app(loop: asyncio.AbstractEventLoop) -> web.Application:
    ret: web.Application = mock.create_autospec(web.Application, spec_set=True)
    ret.on_response_prepare = aiosignal.Signal(ret)  # type: ignore[misc]
    ret.on_response_prepare.freeze()
    return ret


@pytest.fixture
def protocol() -> web.RequestHandler[web.Request]:
    ret = mock.Mock()
    ret.set_parser.return_value = ret
    return ret


@pytest.fixture
def make_request(
    app: web.Application, protocol: web.RequestHandler[web.Request]
) -> _RequestMaker:
    def maker(
        method: str,
        path: str,
        headers: Optional[CIMultiDict[str]] = None,
        protocols: bool = False,
    ) -> web.Request:
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

        return make_mocked_request(method, path, headers, app=app, protocol=protocol)

    return maker


async def test_nonstarted_ping() -> None:
    ws = web.WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.ping()


async def test_nonstarted_pong() -> None:
    ws = web.WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.pong()


async def test_nonstarted_send_frame() -> None:
    ws = web.WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.send_frame(b"string", WSMsgType.TEXT)


async def test_nonstarted_send_str() -> None:
    ws = web.WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.send_str("string")


async def test_nonstarted_send_bytes() -> None:
    ws = web.WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.send_bytes(b"bytes")


async def test_nonstarted_send_json() -> None:
    ws = web.WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.send_json({"type": "json"})


async def test_nonstarted_close() -> None:
    ws = web.WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.close()


async def test_nonstarted_receive_str() -> None:
    ws = web.WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.receive_str()


async def test_nonstarted_receive_bytes() -> None:
    ws = web.WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.receive_bytes()


async def test_nonstarted_receive_json() -> None:
    ws = web.WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.receive_json()


async def test_send_str_nonstring(make_request: _RequestMaker) -> None:
    req = make_request("GET", "/")
    ws = web.WebSocketResponse()
    await ws.prepare(req)
    with pytest.raises(TypeError):
        await ws.send_str(b"bytes")  # type: ignore[arg-type]


async def test_send_bytes_nonbytes(make_request: _RequestMaker) -> None:
    req = make_request("GET", "/")
    ws = web.WebSocketResponse()
    await ws.prepare(req)
    with pytest.raises(TypeError):
        await ws.send_bytes("string")  # type: ignore[arg-type]


async def test_send_json_nonjson(make_request: _RequestMaker) -> None:
    req = make_request("GET", "/")
    ws = web.WebSocketResponse()
    await ws.prepare(req)
    with pytest.raises(TypeError):
        await ws.send_json(set())


async def test_write_non_prepared() -> None:
    ws = web.WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.write(b"data")


async def test_heartbeat_timeout(make_request: _RequestMaker) -> None:
    """Verify the transport is closed when the heartbeat timeout is reached."""
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    req = make_request("GET", "/")
    assert req.transport is not None
    req.transport.close.side_effect = lambda: future.set_result(None)  # type: ignore[attr-defined]
    lowest_time = time.get_clock_info("monotonic").resolution
    req._protocol._timeout_ceil_threshold = lowest_time
    ws = web.WebSocketResponse(heartbeat=lowest_time, timeout=lowest_time)
    await ws.prepare(req)
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


def test_can_prepare_ok(make_request: _RequestMaker) -> None:
    req = make_request("GET", "/", protocols=True)
    ws = web.WebSocketResponse(protocols=("chat",))
    assert WebSocketReady(True, "chat") == ws.can_prepare(req)


def test_can_prepare_unknown_protocol(make_request: _RequestMaker) -> None:
    req = make_request("GET", "/")
    ws = web.WebSocketResponse()
    assert WebSocketReady(True, None) == ws.can_prepare(req)


def test_can_prepare_without_upgrade(make_request: _RequestMaker) -> None:
    req = make_request("GET", "/", headers=CIMultiDict({}))
    ws = web.WebSocketResponse()
    assert WebSocketReady(False, None) == ws.can_prepare(req)


async def test_can_prepare_started(make_request: _RequestMaker) -> None:
    req = make_request("GET", "/")
    ws = web.WebSocketResponse()
    await ws.prepare(req)
    with pytest.raises(RuntimeError) as ctx:
        ws.can_prepare(req)

    assert "Already started" in str(ctx.value)


def test_closed_after_ctor() -> None:
    ws = web.WebSocketResponse()
    assert not ws.closed
    assert ws.close_code is None


async def test_send_str_closed(make_request: _RequestMaker) -> None:
    req = make_request("GET", "/")
    ws = web.WebSocketResponse()
    await ws.prepare(req)
    assert ws._reader is not None
    ws._reader.feed_data(WS_CLOSED_MESSAGE)
    await ws.close()
    assert req.transport is not None
    assert len(req.transport.close.mock_calls) == 1  # type: ignore[attr-defined]

    with pytest.raises(ConnectionError):
        await ws.send_str("string")


async def test_send_bytes_closed(make_request: _RequestMaker) -> None:
    req = make_request("GET", "/")
    ws = web.WebSocketResponse()
    await ws.prepare(req)
    assert ws._reader is not None
    ws._reader.feed_data(WS_CLOSED_MESSAGE)
    await ws.close()

    with pytest.raises(ConnectionError):
        await ws.send_bytes(b"bytes")


async def test_send_json_closed(make_request: _RequestMaker) -> None:
    req = make_request("GET", "/")
    ws = web.WebSocketResponse()
    await ws.prepare(req)
    assert ws._reader is not None
    ws._reader.feed_data(WS_CLOSED_MESSAGE)
    await ws.close()

    with pytest.raises(ConnectionError):
        await ws.send_json({"type": "json"})


async def test_send_frame_closed(make_request: _RequestMaker) -> None:
    req = make_request("GET", "/")
    ws = web.WebSocketResponse()
    await ws.prepare(req)
    assert ws._reader is not None
    ws._reader.feed_data(WS_CLOSED_MESSAGE)
    await ws.close()

    with pytest.raises(ConnectionError):
        await ws.send_frame(b'{"type": "json"}', WSMsgType.TEXT)


async def test_ping_closed(make_request: _RequestMaker) -> None:
    req = make_request("GET", "/")
    ws = web.WebSocketResponse()
    await ws.prepare(req)
    assert ws._reader is not None
    ws._reader.feed_data(WS_CLOSED_MESSAGE)
    await ws.close()

    with pytest.raises(ConnectionError):
        await ws.ping()


async def test_pong_closed(make_request: _RequestMaker, mocker: MockerFixture) -> None:
    req = make_request("GET", "/")
    ws = web.WebSocketResponse()
    await ws.prepare(req)
    assert ws._reader is not None
    ws._reader.feed_data(WS_CLOSED_MESSAGE)
    await ws.close()

    with pytest.raises(ConnectionError):
        await ws.pong()


async def test_close_idempotent(make_request: _RequestMaker) -> None:
    req = make_request("GET", "/")
    ws = web.WebSocketResponse()
    await ws.prepare(req)
    assert ws._reader is not None
    ws._reader.feed_data(WS_CLOSED_MESSAGE)
    close_code = await ws.close(code=1, message=b"message1")
    assert close_code == 1
    assert ws.closed
    assert req.transport is not None
    assert len(req.transport.close.mock_calls) == 1  # type: ignore[attr-defined]

    close_code = await ws.close(code=2, message=b"message2")
    assert close_code == 0


async def test_prepare_post_method_ok(make_request: _RequestMaker) -> None:
    req = make_request("POST", "/")
    ws = web.WebSocketResponse()
    await ws.prepare(req)
    assert ws.prepared


async def test_prepare_without_upgrade(make_request: _RequestMaker) -> None:
    req = make_request("GET", "/", headers=CIMultiDict({}))
    ws = web.WebSocketResponse()
    with pytest.raises(web.HTTPBadRequest):
        await ws.prepare(req)


async def test_wait_closed_before_start() -> None:
    ws = web.WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.close()


async def test_write_eof_not_started() -> None:
    ws = web.WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.write_eof()


async def test_write_eof_idempotent(make_request: _RequestMaker) -> None:
    req = make_request("GET", "/")
    ws = web.WebSocketResponse()
    await ws.prepare(req)
    assert req.transport is not None
    assert len(req.transport.close.mock_calls) == 0  # type: ignore[attr-defined]

    assert ws._reader is not None
    ws._reader.feed_data(WS_CLOSED_MESSAGE)
    await ws.close()

    await ws.write_eof()
    await ws.write_eof()
    await ws.write_eof()
    assert len(req.transport.close.mock_calls) == 1  # type: ignore[attr-defined]


async def test_receive_eofstream_in_reader(
    make_request: _RequestMaker, loop: asyncio.AbstractEventLoop
) -> None:
    req = make_request("GET", "/")
    ws = web.WebSocketResponse()
    await ws.prepare(req)

    ws._reader = mock.Mock()
    exc = EofStream()
    res = loop.create_future()
    res.set_exception(exc)
    ws._reader.read = make_mocked_coro(res)
    assert ws._payload_writer is not None
    f = loop.create_future()
    f.set_result(True)
    ws._payload_writer.drain.return_value = f  # type: ignore[attr-defined]
    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSED
    assert ws.closed


async def test_receive_exception_in_reader(
    make_request: _RequestMaker, loop: asyncio.AbstractEventLoop
) -> None:
    req = make_request("GET", "/")
    ws = web.WebSocketResponse()
    await ws.prepare(req)

    ws._reader = mock.Mock()
    exc = Exception()
    res = loop.create_future()
    res.set_exception(exc)
    ws._reader.read = make_mocked_coro(res)

    f = loop.create_future()
    assert ws._payload_writer is not None
    ws._payload_writer.drain.return_value = f  # type: ignore[attr-defined]
    f.set_result(True)
    msg = await ws.receive()
    assert msg.type == WSMsgType.ERROR
    assert ws.closed
    assert req.transport is not None
    assert len(req.transport.close.mock_calls) == 1  # type: ignore[attr-defined]


async def test_receive_close_but_left_open(
    make_request: _RequestMaker, loop: asyncio.AbstractEventLoop
) -> None:
    req = make_request("GET", "/")
    ws = web.WebSocketResponse()
    await ws.prepare(req)
    close_message = WSMessageClose(data=1000, extra="close")

    ws._reader = mock.Mock()
    ws._reader.read = mock.AsyncMock(return_value=close_message)

    f = loop.create_future()
    assert ws._payload_writer is not None
    ws._payload_writer.drain.return_value = f  # type: ignore[attr-defined]
    f.set_result(True)
    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSE
    assert ws.closed
    assert req.transport is not None
    assert len(req.transport.close.mock_calls) == 1  # type: ignore[attr-defined]


async def test_receive_closing(
    make_request: _RequestMaker, loop: asyncio.AbstractEventLoop
) -> None:
    req = make_request("GET", "/")
    ws = web.WebSocketResponse()
    await ws.prepare(req)
    closing_message = WSMessageClosing(data=1000, extra="closing")

    ws._reader = mock.Mock()
    read_mock = mock.AsyncMock(return_value=closing_message)
    ws._reader.read = read_mock

    f = loop.create_future()
    assert ws._payload_writer is not None
    ws._payload_writer.drain.return_value = f  # type: ignore[attr-defined]
    f.set_result(True)
    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSING
    assert not ws.closed

    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSING
    assert not ws.closed

    ws._cancel(ConnectionResetError("Connection lost"))

    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSING


async def test_close_after_closing(
    make_request: _RequestMaker, loop: asyncio.AbstractEventLoop
) -> None:
    req = make_request("GET", "/")
    ws = web.WebSocketResponse()
    await ws.prepare(req)
    closing_message = WSMessageClosing(data=1000, extra="closing")

    ws._reader = mock.Mock()
    ws._reader.read = mock.AsyncMock(return_value=closing_message)

    f = loop.create_future()
    assert ws._payload_writer is not None
    ws._payload_writer.drain.return_value = f  # type: ignore[attr-defined]
    f.set_result(True)
    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSING
    assert not ws.closed
    assert req.transport is not None
    assert len(req.transport.close.mock_calls) == 0  # type: ignore[attr-defined]

    await ws.close()
    assert ws.closed
    assert len(req.transport.close.mock_calls) == 1


async def test_receive_timeouterror(
    make_request: _RequestMaker, loop: asyncio.AbstractEventLoop
) -> None:
    req = make_request("GET", "/")
    ws = web.WebSocketResponse()
    await ws.prepare(req)
    assert req.transport is not None
    assert len(req.transport.close.mock_calls) == 0  # type: ignore[attr-defined]

    ws._reader = mock.Mock()
    res = loop.create_future()
    res.set_exception(asyncio.TimeoutError())
    ws._reader.read = make_mocked_coro(res)

    with pytest.raises(asyncio.TimeoutError):
        await ws.receive()

    # Should not close the connection on timeout
    assert len(req.transport.close.mock_calls) == 0  # type: ignore[attr-defined]


async def test_multiple_receive_on_close_connection(
    make_request: _RequestMaker,
) -> None:
    req = make_request("GET", "/")
    ws = web.WebSocketResponse()
    await ws.prepare(req)
    assert ws._reader is not None
    ws._reader.feed_data(WS_CLOSED_MESSAGE)
    await ws.close()

    await ws.receive()
    await ws.receive()
    await ws.receive()
    await ws.receive()

    with pytest.raises(RuntimeError):
        await ws.receive()


async def test_concurrent_receive(make_request: _RequestMaker) -> None:
    req = make_request("GET", "/")
    ws = web.WebSocketResponse()
    await ws.prepare(req)
    ws._waiting = True

    with pytest.raises(RuntimeError):
        await ws.receive()


async def test_close_exc(make_request: _RequestMaker) -> None:
    req = make_request("GET", "/")
    ws = web.WebSocketResponse()
    await ws.prepare(req)
    assert req.transport is not None
    assert len(req.transport.close.mock_calls) == 0  # type: ignore[attr-defined]

    exc = ValueError()
    ws._writer = mock.Mock()
    ws._writer.close.side_effect = exc
    await ws.close()
    assert ws.closed
    assert ws.exception() is exc
    assert len(req.transport.close.mock_calls) == 1  # type: ignore[attr-defined]

    ws._closed = False
    ws._writer.close.side_effect = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        await ws.close()


async def test_prepare_twice_idempotent(make_request: _RequestMaker) -> None:
    req = make_request("GET", "/")
    ws = web.WebSocketResponse()

    impl1 = await ws.prepare(req)
    impl2 = await ws.prepare(req)
    assert impl1 is impl2


async def test_send_with_per_message_deflate(
    make_request: _RequestMaker, mocker: MockerFixture
) -> None:
    req = make_request("GET", "/")
    ws = web.WebSocketResponse()
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


async def test_no_transfer_encoding_header(
    make_request: _RequestMaker, mocker: MockerFixture
) -> None:
    req = make_request("GET", "/")
    ws = web.WebSocketResponse()
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
    make_request: _RequestMaker,
    mocker: MockerFixture,
    ws_transport: Optional[mock.MagicMock],
    expected_result: str,
) -> None:
    valid_key = "test"
    default_value = "default"

    req = make_request("GET", "/")
    ws = web.WebSocketResponse()

    await ws.prepare(req)
    ws._writer = ws_transport

    assert ws.get_extra_info(valid_key, default_value) == expected_result
