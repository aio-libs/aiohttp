import asyncio
import base64
import hashlib
import os
from typing import Any, Type
from unittest import mock

import pytest

import aiohttp
from aiohttp import ClientConnectionResetError, ServerDisconnectedError, client, hdrs
from aiohttp.http import WS_KEY
from aiohttp.streams import EofStream
from aiohttp.test_utils import make_mocked_coro


async def test_ws_connect(ws_key: Any, loop: Any, key_data: Any) -> None:
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: "websocket",
        hdrs.CONNECTION: "upgrade",
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
        hdrs.SEC_WEBSOCKET_PROTOCOL: "chat",
    }
    resp.connection.protocol.read_timeout = None
    with mock.patch("aiohttp.client.os") as m_os:
        with mock.patch("aiohttp.client.ClientSession.request") as m_req:
            m_os.urandom.return_value = key_data
            m_req.return_value = loop.create_future()
            m_req.return_value.set_result(resp)

            res = await aiohttp.ClientSession(loop=loop).ws_connect(
                "http://test.org", protocols=("t1", "t2", "chat")
            )

    assert isinstance(res, client.ClientWebSocketResponse)
    assert res.protocol == "chat"
    assert hdrs.ORIGIN not in m_req.call_args[1]["headers"]


async def test_ws_connect_read_timeout_is_reset_to_inf(
    ws_key: Any, loop: Any, key_data: Any
) -> None:
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: "websocket",
        hdrs.CONNECTION: "upgrade",
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
        hdrs.SEC_WEBSOCKET_PROTOCOL: "chat",
    }
    resp.connection.protocol.read_timeout = 0.5
    with mock.patch("aiohttp.client.os") as m_os, mock.patch(
        "aiohttp.client.ClientSession.request"
    ) as m_req:
        m_os.urandom.return_value = key_data
        m_req.return_value = loop.create_future()
        m_req.return_value.set_result(resp)

        res = await aiohttp.ClientSession().ws_connect(
            "http://test.org", protocols=("t1", "t2", "chat")
        )

    assert isinstance(res, client.ClientWebSocketResponse)
    assert res.protocol == "chat"
    assert hdrs.ORIGIN not in m_req.call_args[1]["headers"]
    assert resp.connection.protocol.read_timeout is None


async def test_ws_connect_read_timeout_stays_inf(
    ws_key: Any, loop: Any, key_data: Any
) -> None:
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: "websocket",
        hdrs.CONNECTION: "upgrade",
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
        hdrs.SEC_WEBSOCKET_PROTOCOL: "chat",
    }
    resp.connection.protocol.read_timeout = None
    with mock.patch("aiohttp.client.os") as m_os, mock.patch(
        "aiohttp.client.ClientSession.request"
    ) as m_req:
        m_os.urandom.return_value = key_data
        m_req.return_value = loop.create_future()
        m_req.return_value.set_result(resp)

        res = await aiohttp.ClientSession().ws_connect(
            "http://test.org",
            protocols=("t1", "t2", "chat"),
            timeout=aiohttp.ClientWSTimeout(0.5),
        )

    assert isinstance(res, client.ClientWebSocketResponse)
    assert res.protocol == "chat"
    assert hdrs.ORIGIN not in m_req.call_args[1]["headers"]
    assert resp.connection.protocol.read_timeout is None


async def test_ws_connect_read_timeout_reset_to_max(
    ws_key: Any, loop: Any, key_data: Any
) -> None:
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: "websocket",
        hdrs.CONNECTION: "upgrade",
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
        hdrs.SEC_WEBSOCKET_PROTOCOL: "chat",
    }
    resp.connection.protocol.read_timeout = 0.5
    with mock.patch("aiohttp.client.os") as m_os, mock.patch(
        "aiohttp.client.ClientSession.request"
    ) as m_req:
        m_os.urandom.return_value = key_data
        m_req.return_value = loop.create_future()
        m_req.return_value.set_result(resp)

        res = await aiohttp.ClientSession().ws_connect(
            "http://test.org",
            protocols=("t1", "t2", "chat"),
            timeout=aiohttp.ClientWSTimeout(1.0),
        )

    assert isinstance(res, client.ClientWebSocketResponse)
    assert res.protocol == "chat"
    assert hdrs.ORIGIN not in m_req.call_args[1]["headers"]
    assert resp.connection.protocol.read_timeout == 1.0


async def test_ws_connect_with_origin(key_data, loop) -> None:
    resp = mock.Mock()
    resp.status = 403
    with mock.patch("aiohttp.client.os") as m_os:
        with mock.patch("aiohttp.client.ClientSession.request") as m_req:
            m_os.urandom.return_value = key_data
            m_req.return_value = loop.create_future()
            m_req.return_value.set_result(resp)

            origin = "https://example.org/page.html"
            with pytest.raises(client.WSServerHandshakeError):
                await aiohttp.ClientSession(loop=loop).ws_connect(
                    "http://test.org", origin=origin
                )

    assert hdrs.ORIGIN in m_req.call_args[1]["headers"]
    assert m_req.call_args[1]["headers"][hdrs.ORIGIN] == origin


async def test_ws_connect_with_params(ws_key, loop, key_data) -> None:
    params = {"key1": "value1", "key2": "value2"}

    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: "websocket",
        hdrs.CONNECTION: "upgrade",
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
        hdrs.SEC_WEBSOCKET_PROTOCOL: "chat",
    }
    resp.connection.protocol.read_timeout = None
    with mock.patch("aiohttp.client.os") as m_os:
        with mock.patch("aiohttp.client.ClientSession.request") as m_req:
            m_os.urandom.return_value = key_data
            m_req.return_value = loop.create_future()
            m_req.return_value.set_result(resp)

            await aiohttp.ClientSession().ws_connect(
                "http://test.org", protocols=("t1", "t2", "chat"), params=params
            )

    assert m_req.call_args[1]["params"] == params


async def test_ws_connect_custom_response(loop, ws_key, key_data) -> None:
    class CustomResponse(client.ClientWebSocketResponse):
        def read(self, decode=False):
            return "customized!"

    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: "websocket",
        hdrs.CONNECTION: "upgrade",
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
    }
    resp.connection.protocol.read_timeout = None
    with mock.patch("aiohttp.client.os") as m_os:
        with mock.patch("aiohttp.client.ClientSession.request") as m_req:
            m_os.urandom.return_value = key_data
            m_req.return_value = loop.create_future()
            m_req.return_value.set_result(resp)

            res = await aiohttp.ClientSession(
                ws_response_class=CustomResponse, loop=loop
            ).ws_connect("http://test.org")

    assert res.read() == "customized!"


async def test_ws_connect_err_status(loop, ws_key, key_data) -> None:
    resp = mock.Mock()
    resp.status = 500
    resp.headers = {
        hdrs.UPGRADE: "websocket",
        hdrs.CONNECTION: "upgrade",
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
    }
    with mock.patch("aiohttp.client.os") as m_os:
        with mock.patch("aiohttp.client.ClientSession.request") as m_req:
            m_os.urandom.return_value = key_data
            m_req.return_value = loop.create_future()
            m_req.return_value.set_result(resp)

            with pytest.raises(client.WSServerHandshakeError) as ctx:
                await aiohttp.ClientSession(loop=loop).ws_connect(
                    "http://test.org", protocols=("t1", "t2", "chat")
                )

    assert ctx.value.message == "Invalid response status"


async def test_ws_connect_err_upgrade(loop, ws_key, key_data) -> None:
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: "test",
        hdrs.CONNECTION: "upgrade",
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
    }
    with mock.patch("aiohttp.client.os") as m_os:
        with mock.patch("aiohttp.client.ClientSession.request") as m_req:
            m_os.urandom.return_value = key_data
            m_req.return_value = loop.create_future()
            m_req.return_value.set_result(resp)

            with pytest.raises(client.WSServerHandshakeError) as ctx:
                await aiohttp.ClientSession(loop=loop).ws_connect(
                    "http://test.org", protocols=("t1", "t2", "chat")
                )

    assert ctx.value.message == "Invalid upgrade header"


async def test_ws_connect_err_conn(loop, ws_key, key_data) -> None:
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: "websocket",
        hdrs.CONNECTION: "close",
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
    }
    with mock.patch("aiohttp.client.os") as m_os:
        with mock.patch("aiohttp.client.ClientSession.request") as m_req:
            m_os.urandom.return_value = key_data
            m_req.return_value = loop.create_future()
            m_req.return_value.set_result(resp)

            with pytest.raises(client.WSServerHandshakeError) as ctx:
                await aiohttp.ClientSession(loop=loop).ws_connect(
                    "http://test.org", protocols=("t1", "t2", "chat")
                )

    assert ctx.value.message == "Invalid connection header"


async def test_ws_connect_err_challenge(loop, ws_key, key_data) -> None:
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: "websocket",
        hdrs.CONNECTION: "upgrade",
        hdrs.SEC_WEBSOCKET_ACCEPT: "asdfasdfasdfasdfasdfasdf",
    }
    with mock.patch("aiohttp.client.os") as m_os:
        with mock.patch("aiohttp.client.ClientSession.request") as m_req:
            m_os.urandom.return_value = key_data
            m_req.return_value = loop.create_future()
            m_req.return_value.set_result(resp)

            with pytest.raises(client.WSServerHandshakeError) as ctx:
                await aiohttp.ClientSession(loop=loop).ws_connect(
                    "http://test.org", protocols=("t1", "t2", "chat")
                )

    assert ctx.value.message == "Invalid challenge response"


async def test_ws_connect_common_headers(ws_key, loop, key_data) -> None:
    # Emulate a headers dict being reused for a second ws_connect.

    # In this scenario, we need to ensure that the newly generated secret key
    # is sent to the server, not the stale key.
    headers = {}

    async def test_connection() -> None:
        async def mock_get(*args, **kwargs):
            resp = mock.Mock()
            resp.status = 101
            key = kwargs.get("headers").get(hdrs.SEC_WEBSOCKET_KEY)
            accept = base64.b64encode(
                hashlib.sha1(base64.b64encode(base64.b64decode(key)) + WS_KEY).digest()
            ).decode()
            resp.headers = {
                hdrs.UPGRADE: "websocket",
                hdrs.CONNECTION: "upgrade",
                hdrs.SEC_WEBSOCKET_ACCEPT: accept,
                hdrs.SEC_WEBSOCKET_PROTOCOL: "chat",
            }
            resp.connection.protocol.read_timeout = None
            return resp

        with mock.patch("aiohttp.client.os") as m_os:
            with mock.patch(
                "aiohttp.client.ClientSession.request", side_effect=mock_get
            ) as m_req:
                m_os.urandom.return_value = key_data

                res = await aiohttp.ClientSession(loop=loop).ws_connect(
                    "http://test.org", protocols=("t1", "t2", "chat"), headers=headers
                )

        assert isinstance(res, client.ClientWebSocketResponse)
        assert res.protocol == "chat"
        assert hdrs.ORIGIN not in m_req.call_args[1]["headers"]

    await test_connection()
    # Generate a new ws key
    key_data = os.urandom(16)
    await test_connection()


async def test_close(loop, ws_key, key_data) -> None:
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: "websocket",
        hdrs.CONNECTION: "upgrade",
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
    }
    resp.connection.protocol.read_timeout = None
    with mock.patch("aiohttp.client.WebSocketWriter") as WebSocketWriter:
        with mock.patch("aiohttp.client.os") as m_os:
            with mock.patch("aiohttp.client.ClientSession.request") as m_req:
                m_os.urandom.return_value = key_data
                m_req.return_value = loop.create_future()
                m_req.return_value.set_result(resp)
                writer = mock.Mock()
                WebSocketWriter.return_value = writer
                writer.close = make_mocked_coro()

                session = aiohttp.ClientSession(loop=loop)
                resp = await session.ws_connect("http://test.org")
                assert not resp.closed

                resp._reader.feed_data(
                    aiohttp.WSMessage(aiohttp.WSMsgType.CLOSE, b"", b""), 0
                )

                res = await resp.close()
                writer.close.assert_called_with(1000, b"")
                assert resp.closed
                assert res
                assert resp.exception() is None

                # idempotent
                res = await resp.close()
                assert not res
                assert writer.close.call_count == 1

                await session.close()


async def test_close_eofstream(loop, ws_key, key_data) -> None:
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: "websocket",
        hdrs.CONNECTION: "upgrade",
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
    }
    resp.connection.protocol.read_timeout = None
    with mock.patch("aiohttp.client.WebSocketWriter") as WebSocketWriter:
        with mock.patch("aiohttp.client.os") as m_os:
            with mock.patch("aiohttp.client.ClientSession.request") as m_req:
                m_os.urandom.return_value = key_data
                m_req.return_value = loop.create_future()
                m_req.return_value.set_result(resp)
                writer = WebSocketWriter.return_value = mock.Mock()

                session = aiohttp.ClientSession(loop=loop)
                resp = await session.ws_connect("http://test.org")
                assert not resp.closed

                exc = EofStream()
                resp._reader.set_exception(exc)

                await resp.receive()
                writer.close.assert_called_with(1000, b"")
                assert resp.closed

                await session.close()


async def test_close_connection_lost(
    loop: asyncio.AbstractEventLoop, ws_key: bytes, key_data: bytes
) -> None:
    """Test the websocket client handles the connection being closed out from under it."""
    mresp = mock.Mock(spec_set=client.ClientResponse)
    mresp.status = 101
    mresp.headers = {
        hdrs.UPGRADE: "websocket",
        hdrs.CONNECTION: "upgrade",
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
    }
    mresp.connection.protocol.read_timeout = None
    with mock.patch("aiohttp.client.WebSocketWriter"), mock.patch(
        "aiohttp.client.os"
    ) as m_os, mock.patch("aiohttp.client.ClientSession.request") as m_req:
        m_os.urandom.return_value = key_data
        m_req.return_value = loop.create_future()
        m_req.return_value.set_result(mresp)

        session = aiohttp.ClientSession()
        resp = await session.ws_connect("http://test.org")
        assert not resp.closed

        exc = ServerDisconnectedError()
        resp._reader.set_exception(exc)

        msg = await resp.receive()
        assert msg.type is aiohttp.WSMsgType.CLOSED
        assert resp.closed

        await session.close()


async def test_close_exc(
    loop: asyncio.AbstractEventLoop, ws_key: bytes, key_data: bytes
) -> None:
    mresp = mock.Mock()
    mresp.status = 101
    mresp.headers = {
        hdrs.UPGRADE: "websocket",
        hdrs.CONNECTION: "upgrade",
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
    }
    mresp.connection.protocol.read_timeout = None
    with mock.patch("aiohttp.client.WebSocketWriter") as WebSocketWriter:
        with mock.patch("aiohttp.client.os") as m_os:
            with mock.patch("aiohttp.client.ClientSession.request") as m_req:
                m_os.urandom.return_value = key_data
                m_req.return_value = loop.create_future()
                m_req.return_value.set_result(mresp)
                writer = mock.Mock()
                WebSocketWriter.return_value = writer
                writer.close = make_mocked_coro()

                session = aiohttp.ClientSession(loop=loop)
                resp = await session.ws_connect("http://test.org")
                assert not resp.closed

                exc = ValueError()
                resp._reader.set_exception(exc)

                await resp.close()
                assert resp.closed
                assert resp.exception() is exc

                await session.close()


async def test_close_exc2(loop, ws_key, key_data) -> None:
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: "websocket",
        hdrs.CONNECTION: "upgrade",
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
    }
    resp.connection.protocol.read_timeout = None
    with mock.patch("aiohttp.client.WebSocketWriter") as WebSocketWriter:
        with mock.patch("aiohttp.client.os") as m_os:
            with mock.patch("aiohttp.client.ClientSession.request") as m_req:
                m_os.urandom.return_value = key_data
                m_req.return_value = loop.create_future()
                m_req.return_value.set_result(resp)
                writer = WebSocketWriter.return_value = mock.Mock()

                resp = await aiohttp.ClientSession(loop=loop).ws_connect(
                    "http://test.org"
                )
                assert not resp.closed

                exc = ValueError()
                writer.close.side_effect = exc

                await resp.close()
                assert resp.closed
                assert resp.exception() is exc

                resp._closed = False
                writer.close.side_effect = asyncio.CancelledError()
                with pytest.raises(asyncio.CancelledError):
                    await resp.close()


@pytest.mark.parametrize("exc", (ClientConnectionResetError, ConnectionResetError))
async def test_send_data_after_close(
    exc: Type[Exception],
    ws_key: bytes,
    key_data: bytes,
    loop: asyncio.AbstractEventLoop,
) -> None:
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: "websocket",
        hdrs.CONNECTION: "upgrade",
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
    }
    resp.connection.protocol.read_timeout = None
    with mock.patch("aiohttp.client.os") as m_os:
        with mock.patch("aiohttp.client.ClientSession.request") as m_req:
            m_os.urandom.return_value = key_data
            m_req.return_value = loop.create_future()
            m_req.return_value.set_result(resp)

            resp = await aiohttp.ClientSession(loop=loop).ws_connect("http://test.org")
            resp._writer._closing = True

            for meth, args in (
                (resp.ping, ()),
                (resp.pong, ()),
                (resp.send_str, ("s",)),
                (resp.send_bytes, (b"b",)),
                (resp.send_json, ({},)),
                (resp.send_frame, (b"", aiohttp.WSMsgType.BINARY)),
            ):
                with pytest.raises(exc):  # Verify exc can be caught with both classes
                    await meth(*args)


async def test_send_data_type_errors(ws_key, key_data, loop) -> None:
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: "websocket",
        hdrs.CONNECTION: "upgrade",
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
    }
    resp.connection.protocol.read_timeout = None
    with mock.patch("aiohttp.client.WebSocketWriter") as WebSocketWriter:
        with mock.patch("aiohttp.client.os") as m_os:
            with mock.patch("aiohttp.client.ClientSession.request") as m_req:
                m_os.urandom.return_value = key_data
                m_req.return_value = loop.create_future()
                m_req.return_value.set_result(resp)
                WebSocketWriter.return_value = mock.Mock()

                resp = await aiohttp.ClientSession(loop=loop).ws_connect(
                    "http://test.org"
                )

                with pytest.raises(TypeError):
                    await resp.send_str(b"s")
                with pytest.raises(TypeError):
                    await resp.send_bytes("b")
                with pytest.raises(TypeError):
                    await resp.send_json(set())


async def test_reader_read_exception(ws_key, key_data, loop) -> None:
    hresp = mock.Mock()
    hresp.status = 101
    hresp.headers = {
        hdrs.UPGRADE: "websocket",
        hdrs.CONNECTION: "upgrade",
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
    }
    hresp.connection.protocol.read_timeout = None
    with mock.patch("aiohttp.client.WebSocketWriter") as WebSocketWriter:
        with mock.patch("aiohttp.client.os") as m_os:
            with mock.patch("aiohttp.client.ClientSession.request") as m_req:
                m_os.urandom.return_value = key_data
                m_req.return_value = loop.create_future()
                m_req.return_value.set_result(hresp)

                writer = mock.Mock()
                WebSocketWriter.return_value = writer
                writer.close = make_mocked_coro()

                session = aiohttp.ClientSession(loop=loop)
                resp = await session.ws_connect("http://test.org")

                exc = ValueError()
                resp._reader.set_exception(exc)

                msg = await resp.receive()
                assert msg.type == aiohttp.WSMsgType.ERROR
                assert resp.exception() is exc

                await session.close()


async def test_receive_runtime_err(loop) -> None:
    timeout = aiohttp.ClientWSTimeout(ws_receive=10.0)
    resp = client.ClientWebSocketResponse(
        mock.Mock(), mock.Mock(), mock.Mock(), mock.Mock(), timeout, True, True, loop
    )
    resp._waiting = True

    with pytest.raises(RuntimeError):
        await resp.receive()


async def test_ws_connect_close_resp_on_err(loop, ws_key, key_data) -> None:
    resp = mock.Mock()
    resp.status = 500
    resp.headers = {
        hdrs.UPGRADE: "websocket",
        hdrs.CONNECTION: "upgrade",
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
    }
    with mock.patch("aiohttp.client.os") as m_os:
        with mock.patch("aiohttp.client.ClientSession.request") as m_req:
            m_os.urandom.return_value = key_data
            m_req.return_value = loop.create_future()
            m_req.return_value.set_result(resp)

            with pytest.raises(client.WSServerHandshakeError):
                await aiohttp.ClientSession(loop=loop).ws_connect(
                    "http://test.org", protocols=("t1", "t2", "chat")
                )
            resp.close.assert_called_with()


async def test_ws_connect_non_overlapped_protocols(ws_key, loop, key_data) -> None:
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: "websocket",
        hdrs.CONNECTION: "upgrade",
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
        hdrs.SEC_WEBSOCKET_PROTOCOL: "other,another",
    }
    resp.connection.protocol.read_timeout = None
    with mock.patch("aiohttp.client.os") as m_os:
        with mock.patch("aiohttp.client.ClientSession.request") as m_req:
            m_os.urandom.return_value = key_data
            m_req.return_value = loop.create_future()
            m_req.return_value.set_result(resp)

            res = await aiohttp.ClientSession(loop=loop).ws_connect(
                "http://test.org", protocols=("t1", "t2", "chat")
            )

    assert res.protocol is None


async def test_ws_connect_non_overlapped_protocols_2(ws_key, loop, key_data) -> None:
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: "websocket",
        hdrs.CONNECTION: "upgrade",
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
        hdrs.SEC_WEBSOCKET_PROTOCOL: "other,another",
    }
    resp.connection.protocol.read_timeout = None
    with mock.patch("aiohttp.client.os") as m_os:
        with mock.patch("aiohttp.client.ClientSession.request") as m_req:
            m_os.urandom.return_value = key_data
            m_req.return_value = loop.create_future()
            m_req.return_value.set_result(resp)

            connector = aiohttp.TCPConnector(loop=loop, force_close=True)
            res = await aiohttp.ClientSession(
                connector=connector, loop=loop
            ).ws_connect("http://test.org", protocols=("t1", "t2", "chat"))

    assert res.protocol is None
    del res


async def test_ws_connect_deflate(loop, ws_key, key_data) -> None:
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: "websocket",
        hdrs.CONNECTION: "upgrade",
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
        hdrs.SEC_WEBSOCKET_EXTENSIONS: "permessage-deflate",
    }
    resp.connection.protocol.read_timeout = None
    with mock.patch("aiohttp.client.os") as m_os:
        with mock.patch("aiohttp.client.ClientSession.request") as m_req:
            m_os.urandom.return_value = key_data
            m_req.return_value = loop.create_future()
            m_req.return_value.set_result(resp)

            res = await aiohttp.ClientSession(loop=loop).ws_connect(
                "http://test.org", compress=15
            )

    assert res.compress == 15
    assert res.client_notakeover is False


async def test_ws_connect_deflate_per_message(loop, ws_key, key_data) -> None:
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: "websocket",
        hdrs.CONNECTION: "upgrade",
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
        hdrs.SEC_WEBSOCKET_EXTENSIONS: "permessage-deflate",
    }
    resp.connection.protocol.read_timeout = None
    with mock.patch("aiohttp.client.WebSocketWriter") as WebSocketWriter:
        with mock.patch("aiohttp.client.os") as m_os:
            with mock.patch("aiohttp.client.ClientSession.request") as m_req:
                m_os.urandom.return_value = key_data
                m_req.return_value = loop.create_future()
                m_req.return_value.set_result(resp)
                writer = WebSocketWriter.return_value = mock.Mock()
                send_frame = writer.send_frame = make_mocked_coro()

                session = aiohttp.ClientSession(loop=loop)
                resp = await session.ws_connect("http://test.org")

                await resp.send_str("string", compress=-1)
                send_frame.assert_called_with(
                    b"string", aiohttp.WSMsgType.TEXT, compress=-1
                )

                await resp.send_bytes(b"bytes", compress=15)
                send_frame.assert_called_with(
                    b"bytes", aiohttp.WSMsgType.BINARY, compress=15
                )

                await resp.send_json([{}], compress=-9)
                send_frame.assert_called_with(
                    b"[{}]", aiohttp.WSMsgType.TEXT, compress=-9
                )

                await resp.send_frame(b"[{}]", aiohttp.WSMsgType.TEXT, compress=-9)
                send_frame.assert_called_with(b"[{}]", aiohttp.WSMsgType.TEXT, -9)

                await session.close()


async def test_ws_connect_deflate_server_not_support(loop, ws_key, key_data) -> None:
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: "websocket",
        hdrs.CONNECTION: "upgrade",
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
    }
    resp.connection.protocol.read_timeout = None
    with mock.patch("aiohttp.client.os") as m_os:
        with mock.patch("aiohttp.client.ClientSession.request") as m_req:
            m_os.urandom.return_value = key_data
            m_req.return_value = loop.create_future()
            m_req.return_value.set_result(resp)

            res = await aiohttp.ClientSession(loop=loop).ws_connect(
                "http://test.org", compress=15
            )

    assert res.compress == 0
    assert res.client_notakeover is False


async def test_ws_connect_deflate_notakeover(loop, ws_key, key_data) -> None:
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: "websocket",
        hdrs.CONNECTION: "upgrade",
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
        hdrs.SEC_WEBSOCKET_EXTENSIONS: "permessage-deflate; "
        "client_no_context_takeover",
    }
    resp.connection.protocol.read_timeout = None
    with mock.patch("aiohttp.client.os") as m_os:
        with mock.patch("aiohttp.client.ClientSession.request") as m_req:
            m_os.urandom.return_value = key_data
            m_req.return_value = loop.create_future()
            m_req.return_value.set_result(resp)

            res = await aiohttp.ClientSession(loop=loop).ws_connect(
                "http://test.org", compress=15
            )

    assert res.compress == 15
    assert res.client_notakeover is True


async def test_ws_connect_deflate_client_wbits(loop, ws_key, key_data) -> None:
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: "websocket",
        hdrs.CONNECTION: "upgrade",
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
        hdrs.SEC_WEBSOCKET_EXTENSIONS: "permessage-deflate; "
        "client_max_window_bits=10",
    }
    resp.connection.protocol.read_timeout = None
    with mock.patch("aiohttp.client.os") as m_os:
        with mock.patch("aiohttp.client.ClientSession.request") as m_req:
            m_os.urandom.return_value = key_data
            m_req.return_value = loop.create_future()
            m_req.return_value.set_result(resp)

            res = await aiohttp.ClientSession(loop=loop).ws_connect(
                "http://test.org", compress=15
            )

    assert res.compress == 10
    assert res.client_notakeover is False


async def test_ws_connect_deflate_client_wbits_bad(loop, ws_key, key_data) -> None:
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: "websocket",
        hdrs.CONNECTION: "upgrade",
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
        hdrs.SEC_WEBSOCKET_EXTENSIONS: "permessage-deflate; "
        "client_max_window_bits=6",
    }
    with mock.patch("aiohttp.client.os") as m_os:
        with mock.patch("aiohttp.client.ClientSession.request") as m_req:
            m_os.urandom.return_value = key_data
            m_req.return_value = loop.create_future()
            m_req.return_value.set_result(resp)

            with pytest.raises(client.WSServerHandshakeError):
                await aiohttp.ClientSession(loop=loop).ws_connect(
                    "http://test.org", compress=15
                )


async def test_ws_connect_deflate_server_ext_bad(loop, ws_key, key_data) -> None:
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: "websocket",
        hdrs.CONNECTION: "upgrade",
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
        hdrs.SEC_WEBSOCKET_EXTENSIONS: "permessage-deflate; bad",
    }
    with mock.patch("aiohttp.client.os") as m_os:
        with mock.patch("aiohttp.client.ClientSession.request") as m_req:
            m_os.urandom.return_value = key_data
            m_req.return_value = loop.create_future()
            m_req.return_value.set_result(resp)

            with pytest.raises(client.WSServerHandshakeError):
                await aiohttp.ClientSession(loop=loop).ws_connect(
                    "http://test.org", compress=15
                )
