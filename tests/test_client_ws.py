import asyncio
import base64
import hashlib
import os
from unittest import mock

import pytest

import aiohttp
from aiohttp import client, hdrs, helpers
from aiohttp.http import WS_KEY
from aiohttp.log import ws_logger


@pytest.fixture
def key_data():
    return os.urandom(16)


@pytest.fixture
def key(key_data):
    return base64.b64encode(key_data)


@pytest.fixture
def ws_key(key):
    return base64.b64encode(hashlib.sha1(key + WS_KEY).digest()).decode()


@asyncio.coroutine
def test_ws_connect(ws_key, loop, key_data):
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: hdrs.WEBSOCKET,
        hdrs.CONNECTION: hdrs.UPGRADE,
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
        hdrs.SEC_WEBSOCKET_PROTOCOL: 'chat'
    }
    with mock.patch('aiohttp.client.os') as m_os:
        with mock.patch('aiohttp.client.ClientSession.get') as m_req:
            m_os.urandom.return_value = key_data
            m_req.return_value = helpers.create_future(loop)
            m_req.return_value.set_result(resp)

            res = yield from aiohttp.ClientSession(loop=loop).ws_connect(
                'http://test.org',
                protocols=('t1', 't2', 'chat'))

    assert isinstance(res, client.ClientWebSocketResponse)
    assert res.protocol == 'chat'
    assert hdrs.ORIGIN not in m_req.call_args[1]["headers"]


@asyncio.coroutine
def test_ws_connect_with_origin(key_data, loop):
    resp = mock.Mock()
    resp.status = 403
    with mock.patch('aiohttp.client.os') as m_os:
        with mock.patch('aiohttp.client.ClientSession.get') as m_req:
            m_os.urandom.return_value = key_data
            m_req.return_value = helpers.create_future(loop)
            m_req.return_value.set_result(resp)

            origin = 'https://example.org/page.html'
            with pytest.raises(client.WSServerHandshakeError):
                yield from aiohttp.ClientSession(loop=loop).ws_connect(
                    'http://test.org', origin=origin)

    assert hdrs.ORIGIN in m_req.call_args[1]["headers"]
    assert m_req.call_args[1]["headers"][hdrs.ORIGIN] == origin


@asyncio.coroutine
def test_ws_connect_custom_response(loop, ws_key, key_data):

    class CustomResponse(client.ClientWebSocketResponse):
        def read(self, decode=False):
            return 'customized!'

    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: hdrs.WEBSOCKET,
        hdrs.CONNECTION: hdrs.UPGRADE,
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
    }
    with mock.patch('aiohttp.client.os') as m_os:
        with mock.patch('aiohttp.client.ClientSession.get') as m_req:
            m_os.urandom.return_value = key_data
            m_req.return_value = helpers.create_future(loop)
            m_req.return_value.set_result(resp)

            res = yield from aiohttp.ClientSession(
                ws_response_class=CustomResponse, loop=loop).ws_connect(
                    'http://test.org')

    assert res.read() == 'customized!'


@asyncio.coroutine
def test_ws_connect_err_status(loop, ws_key, key_data):
    resp = mock.Mock()
    resp.status = 500
    resp.headers = {
        hdrs.UPGRADE: hdrs.WEBSOCKET,
        hdrs.CONNECTION: hdrs.UPGRADE,
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key
    }
    with mock.patch('aiohttp.client.os') as m_os:
        with mock.patch('aiohttp.client.ClientSession.get') as m_req:
            m_os.urandom.return_value = key_data
            m_req.return_value = helpers.create_future(loop)
            m_req.return_value.set_result(resp)

            with pytest.raises(client.WSServerHandshakeError) as ctx:
                yield from aiohttp.ClientSession(loop=loop).ws_connect(
                    'http://test.org',
                    protocols=('t1', 't2', 'chat'))

    assert ctx.value.message == 'Invalid response status'


@asyncio.coroutine
def test_ws_connect_err_upgrade(loop, ws_key, key_data):
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: 'test',
        hdrs.CONNECTION: hdrs.UPGRADE,
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key
    }
    with mock.patch('aiohttp.client.os') as m_os:
        with mock.patch('aiohttp.client.ClientSession.get') as m_req:
            m_os.urandom.return_value = key_data
            m_req.return_value = helpers.create_future(loop)
            m_req.return_value.set_result(resp)

            with pytest.raises(client.WSServerHandshakeError) as ctx:
                yield from aiohttp.ClientSession(loop=loop).ws_connect(
                    'http://test.org',
                    protocols=('t1', 't2', 'chat'))

    assert ctx.value.message == 'Invalid upgrade header'


@asyncio.coroutine
def test_ws_connect_err_conn(loop, ws_key, key_data):
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: hdrs.WEBSOCKET,
        hdrs.CONNECTION: 'close',
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key
    }
    with mock.patch('aiohttp.client.os') as m_os:
        with mock.patch('aiohttp.client.ClientSession.get') as m_req:
            m_os.urandom.return_value = key_data
            m_req.return_value = helpers.create_future(loop)
            m_req.return_value.set_result(resp)

            with pytest.raises(client.WSServerHandshakeError) as ctx:
                yield from aiohttp.ClientSession(loop=loop).ws_connect(
                    'http://test.org',
                    protocols=('t1', 't2', 'chat'))

    assert ctx.value.message == 'Invalid connection header'


@asyncio.coroutine
def test_ws_connect_err_challenge(loop, ws_key, key_data):
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: hdrs.WEBSOCKET,
        hdrs.CONNECTION: hdrs.UPGRADE,
        hdrs.SEC_WEBSOCKET_ACCEPT: 'asdfasdfasdfasdfasdfasdf'
    }
    with mock.patch('aiohttp.client.os') as m_os:
        with mock.patch('aiohttp.client.ClientSession.get') as m_req:
            m_os.urandom.return_value = key_data
            m_req.return_value = helpers.create_future(loop)
            m_req.return_value.set_result(resp)

            with pytest.raises(client.WSServerHandshakeError) as ctx:
                yield from aiohttp.ClientSession(loop=loop).ws_connect(
                    'http://test.org',
                    protocols=('t1', 't2', 'chat'))

    assert ctx.value.message == 'Invalid challenge response'


@asyncio.coroutine
def test_ws_connect_common_headers(ws_key, loop, key_data):
    """Emulate a headers dict being reused for a second ws_connect.

    In this scenario, we need to ensure that the newly generated secret key
    is sent to the server, not the stale key.
    """
    headers = {}

    @asyncio.coroutine
    def test_connection():
        @asyncio.coroutine
        def mock_get(*args, **kwargs):
            resp = mock.Mock()
            resp.status = 101
            key = kwargs.get('headers').get(hdrs.SEC_WEBSOCKET_KEY)
            accept = base64.b64encode(
                hashlib.sha1(base64.b64encode(base64.b64decode(key)) + WS_KEY)
                .digest()).decode()
            resp.headers = {
                hdrs.UPGRADE: hdrs.WEBSOCKET,
                hdrs.CONNECTION: hdrs.UPGRADE,
                hdrs.SEC_WEBSOCKET_ACCEPT: accept,
                hdrs.SEC_WEBSOCKET_PROTOCOL: 'chat'
            }
            return resp
        with mock.patch('aiohttp.client.os') as m_os:
            with mock.patch('aiohttp.client.ClientSession.get',
                            side_effect=mock_get) as m_req:
                m_os.urandom.return_value = key_data

                res = yield from aiohttp.ClientSession(loop=loop).ws_connect(
                    'http://test.org',
                    protocols=('t1', 't2', 'chat'),
                    headers=headers)

        assert isinstance(res, client.ClientWebSocketResponse)
        assert res.protocol == 'chat'
        assert hdrs.ORIGIN not in m_req.call_args[1]["headers"]

    yield from test_connection()
    # Generate a new ws key
    key_data = os.urandom(16)
    yield from test_connection()


@asyncio.coroutine
def test_close(loop, ws_key, key_data):
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: hdrs.WEBSOCKET,
        hdrs.CONNECTION: hdrs.UPGRADE,
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
    }
    with mock.patch('aiohttp.client.WebSocketWriter') as WebSocketWriter:
        with mock.patch('aiohttp.client.os') as m_os:
            with mock.patch('aiohttp.client.ClientSession.get') as m_req:
                m_os.urandom.return_value = key_data
                m_req.return_value = helpers.create_future(loop)
                m_req.return_value.set_result(resp)
                writer = WebSocketWriter.return_value = mock.Mock()

                session = aiohttp.ClientSession(loop=loop)
                resp = yield from session.ws_connect(
                    'http://test.org')
                assert not resp.closed

                resp._reader.feed_data(
                    aiohttp.WSMessage(aiohttp.WSMsgType.CLOSE, b'', b''), 0)

                res = yield from resp.close()
                writer.close.assert_called_with(1000, b'')
                assert resp.closed
                assert res
                assert resp.exception() is None

                # idempotent
                res = yield from resp.close()
                assert not res
                assert writer.close.call_count == 1

                session.close()


@asyncio.coroutine
def test_close_exc(loop, ws_key, key_data):
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: hdrs.WEBSOCKET,
        hdrs.CONNECTION: hdrs.UPGRADE,
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
    }
    with mock.patch('aiohttp.client.WebSocketWriter') as WebSocketWriter:
        with mock.patch('aiohttp.client.os') as m_os:
            with mock.patch('aiohttp.client.ClientSession.get') as m_req:
                m_os.urandom.return_value = key_data
                m_req.return_value = helpers.create_future(loop)
                m_req.return_value.set_result(resp)
                WebSocketWriter.return_value = mock.Mock()

                session = aiohttp.ClientSession(loop=loop)
                resp = yield from session.ws_connect('http://test.org')
                assert not resp.closed

                exc = ValueError()
                resp._reader.set_exception(exc)

                yield from resp.close()
                assert resp.closed
                assert resp.exception() is exc

                session.close()


@asyncio.coroutine
def test_close_exc2(loop, ws_key, key_data):
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: hdrs.WEBSOCKET,
        hdrs.CONNECTION: hdrs.UPGRADE,
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
    }
    with mock.patch('aiohttp.client.WebSocketWriter') as WebSocketWriter:
        with mock.patch('aiohttp.client.os') as m_os:
            with mock.patch('aiohttp.client.ClientSession.get') as m_req:
                m_os.urandom.return_value = key_data
                m_req.return_value = helpers.create_future(loop)
                m_req.return_value.set_result(resp)
                writer = WebSocketWriter.return_value = mock.Mock()

                resp = yield from aiohttp.ClientSession(loop=loop).ws_connect(
                    'http://test.org')
                assert not resp.closed

                exc = ValueError()
                writer.close.side_effect = exc

                yield from resp.close()
                assert resp.closed
                assert resp.exception() is exc

                resp._closed = False
                writer.close.side_effect = asyncio.CancelledError()
                with pytest.raises(asyncio.CancelledError):
                    yield from resp.close()


@asyncio.coroutine
def test_send_data_after_close(ws_key, key_data, loop, mocker):
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: hdrs.WEBSOCKET,
        hdrs.CONNECTION: hdrs.UPGRADE,
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
    }
    with mock.patch('aiohttp.client.os') as m_os:
        with mock.patch('aiohttp.client.ClientSession.get') as m_req:
            m_os.urandom.return_value = key_data
            m_req.return_value = helpers.create_future(loop)
            m_req.return_value.set_result(resp)

            resp = yield from aiohttp.ClientSession(loop=loop).ws_connect(
                'http://test.org')
            resp._writer._closing = True

            mocker.spy(ws_logger, 'warning')

            for meth, args in ((resp.ping, ()),
                               (resp.pong, ()),
                               (resp.send_str, ('s',)),
                               (resp.send_bytes, (b'b',)),
                               (resp.send_json, ({},))):
                meth(*args)
                assert ws_logger.warning.called
                ws_logger.warning.reset_mock()


@asyncio.coroutine
def test_send_data_type_errors(ws_key, key_data, loop):
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: hdrs.WEBSOCKET,
        hdrs.CONNECTION: hdrs.UPGRADE,
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
    }
    with mock.patch('aiohttp.client.WebSocketWriter') as WebSocketWriter:
        with mock.patch('aiohttp.client.os') as m_os:
            with mock.patch('aiohttp.client.ClientSession.get') as m_req:
                m_os.urandom.return_value = key_data
                m_req.return_value = helpers.create_future(loop)
                m_req.return_value.set_result(resp)
                WebSocketWriter.return_value = mock.Mock()

                resp = yield from aiohttp.ClientSession(loop=loop).ws_connect(
                    'http://test.org')

                pytest.raises(TypeError, resp.send_str, b's')
                pytest.raises(TypeError, resp.send_bytes, 'b')
                pytest.raises(TypeError, resp.send_json, set())


@asyncio.coroutine
def test_reader_read_exception(ws_key, key_data, loop):
    hresp = mock.Mock()
    hresp.status = 101
    hresp.headers = {
        hdrs.UPGRADE: hdrs.WEBSOCKET,
        hdrs.CONNECTION: hdrs.UPGRADE,
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
    }
    with mock.patch('aiohttp.client.WebSocketWriter') as WebSocketWriter:
        with mock.patch('aiohttp.client.os') as m_os:
            with mock.patch('aiohttp.client.ClientSession.get') as m_req:
                m_os.urandom.return_value = key_data
                m_req.return_value = helpers.create_future(loop)
                m_req.return_value.set_result(hresp)
                WebSocketWriter.return_value = mock.Mock()

                session = aiohttp.ClientSession(loop=loop)
                resp = yield from session.ws_connect('http://test.org')

                exc = ValueError()
                resp._reader.set_exception(exc)

                msg = yield from resp.receive()
                assert msg.type == aiohttp.WSMsgType.ERROR
                assert msg.type is msg.tp
                assert resp.exception() is exc

                session.close()


@asyncio.coroutine
def test_receive_runtime_err(loop):
    resp = client.ClientWebSocketResponse(
        mock.Mock(), mock.Mock(), mock.Mock(), mock.Mock(), 10.0,
        True, True, loop)
    resp._waiting = True

    with pytest.raises(RuntimeError):
        yield from resp.receive()


@asyncio.coroutine
def test_ws_connect_close_resp_on_err(loop, ws_key, key_data):
    resp = mock.Mock()
    resp.status = 500
    resp.headers = {
        hdrs.UPGRADE: hdrs.WEBSOCKET,
        hdrs.CONNECTION: hdrs.UPGRADE,
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key
    }
    with mock.patch('aiohttp.client.os') as m_os:
        with mock.patch('aiohttp.client.ClientSession.get') as m_req:
            m_os.urandom.return_value = key_data
            m_req.return_value = helpers.create_future(loop)
            m_req.return_value.set_result(resp)

            with pytest.raises(client.WSServerHandshakeError):
                yield from aiohttp.ClientSession(loop=loop).ws_connect(
                    'http://test.org',
                    protocols=('t1', 't2', 'chat'))
            resp.close.assert_called_with()


@asyncio.coroutine
def test_ws_connect_non_overlapped_protocols(ws_key, loop, key_data):
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: hdrs.WEBSOCKET,
        hdrs.CONNECTION: hdrs.UPGRADE,
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
        hdrs.SEC_WEBSOCKET_PROTOCOL: 'other,another'
    }
    with mock.patch('aiohttp.client.os') as m_os:
        with mock.patch('aiohttp.client.ClientSession.get') as m_req:
            m_os.urandom.return_value = key_data
            m_req.return_value = helpers.create_future(loop)
            m_req.return_value.set_result(resp)

            res = yield from aiohttp.ClientSession(loop=loop).ws_connect(
                'http://test.org',
                protocols=('t1', 't2', 'chat'))

    assert res.protocol is None


@asyncio.coroutine
def test_ws_connect_non_overlapped_protocols_2(ws_key, loop, key_data):
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: hdrs.WEBSOCKET,
        hdrs.CONNECTION: hdrs.UPGRADE,
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
        hdrs.SEC_WEBSOCKET_PROTOCOL: 'other,another'
    }
    with mock.patch('aiohttp.client.os') as m_os:
        with mock.patch('aiohttp.client.ClientSession.get') as m_req:
            m_os.urandom.return_value = key_data
            m_req.return_value = helpers.create_future(loop)
            m_req.return_value.set_result(resp)

            connector = aiohttp.TCPConnector(loop=loop, force_close=True)
            res = yield from aiohttp.ClientSession(
                connector=connector, loop=loop).ws_connect(
                'http://test.org',
                protocols=('t1', 't2', 'chat'))

    assert res.protocol is None
    del res
