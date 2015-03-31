"""WebSocket client for asyncio."""

import asyncio
import base64
import hashlib
import os

from aiohttp import client, hdrs
from .errors import WSServerHandshakeError
from .websocket import WS_KEY, Message
from .websocket import WebSocketParser, WebSocketWriter, WebSocketError
from .websocket import MSG_BINARY, MSG_TEXT, MSG_CLOSE, MSG_PING, MSG_PONG

__all__ = ('ws_connect', 'MsgType')


try:
    from enum import IntEnum
except ImportError:  # pragma: no cover
    IntEnum = object


class MsgType(IntEnum):

    text = MSG_TEXT
    binary = MSG_BINARY
    ping = MSG_PING
    pong = MSG_PONG
    close = MSG_CLOSE
    closed = 20
    error = 21

closedMessage = Message(MsgType.closed, None, None)


@asyncio.coroutine
def ws_connect(url, protocols=(), timeout=10.0, connector=None,
               autoclose=True, autoping=True, loop=None):
    """Initiate websocket connection."""
    if loop is None:
        loop = asyncio.get_event_loop()

    sec_key = base64.b64encode(os.urandom(16))

    headers = {
        hdrs.UPGRADE: hdrs.WEBSOCKET,
        hdrs.CONNECTION: hdrs.UPGRADE,
        hdrs.SEC_WEBSOCKET_VERSION: '13',
        hdrs.SEC_WEBSOCKET_KEY: sec_key.decode(),
    }
    if protocols:
        headers[hdrs.SEC_WEBSOCKET_PROTOCOL] = ','.join(protocols)

    # send request
    resp = yield from client.request(
        'get', url, headers=headers,
        read_until_eof=False,
        connector=connector, loop=loop)

    # check handshake
    if resp.status != 101:
        raise WSServerHandshakeError('Invalid response status')

    if resp.headers.get(hdrs.UPGRADE, '').lower() != 'websocket':
        raise WSServerHandshakeError('Invalid upgrade header')

    if resp.headers.get(hdrs.CONNECTION, '').lower() != 'upgrade':
        raise WSServerHandshakeError('Invalid connection header')

    # key calculation
    key = resp.headers.get(hdrs.SEC_WEBSOCKET_ACCEPT, '')
    match = base64.b64encode(hashlib.sha1(sec_key + WS_KEY).digest()).decode()
    if key != match:
        raise WSServerHandshakeError('Invalid challenge response')

    # websocket protocol
    protocol = None
    if protocols and hdrs.SEC_WEBSOCKET_PROTOCOL in resp.headers:
        resp_protocols = [proto.strip() for proto in
                          resp.headers[hdrs.SEC_WEBSOCKET_PROTOCOL].split(',')]

        for proto in resp_protocols:
            if proto in protocols:
                protocol = proto
                break

    reader = resp.connection.reader.set_parser(WebSocketParser)
    writer = WebSocketWriter(resp.connection.writer, use_mask=True)

    return ClientWebSocketResponse(
        reader, writer, protocol, resp, timeout, autoclose, autoping, loop)


class ClientWebSocketResponse:

    def __init__(self, reader, writer, protocol,
                 response, timeout, autoclose, autoping, loop):
        self._response = response
        self._conn = response.connection

        self._writer = writer
        self._reader = reader
        self._protocol = protocol
        self._closed = False
        self._closing = False
        self._close_code = None
        self._timeout = timeout
        self._autoclose = autoclose
        self._autoping = autoping
        self._loop = loop
        self._waiting = False
        self._exception = None

    @property
    def closed(self):
        return self._closed

    @property
    def close_code(self):
        return self._close_code

    @property
    def protocol(self):
        return self._protocol

    def exception(self):
        return self._exception

    def ping(self, message='b'):
        if self._closed:
            raise RuntimeError('websocket connection is closed')
        self._writer.ping(message)

    def pong(self, message='b'):
        if self._closed:
            raise RuntimeError('websocket connection is closed')
        self._writer.pong(message)

    def send_str(self, data):
        if self._closed:
            raise RuntimeError('websocket connection is closed')
        if not isinstance(data, str):
            raise TypeError('data argument must be str (%r)' % type(data))
        self._writer.send(data, binary=False)

    def send_bytes(self, data):
        if self._closed:
            raise RuntimeError('websocket connection is closed')
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError('data argument must be byte-ish (%r)' %
                            type(data))
        self._writer.send(data, binary=True)

    @asyncio.coroutine
    def close(self, *, code=1000, message=b''):
        if not self._closed:
            self._closed = True
            try:
                self._writer.close(code, message)
            except asyncio.CancelledError:
                self._close_code = 1006
                self._response.close(force=True)
                raise
            except Exception as exc:
                self._close_code = 1006
                self._exception = exc
                self._response.close(force=True)
                return True

            if self._closing:
                self._response.close(force=True)
                return True

            while True:
                try:
                    msg = yield from asyncio.wait_for(
                        self._reader.read(), self._timeout, loop=self._loop)
                except asyncio.CancelledError:
                    self._close_code = 1006
                    raise
                except Exception as exc:
                    self._close_code = 1006
                    self._exception = exc
                    self._response.close(force=True)
                    return True

                if msg.tp == MsgType.close:
                    self._close_code = msg.data
                    self._response.close(force=True)
                    return True
        else:
            return False

    @asyncio.coroutine
    def receive(self):
        if self._waiting:
            raise RuntimeError('Concurrent call to receive() is not allowed')

        self._waiting = True
        try:
            while True:
                if self._closed:
                    return closedMessage

                try:
                    msg = yield from self._reader.read()
                except (asyncio.CancelledError, asyncio.TimeoutError):
                    raise
                except WebSocketError as exc:
                    self._close_code = exc.code
                    yield from self.close(code=exc.code)
                    return Message(MsgType.error, exc, None)
                except Exception as exc:
                    self._exception = exc
                    self._closing = True
                    self._close_code = 1006
                    yield from self.close()
                    return Message(MsgType.error, exc, None)

                if msg.tp == MsgType.close:
                    self._closing = True
                    self._close_code = msg.data
                    if not self._closed and self._autoclose:
                        yield from self.close()
                    return msg
                elif not self._closed:
                    if msg.tp == MsgType.ping and self._autoping:
                        self._writer.pong(msg.data)
                    elif msg.tp == MsgType.pong and self._autoping:
                        continue
                    else:
                        return msg
        finally:
            self._waiting = False
