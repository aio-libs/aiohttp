"""WebSocket client for asyncio."""

import asyncio
import base64
import hashlib
import os

from aiohttp import client, hdrs
from .errors import WSServerHandshakeError, WSServerDisconnectedError
from .websocket import WS_KEY, WebSocketParser, WebSocketWriter
from .websocket import MSG_BINARY, MSG_CLOSE, MSG_PING, MSG_PONG, MSG_TEXT

__all__ = ['ws_connect',
           'MSG_BINARY', 'MSG_CLOSE', 'MSG_PING', 'MSG_PONG', 'MSG_TEXT']


@asyncio.coroutine
def ws_connect(url, protocols=(), connector=None,
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
        'get', url, headers=headers, connector=connector, loop=loop)

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
        reader, writer, protocol, resp, autoclose, autoping, loop)


class ClientWebSocketResponse:

    def __init__(self, reader, writer, protocol,
                 response, autoclose, autoping, loop):
        self._response = response
        self._conn = response.connection

        self._writer = writer
        self._reader = reader
        self._protocol = protocol
        self._closed = False
        self._autoclose = autoclose
        self._autoping = autoping
        self._loop = loop
        self._close_exc = None

    @property
    def closed(self):
        return self._closed

    @property
    def protocol(self):
        return self._protocol

    def ping(self, message='b'):
        if self._closed:
            raise RuntimeError('websocket connection is closing')
        self._writer.ping(message)

    def pong(self, message='b'):
        if self._closed:
            raise RuntimeError('websocket connection is closing')
        self._writer.pong(message)

    def send_str(self, data):
        if self._closed:
            raise RuntimeError('websocket connection is closing')
        if not isinstance(data, str):
            raise TypeError('data argument must be str (%r)' % type(data))
        self._writer.send(data, binary=False)

    def send_bytes(self, data):
        if self._closed:
            raise RuntimeError('websocket connection is closing')
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError('data argument must be byte-ish (%r)' %
                            type(data))
        self._writer.send(data, binary=True)

    @asyncio.coroutine
    def close(self, *, code=1000, message=b''):
        if not self._closed:
            self._closed = True
            self._writer.close(code, message)

            while True:
                try:
                    msg = yield from self.receive()
                except asyncio.CancelledError:
                    self._response.close(force=True)
                    raise
                except Exception as exc:
                    self._response.close(force=True)
                    self._close_exc = exc
                    return True

                if msg.tp == MSG_CLOSE:
                    self._response.close(force=True)
                    return True
        else:
            return False

    def close_exception(self):
        return self._close_exc

    @asyncio.coroutine
    def receive(self):
        while True:
            try:
                msg = yield from self._reader.read()
            except (asyncio.CancelledError, asyncio.TimeoutError):
                raise
            except Exception as exc:
                raise WSServerDisconnectedError() from exc

            if msg.tp == MSG_CLOSE:
                if not self._closed and self._autoclose:
                    self._closed = True
                    self._writer.close(1000, b'')
                    self._response.close(force=True)
                return msg
            elif not self._closed:
                if msg.tp == MSG_PING:
                    if self._autoping:
                        self._writer.pong(msg.data)
                    else:
                        return msg
                elif msg.tp in (MSG_TEXT, MSG_BINARY):
                    return msg

    @asyncio.coroutine
    def receive_str(self):
        msg = yield from self.receive()
        if msg.tp != MSG_TEXT:
            raise TypeError(
                "Received message {}:{!r} is not str".format(
                    msg.tp, msg.data))
        return msg.data

    @asyncio.coroutine
    def receive_bytes(self):
        msg = yield from self.receive()
        if msg.tp != MSG_BINARY:
            raise TypeError(
                "Received message {}:{!r} is not bytes".format(
                    msg.tp, msg.data))
        return msg.data
