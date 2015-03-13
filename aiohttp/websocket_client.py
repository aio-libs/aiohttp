"""WebSocket client for asyncio."""
__all__ = ['ws_connect']
import asyncio
import base64
import hashlib
import os

from aiohttp import client, hdrs
from .errors import WSServerHandshakeError, WSServerDisconnectedError
from .websocket import WebSocketParser, WebSocketWriter
from .websocket import WS_KEY, MSG_BINARY, MSG_CLOSE, MSG_PING, MSG_TEXT


@asyncio.coroutine
def ws_connect(url, protocols=(), connector=None, loop=None):
    """
    """
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
    writer = WebSocketWriter(resp.connection.writer)

    return ClientWebSocketResponse(reader, writer, protocol, resp, loop)


class ClientWebSocketResponse:

    def __init__(self, reader, writer, protocol, response, loop):
        self._response = response
        self._conn = response.connection

        self._writer = writer
        self._reader = reader
        self._protocol = protocol
        self._closing = False
        self._loop = loop
        self._closing_fut = asyncio.Future(loop=loop)

    @property
    def closing(self):
        return self._closing

    @property
    def protocol(self):
        return self._protocol

    def ping(self, message='b'):
        if self._closing:
            raise RuntimeError('websocket connection is closing')
        self._writer.ping(message)

    def send_str(self, data):
        if self._closing:
            raise RuntimeError('websocket connection is closing')
        if not isinstance(data, str):
            raise TypeError('data argument must be str (%r)' % type(data))
        self._writer.send(data, binary=False)

    def send_bytes(self, data):
        if self._closing:
            raise RuntimeError('websocket connection is closing')
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError('data argument must be byte-ish (%r)' %
                            type(data))
        self._writer.send(data, binary=True)

    def close(self, *, code=1000, message=b''):
        if not self._closing:
            self._closing = True
            self._writer.close(code, message)

    @asyncio.coroutine
    def wait_closed(self):
        yield from self._closing_fut

    @asyncio.coroutine
    def receive(self):
        while True:
            try:
                msg = yield from self._reader.read()
            except Exception as exc:
                if not self._closing_fut.done():
                    self._closing_fut.set_exception(exc)
                raise

            if msg.tp == MSG_CLOSE:
                if self._closing:
                    self._response.close(force=True)
                    exc = WSServerDisconnectedError(msg.data, msg.extra)
                    self._closing_fut.set_exception(exc)
                    raise exc
                else:
                    self._closing = True
                    self._writer.close(msg.data, msg.extra)
                    # yield from self._conn._transport.drain()

                    self._response.close()
                    exc = WSServerDisconnectedError(msg.data, msg.extra)
                    self._closing_fut.set_result(exc)
                    return msg
            elif not self._closing:
                if msg.tp == MSG_PING:
                    self._writer.pong(msg.data)
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
