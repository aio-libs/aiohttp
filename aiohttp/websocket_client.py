"""WebSocket client for asyncio."""

import asyncio

import aiohttp
from .websocket import Message
from .websocket import WebSocketError
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
                    self._response.close(force=True)
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


@asyncio.coroutine
def ws_connect(url, *, protocols=(), timeout=10.0, connector=None,
               ws_response_class=ClientWebSocketResponse, autoclose=True,
               autoping=True, loop=None):

    if loop is None:
        asyncio.get_event_loop()

    if connector is None:
        connector = aiohttp.TCPConnector(loop=loop, force_close=True)

    session = aiohttp.ClientSession(loop=loop, connector=connector,
                                    ws_response_class=ws_response_class)

    try:
        resp = yield from session.ws_connect(
            url,
            protocols=protocols,
            timeout=timeout,
            autoclose=autoclose,
            autoping=autoping)
        return resp

    finally:
        session.detach()
