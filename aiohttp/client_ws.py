"""WebSocket client for asyncio."""

import asyncio
import json
import sys

from ._ws_impl import CLOSED_MESSAGE, WebSocketError, WSMessage, WSMsgType

PY_35 = sys.version_info >= (3, 5)
PY_352 = sys.version_info >= (3, 5, 2)


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

    def send_json(self, data, *, dumps=json.dumps):
        self.send_str(dumps(data))

    @asyncio.coroutine
    def close(self, *, code=1000, message=b''):
        if not self._closed:
            self._closed = True
            try:
                self._writer.close(code, message)
            except asyncio.CancelledError:
                self._close_code = 1006
                self._response.close()
                raise
            except Exception as exc:
                self._close_code = 1006
                self._exception = exc
                self._response.close()
                return True

            if self._closing:
                self._response.close()
                return True

            while True:
                try:
                    msg = yield from asyncio.wait_for(
                        self._reader.read(), self._timeout, loop=self._loop)
                except asyncio.CancelledError:
                    self._close_code = 1006
                    self._response.close()
                    raise
                except Exception as exc:
                    self._close_code = 1006
                    self._exception = exc
                    self._response.close()
                    return True

                if msg.type == WSMsgType.CLOSE:
                    self._close_code = msg.data
                    self._response.close()
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
                    return CLOSED_MESSAGE

                try:
                    msg = yield from self._reader.read()
                except (asyncio.CancelledError, asyncio.TimeoutError):
                    raise
                except WebSocketError as exc:
                    self._close_code = exc.code
                    yield from self.close(code=exc.code)
                    return WSMessage(WSMsgType.ERROR, exc, None)
                except Exception as exc:
                    self._exception = exc
                    self._closing = True
                    self._close_code = 1006
                    yield from self.close()
                    return WSMessage(WSMsgType.ERROR, exc, None)

                if msg.type == WSMsgType.CLOSE:
                    self._closing = True
                    self._close_code = msg.data
                    if not self._closed and self._autoclose:
                        yield from self.close()
                    return msg
                if msg.type == WSMsgType.PING and self._autoping:
                    self.pong(msg.data)
                elif msg.type == WSMsgType.PONG and self._autoping:
                    continue
                else:
                    return msg
        finally:
            self._waiting = False

    @asyncio.coroutine
    def receive_str(self):
        msg = yield from self.receive()
        if msg.type != WSMsgType.TEXT:
            raise TypeError(
                "Received message {}:{!r} is not str".format(msg.type,
                                                             msg.data))
        return msg.data

    @asyncio.coroutine
    def receive_bytes(self):
        msg = yield from self.receive()
        if msg.type != WSMsgType.BINARY:
            raise TypeError(
                "Received message {}:{!r} is not bytes".format(msg.type,
                                                               msg.data))
        return msg.data

    @asyncio.coroutine
    def receive_json(self, *, loads=json.loads):
        data = yield from self.receive_str()
        return loads(data)

    if PY_35:
        def __aiter__(self):
            return self

        if not PY_352:  # pragma: no cover
            __aiter__ = asyncio.coroutine(__aiter__)

        @asyncio.coroutine
        def __anext__(self):
            msg = yield from self.receive()
            if msg.type == WSMsgType.CLOSE:
                raise StopAsyncIteration  # NOQA
            return msg
