"""WebSocket client for asyncio."""

import asyncio
import json
import sys

from ._ws_impl import (CLOSED_MESSAGE, CLOSING_MESSAGE,
                       WebSocketError, WSMessage, WSMsgType)
from .errors import ServerDisconnectedError
from .helpers import create_future

PY_35 = sys.version_info >= (3, 5)
PY_352 = sys.version_info >= (3, 5, 2)


class ClientWebSocketResponse:

    def __init__(self, reader, writer, protocol,
                 response, timeout, autoclose, autoping, loop, *,
                 time_service=None,
                 receive_timeout=None, heartbeat=None):
        self._response = response
        self._conn = response.connection

        self._writer = writer
        self._reader = reader
        self._protocol = protocol
        self._time_service = time_service
        self._closed = False
        self._closing = False
        self._close_code = None
        self._timeout = timeout
        self._receive_timeout = receive_timeout
        self._autoclose = autoclose
        self._autoping = autoping
        self._heartbeat = heartbeat
        self._heartbeat_cb = None
        self._pong_response_cb = None
        self._loop = loop
        self._waiting = None
        self._exception = None

        self._reset_heartbeat()

    def _cancel_heartbeat(self):
        if self._pong_response_cb is not None:
            self._pong_response_cb.cancel()
            self._pong_response_cb = None

        if self._heartbeat_cb is not None:
            self._heartbeat_cb.cancel()
            self._heartbeat_cb = None

    def _reset_heartbeat(self):
        self._cancel_heartbeat()

        if self._heartbeat is not None:
            self._heartbeat_cb = self._time_service.call_later(
                self._heartbeat, self._send_heartbeat)

    def _send_heartbeat(self):
        if self._heartbeat is not None and not self._closed:
            self.ping()

            if self._pong_response_cb is not None:
                self._pong_response_cb.cancel()
            self._pong_response_cb = self._time_service.call_later(
                self._heartbeat/2.0, self._pong_not_received)

    def _pong_not_received(self):
        self._closed = True
        self._close_code = 1006
        self._exception = asyncio.TimeoutError()
        self._response.close()

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
        self._writer.ping(message)

    def pong(self, message='b'):
        self._writer.pong(message)

    def send_str(self, data):
        if not isinstance(data, str):
            raise TypeError('data argument must be str (%r)' % type(data))
        return self._writer.send(data, binary=False)

    def send_bytes(self, data):
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError('data argument must be byte-ish (%r)' %
                            type(data))
        return self._writer.send(data, binary=True)

    def send_json(self, data, *, dumps=json.dumps):
        return self.send_str(dumps(data))

    @asyncio.coroutine
    def close(self, *, code=1000, message=b''):
        # we need to break `receive()` cycle first,
        # `close()` may be called from different task
        if self._waiting is not None and not self._closed:
            self._reader.feed_data(CLOSING_MESSAGE, 0)
            yield from self._waiting

        if not self._closed:
            self._cancel_heartbeat()
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
    def receive(self, timeout=None):
        while True:
            if self._waiting is not None:
                raise RuntimeError(
                    'Concurrent call to receive() is not allowed')

            if self._closed:
                return CLOSED_MESSAGE
            elif self._closing:
                yield from self.close()
                return CLOSED_MESSAGE

            try:
                try:
                    self._waiting = create_future(self._loop)
                    with self._time_service.timeout(
                            timeout or self._receive_timeout):
                        msg = yield from self._reader.read()
                        self._reset_heartbeat()
                finally:
                    waiter = self._waiting
                    self._waiting = None
                    waiter.set_result(True)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                raise
            except ServerDisconnectedError:
                self._closed = True
                self._close_code = 1006
                return CLOSED_MESSAGE
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
            elif msg.type == WSMsgType.CLOSING:
                self._closing = True
            elif msg.type == WSMsgType.PING and self._autoping:
                self.pong(msg.data)
                continue
            elif msg.type == WSMsgType.PONG and self._autoping:
                continue

            return msg

    @asyncio.coroutine
    def receive_str(self, *, timeout=None):
        msg = yield from self.receive(timeout)
        if msg.type != WSMsgType.TEXT:
            raise TypeError(
                "Received message {}:{!r} is not str".format(msg.type,
                                                             msg.data))
        return msg.data

    @asyncio.coroutine
    def receive_bytes(self, *, timeout=None):
        msg = yield from self.receive(timeout)
        if msg.type != WSMsgType.BINARY:
            raise TypeError(
                "Received message {}:{!r} is not bytes".format(msg.type,
                                                               msg.data))
        return msg.data

    @asyncio.coroutine
    def receive_json(self, *, loads=json.loads, timeout=None):
        data = yield from self.receive_str(timeout=timeout)
        return loads(data)

    if PY_35:
        def __aiter__(self):
            return self

        if not PY_352:  # pragma: no cover
            __aiter__ = asyncio.coroutine(__aiter__)

        @asyncio.coroutine
        def __anext__(self):
            msg = yield from self.receive()
            if msg.type in (WSMsgType.CLOSE,
                            WSMsgType.CLOSING,
                            WSMsgType.CLOSED):
                raise StopAsyncIteration  # NOQA
            return msg
