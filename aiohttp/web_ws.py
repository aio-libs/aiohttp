import asyncio
import json
from collections import namedtuple

import async_timeout

from . import hdrs
from .helpers import call_later
from .http import (WS_CLOSED_MESSAGE, WS_CLOSING_MESSAGE, HttpProcessingError,
                   WebSocketError, WebSocketReader, WSMessage, WSMsgType,
                   do_handshake)
from .streams import FlowControlDataQueue
from .web_exceptions import (HTTPBadRequest, HTTPInternalServerError,
                             HTTPMethodNotAllowed)
from .web_response import StreamResponse


__all__ = ('WebSocketResponse', 'WebSocketReady', 'MsgType', 'WSMsgType',)

THRESHOLD_CONNLOST_ACCESS = 5


# deprecated since 1.0
MsgType = WSMsgType


class WebSocketReady(namedtuple('WebSocketReady', 'ok protocol')):
    def __bool__(self):
        return self.ok


class WebSocketResponse(StreamResponse):

    def __init__(self, *,
                 timeout=10.0, receive_timeout=None,
                 autoclose=True, autoping=True, heartbeat=None,
                 protocols=(), compress=True):
        super().__init__(status=101)
        self._protocols = protocols
        self._ws_protocol = None
        self._writer = None
        self._reader = None
        self._closed = False
        self._closing = False
        self._conn_lost = 0
        self._close_code = None
        self._loop = None
        self._waiting = None
        self._exception = None
        self._timeout = timeout
        self._receive_timeout = receive_timeout
        self._autoclose = autoclose
        self._autoping = autoping
        self._heartbeat = heartbeat
        self._heartbeat_cb = None
        if heartbeat is not None:
            self._pong_heartbeat = heartbeat/2.0
        self._pong_response_cb = None
        self._compress = compress

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
            self._heartbeat_cb = call_later(
                self._send_heartbeat, self._heartbeat, self._loop)

    def _send_heartbeat(self):
        if self._heartbeat is not None and not self._closed:
            self._writer.ping()

            if self._pong_response_cb is not None:
                self._pong_response_cb.cancel()
            self._pong_response_cb = call_later(
                self._pong_not_received, self._pong_heartbeat, self._loop)

    def _pong_not_received(self):
        if self._req is not None and self._req.transport is not None:
            self._closed = True
            self._close_code = 1006
            self._exception = asyncio.TimeoutError()
            self._req.transport.close()

    async def prepare(self, request):
        # make pre-check to don't hide it by do_handshake() exceptions
        if self._payload_writer is not None:
            return self._payload_writer

        protocol, writer = self._pre_start(request)
        payload_writer = await super().prepare(request)
        self._post_start(request, protocol, writer)
        await payload_writer.drain()
        return payload_writer

    def _pre_start(self, request):
        self._loop = request.loop

        try:
            status, headers, _, writer, protocol, compress = do_handshake(
                request.method, request.headers, request._protocol.writer,
                self._protocols, compress=self._compress)
        except HttpProcessingError as err:
            if err.code == 405:
                raise HTTPMethodNotAllowed(
                    request.method, [hdrs.METH_GET])
            elif err.code == 400:
                raise HTTPBadRequest(text=err.message, headers=err.headers)
            else:  # pragma: no cover
                raise HTTPInternalServerError() from err

        self._reset_heartbeat()

        if self.status != status:
            self.set_status(status)
        for k, v in headers:
            self.headers[k] = v
        self.force_close()
        self._compress = compress
        return protocol, writer

    def _post_start(self, request, protocol, writer):
        self._ws_protocol = protocol
        self._writer = writer
        self._reader = FlowControlDataQueue(
            request._protocol, limit=2 ** 16, loop=self._loop)
        request.protocol.set_parser(WebSocketReader(
            self._reader, compress=self._compress))

    def can_prepare(self, request):
        if self._writer is not None:
            raise RuntimeError('Already started')
        try:
            _, _, _, _, protocol, _ = do_handshake(
                request.method, request.headers, request._protocol.writer,
                self._protocols)
        except HttpProcessingError:
            return WebSocketReady(False, None)
        else:
            return WebSocketReady(True, protocol)

    @property
    def closed(self):
        return self._closed

    @property
    def close_code(self):
        return self._close_code

    @property
    def ws_protocol(self):
        return self._ws_protocol

    @property
    def compress(self):
        return self._compress

    def exception(self):
        return self._exception

    async def ping(self, message='b'):
        if self._writer is None:
            raise RuntimeError('Call .prepare() first')
        await self._writer.ping(message)

    async def pong(self, message='b'):
        # unsolicited pong
        if self._writer is None:
            raise RuntimeError('Call .prepare() first')
        await self._writer.pong(message)

    async def send_str(self, data):
        if self._writer is None:
            raise RuntimeError('Call .prepare() first')
        if not isinstance(data, str):
            raise TypeError('data argument must be str (%r)' % type(data))
        await self._writer.send(data, binary=False)

    async def send_bytes(self, data):
        if self._writer is None:
            raise RuntimeError('Call .prepare() first')
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError('data argument must be byte-ish (%r)' %
                            type(data))
        await self._writer.send(data, binary=True)

    async def send_json(self, data, *, dumps=json.dumps):
        await self.send_str(dumps(data))

    async def write_eof(self):
        if self._eof_sent:
            return
        if self._payload_writer is None:
            raise RuntimeError("Response has not been started")

        await self.close()
        self._eof_sent = True

    async def close(self, *, code=1000, message=b''):
        if self._writer is None:
            raise RuntimeError('Call .prepare() first')

        self._cancel_heartbeat()

        # we need to break `receive()` cycle first,
        # `close()` may be called from different task
        if self._waiting is not None and not self._closed:
            self._reader.feed_data(WS_CLOSING_MESSAGE, 0)
            await self._waiting

        if not self._closed:
            self._closed = True
            try:
                self._writer.close(code, message)
                await self.drain()
            except (asyncio.CancelledError, asyncio.TimeoutError):
                self._close_code = 1006
                raise
            except Exception as exc:
                self._close_code = 1006
                self._exception = exc
                return True

            if self._closing:
                return True

            try:
                with async_timeout.timeout(self._timeout, loop=self._loop):
                    msg = await self._reader.read()
            except asyncio.CancelledError:
                self._close_code = 1006
                raise
            except Exception as exc:
                self._close_code = 1006
                self._exception = exc
                return True

            if msg.type == WSMsgType.CLOSE:
                self._close_code = msg.data
                return True

            self._close_code = 1006
            self._exception = asyncio.TimeoutError()
            return True
        else:
            return False

    async def receive(self, timeout=None):
        if self._reader is None:
            raise RuntimeError('Call .prepare() first')

        while True:
            if self._waiting is not None:
                raise RuntimeError(
                    'Concurrent call to receive() is not allowed')

            if self._closed:
                self._conn_lost += 1
                if self._conn_lost >= THRESHOLD_CONNLOST_ACCESS:
                    raise RuntimeError('WebSocket connection is closed.')
                return WS_CLOSED_MESSAGE
            elif self._closing:
                return WS_CLOSING_MESSAGE

            try:
                self._waiting = self._loop.create_future()
                try:
                    with async_timeout.timeout(
                            timeout or self._receive_timeout, loop=self._loop):
                        msg = await self._reader.read()
                    self._reset_heartbeat()
                finally:
                    waiter = self._waiting
                    self._waiting = None
                    waiter.set_result(True)
            except (asyncio.CancelledError, asyncio.TimeoutError) as exc:
                self._close_code = 1006
                raise
            except WebSocketError as exc:
                self._close_code = exc.code
                await self.close(code=exc.code)
                return WSMessage(WSMsgType.ERROR, exc, None)
            except Exception as exc:
                self._exception = exc
                self._closing = True
                self._close_code = 1006
                await self.close()
                return WSMessage(WSMsgType.ERROR, exc, None)

            if msg.type == WSMsgType.CLOSE:
                self._closing = True
                self._close_code = msg.data
                if not self._closed and self._autoclose:
                    await self.close()
            elif msg.type == WSMsgType.CLOSING:
                self._closing = True
            elif msg.type == WSMsgType.PING and self._autoping:
                await self.pong(msg.data)
                continue
            elif msg.type == WSMsgType.PONG and self._autoping:
                continue

            return msg

    async def receive_str(self, *, timeout=None):
        msg = await self.receive(timeout)
        if msg.type != WSMsgType.TEXT:
            raise TypeError(
                "Received message {}:{!r} is not WSMsgType.TEXT".format(
                    msg.type, msg.data))
        return msg.data

    async def receive_bytes(self, *, timeout=None):
        msg = await self.receive(timeout)
        if msg.type != WSMsgType.BINARY:
            raise TypeError(
                "Received message {}:{!r} is not bytes".format(msg.type,
                                                               msg.data))
        return msg.data

    async def receive_json(self, *, loads=json.loads, timeout=None):
        data = await self.receive_str(timeout=timeout)
        return loads(data)

    async def write(self, data):
        raise RuntimeError("Cannot call .write() for websocket")

    def __aiter__(self):
        return self

    async def __anext__(self):
        msg = await self.receive()
        if msg.type in (WSMsgType.CLOSE,
                        WSMsgType.CLOSING,
                        WSMsgType.CLOSED):
            raise StopAsyncIteration  # NOQA
        return msg
