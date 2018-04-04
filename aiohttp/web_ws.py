import asyncio
import base64
import binascii
import hashlib
import json

import async_timeout
import attr
from multidict import CIMultiDict

from . import hdrs
from .helpers import call_later, set_result
from .http import (WS_CLOSED_MESSAGE, WS_CLOSING_MESSAGE, WS_KEY,
                   WebSocketError, WebSocketReader, WebSocketWriter, WSMessage,
                   WSMsgType, ws_ext_gen, ws_ext_parse)
from .log import ws_logger
from .streams import EofStream, FlowControlDataQueue
from .web_exceptions import HTTPBadRequest, HTTPException, HTTPMethodNotAllowed
from .web_response import StreamResponse


__all__ = ('WebSocketResponse', 'WebSocketReady', 'WSMsgType',)

THRESHOLD_CONNLOST_ACCESS = 5


@attr.s(frozen=True, slots=True)
class WebSocketReady:
    ok = attr.ib(type=bool)
    protocol = attr.ib(type=str)

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
            self._pong_heartbeat = heartbeat / 2.0
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
            # fire-and-forget a task is not perfect but maybe ok for
            # sending ping. Otherwise we need a long-living heartbeat
            # task in the class.
            self._loop.create_task(self._writer.ping())

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

    def _handshake(self, request):
        headers = request.headers
        if request.method != hdrs.METH_GET:
            raise HTTPMethodNotAllowed(request.method, [hdrs.METH_GET])
        if 'websocket' != headers.get(hdrs.UPGRADE, '').lower().strip():
            raise HTTPBadRequest(
                text=('No WebSocket UPGRADE hdr: {}\n Can '
                      '"Upgrade" only to "WebSocket".')
                .format(headers.get(hdrs.UPGRADE)))

        if 'upgrade' not in headers.get(hdrs.CONNECTION, '').lower():
            raise HTTPBadRequest(
                text='No CONNECTION upgrade hdr: {}'.format(
                    headers.get(hdrs.CONNECTION)))

        # find common sub-protocol between client and server
        protocol = None
        if hdrs.SEC_WEBSOCKET_PROTOCOL in headers:
            req_protocols = [str(proto.strip()) for proto in
                             headers[hdrs.SEC_WEBSOCKET_PROTOCOL].split(',')]

            for proto in req_protocols:
                if proto in self._protocols:
                    protocol = proto
                    break
            else:
                # No overlap found: Return no protocol as per spec
                ws_logger.warning(
                    'Client protocols %r don’t overlap server-known ones %r',
                    req_protocols, self._protocols)

        # check supported version
        version = headers.get(hdrs.SEC_WEBSOCKET_VERSION, '')
        if version not in ('13', '8', '7'):
            raise HTTPBadRequest(
                text='Unsupported version: {}'.format(version))

        # check client handshake for validity
        key = headers.get(hdrs.SEC_WEBSOCKET_KEY)
        try:
            if not key or len(base64.b64decode(key)) != 16:
                raise HTTPBadRequest(
                    text='Handshake error: {!r}'.format(key))
        except binascii.Error:
            raise HTTPBadRequest(
                text='Handshake error: {!r}'.format(key)) from None

        accept_val = base64.b64encode(
            hashlib.sha1(key.encode() + WS_KEY).digest()).decode()
        response_headers = CIMultiDict({hdrs.UPGRADE: 'websocket',
                                        hdrs.CONNECTION: 'upgrade',
                                        hdrs.TRANSFER_ENCODING: 'chunked',
                                        hdrs.SEC_WEBSOCKET_ACCEPT: accept_val})

        notakeover = False
        compress = self._compress
        if compress:
            extensions = headers.get(hdrs.SEC_WEBSOCKET_EXTENSIONS)
            # Server side always get return with no exception.
            # If something happened, just drop compress extension
            compress, notakeover = ws_ext_parse(extensions, isserver=True)
            if compress:
                enabledext = ws_ext_gen(compress=compress, isserver=True,
                                        server_notakeover=notakeover)
                response_headers[hdrs.SEC_WEBSOCKET_EXTENSIONS] = enabledext

        if protocol:
            response_headers[hdrs.SEC_WEBSOCKET_PROTOCOL] = protocol
        return (response_headers, protocol, compress, notakeover)

    def _pre_start(self, request):
        self._loop = request.loop

        headers, protocol, compress, notakeover = self._handshake(
            request)

        self._reset_heartbeat()

        self.set_status(101)
        self.headers.update(headers)
        self.force_close()
        self._compress = compress
        writer = WebSocketWriter(request._protocol,
                                 request._protocol.transport,
                                 compress=compress,
                                 notakeover=notakeover)

        return protocol, writer

    def _post_start(self, request, protocol, writer):
        self._ws_protocol = protocol
        self._writer = writer
        self._reader = FlowControlDataQueue(
            request._protocol, limit=2 ** 16, loop=self._loop)
        request.protocol.set_parser(WebSocketReader(
            self._reader, compress=self._compress))
        # disable HTTP keepalive for WebSocket
        request.protocol.keep_alive(False)

    def can_prepare(self, request):
        if self._writer is not None:
            raise RuntimeError('Already started')
        try:
            _, protocol, _, _ = self._handshake(request)
        except HTTPException:
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

    async def send_str(self, data, compress=None):
        if self._writer is None:
            raise RuntimeError('Call .prepare() first')
        if not isinstance(data, str):
            raise TypeError('data argument must be str (%r)' % type(data))
        await self._writer.send(data, binary=False, compress=compress)

    async def send_bytes(self, data, compress=None):
        if self._writer is None:
            raise RuntimeError('Call .prepare() first')
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError('data argument must be byte-ish (%r)' %
                            type(data))
        await self._writer.send(data, binary=True, compress=compress)

    async def send_json(self, data, compress=None, *, dumps=json.dumps):
        await self.send_str(dumps(data), compress=compress)

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
                await self._writer.close(code, message)
                await self._payload_writer.drain()
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
                    set_result(waiter, True)
                    self._waiting = None
            except (asyncio.CancelledError, asyncio.TimeoutError):
                self._close_code = 1006
                raise
            except EofStream:
                self._close_code = 1000
                await self.close()
                return WSMessage(WSMsgType.CLOSED, None, None)
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
