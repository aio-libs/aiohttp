import asyncio
import base64
import binascii
import hashlib
import json
from typing import Any, Iterable, Optional, Tuple, Union

import async_timeout
import attr
from multidict import CIMultiDict

from . import hdrs
from .abc import AbstractStreamWriter
from .helpers import set_result
from .http import (
    WS_CLOSED_MESSAGE,
    WS_CLOSING_MESSAGE,
    WS_KEY,
    WebSocketError,
    WebSocketReader,
    WebSocketWriter,
    WSMessage,
)
from .http import WSMsgType as WSMsgType
from .http import ws_ext_gen, ws_ext_parse
from .log import ws_logger
from .streams import EofStream, FlowControlDataQueue
from .typedefs import JSONDecoder, JSONEncoder
from .web_exceptions import HTTPBadRequest, HTTPException
from .web_request import BaseRequest
from .web_response import StreamResponse

__all__ = ('WebSocketResponse', 'WebSocketReady', 'WSMsgType',)

THRESHOLD_CONNLOST_ACCESS = 5


@attr.s(frozen=True, slots=True)
class WebSocketReady:
    ok = attr.ib(type=bool)
    protocol = attr.ib(type=Optional[str])

    def __bool__(self) -> bool:
        return self.ok

class WebSocketResponse(StreamResponse):
    __slots__ = ('_protocols', '_ws_protocol', '_writer', '_reader', '_closed',
                 '_closing', '_conn_lost', '_close_code', '_loop',
                 '_receiving', '_exception', '_receive_timeout',
                 '_close_timeout', '_autoclose', '_autoping', '_heartbeat',
                 '_background_task', '_receive_queue', '_pong_heartbeat',
                 '_compress', '_max_msg_size')

    def __init__(self, *,
                 timeout: float=10.0, receive_timeout: Optional[float]=None,
                 autoclose: bool=True, autoping: bool=True,
                 heartbeat: Optional[float]=None,
                 protocols: Iterable[str]=(),
                 compress: bool=True, max_msg_size: int=4*1024*1024) -> None:
        super().__init__(status=101)
        self._length_check = False
        self._protocols = protocols
        self._ws_protocol = None  # type: Optional[str]
        self._writer = None  # type: Optional[WebSocketWriter]
        self._reader = None  # type: Optional[FlowControlDataQueue[WSMessage]]
        self._closed = False
        self._closing = False
        self._conn_lost = 0
        self._close_code = None  # type: Optional[int]
        self._loop = None  # type: Optional[asyncio.AbstractEventLoop]
        # future to detect concurrent calls to `receive()`:
        self._receiving = None  # type: Optional[asyncio.Future[bool]]
        self._exception = None  # type: Optional[BaseException]
        self._close_timeout = timeout
        self._receive_timeout = receive_timeout
        self._autoclose = autoclose
        self._autoping = autoping
        self._heartbeat = heartbeat
        if heartbeat is not None:
            self._pong_heartbeat = heartbeat / 2.0
        self._background_task = None  # type: Optional[asyncio.Task[None]]
        self._receive_queue = asyncio.Queue(maxsize=1)  # type: asyncio.Queue[Union[WSMessage, BaseException]]  # noqa: E501
        self._compress = compress
        self._max_msg_size = max_msg_size

    def _start_background_receiving(self) -> None:
        assert self._loop is not None
        self._background_task = self._loop.create_task(
            self._do_background_receiving())

    async def _stop_background_receiving(self) -> None:
        if self._background_task is not None:
            assert self._reader is not None
            self._reader.set_exception(StopAsyncIteration())
            await self._background_task
            self._background_task = None

    def _cancel_background_receiving(self) -> None:
        task = self._background_task
        if task is not None:
            # stop the task and wait for it to complete
            task.cancel()
            self._background_task = None

    def _pong_not_received(self) -> None:
        if self._req is not None and self._req.transport is not None:
            self._closed = True
            self._close_code = 1006
            self._exception = asyncio.TimeoutError()
            self._req.transport.close()

    async def _do_background_receiving(self) -> None:
        if self._closed:
            return

        assert self._reader is not None
        loop = self._loop
        assert loop is not None

        while True:
            if self._closed:
                self._conn_lost += 1
                if self._conn_lost >= THRESHOLD_CONNLOST_ACCESS:
                    exc = RuntimeError('WebSocket connection is closed.')
                    await self._receive_queue.put(exc)
                return
            if self._closing:
                return

            if self._heartbeat is not None:
                assert self._writer
                await self._writer.ping()

            try:
                with async_timeout.timeout(self._receive_timeout,
                                           loop=self._loop):
                    msg = await self._reader.read()
            except StopAsyncIteration:
                return
            except (asyncio.CancelledError, asyncio.TimeoutError) as exc:
                self._close_code = 1006
                self._exception = exc
                await self._receive_queue.put(exc)
                return
            except EofStream:
                self._close_code = 1000
                await self._close()
                err_msg = WSMessage(WSMsgType.CLOSED, None, None)
                await self._receive_queue.put(err_msg)
                return
            except WebSocketError as exc:
                self._close_code = exc.code
                await self._close()
                err_msg = WSMessage(WSMsgType.ERROR, exc, None)
                await self._receive_queue.put(err_msg)
                return
            except Exception as exc:
                self._exception = exc
                self._closing = True
                self._close_code = 1006
                await self._close()
                err_msg = WSMessage(WSMsgType.ERROR, exc, None)
                await self._receive_queue.put(err_msg)
                return

            if msg.type == WSMsgType.CLOSE:
                self._closing = True
                self._close_code = msg.data
                if not self._closed and self._autoclose:
                    await self._close()
            elif msg.type == WSMsgType.CLOSING:
                self._closing = True
            elif msg.type == WSMsgType.PING and self._autoping:
                await self.pong(msg.data)
                continue
            elif msg.type == WSMsgType.PONG and self._autoping:
                continue

            await self._receive_queue.put(msg)

    async def prepare(self, request: BaseRequest) -> AbstractStreamWriter:
        # make pre-check to don't hide it by do_handshake() exceptions
        if self._payload_writer is not None:
            return self._payload_writer

        protocol, writer = self._pre_start(request)
        payload_writer = await super().prepare(request)
        assert payload_writer is not None
        self._post_start(request, protocol, writer)
        await payload_writer.drain()
        return payload_writer

    def _handshake(self, request: BaseRequest) -> Tuple['CIMultiDict[str]',
                                                        str,
                                                        bool,
                                                        bool]:
        headers = request.headers
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
        response_headers = CIMultiDict(  # type: ignore
            {hdrs.UPGRADE: 'websocket',  # type: ignore
             hdrs.CONNECTION: 'upgrade',
             hdrs.SEC_WEBSOCKET_ACCEPT: accept_val})

        notakeover = False
        compress = 0
        if self._compress:
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
        return (response_headers,  # type: ignore
                protocol,
                compress,
                notakeover)

    def _pre_start(self, request: BaseRequest) -> Tuple[str, WebSocketWriter]:
        self._loop = request._loop

        headers, protocol, compress, notakeover = self._handshake(
            request)

        self._cancel_background_receiving()
        self._start_background_receiving()

        self.set_status(101)
        self.headers.update(headers)
        self.force_close()
        self._compress = compress
        transport = request._protocol.transport
        assert transport is not None
        writer = WebSocketWriter(request._protocol,
                                 transport,
                                 compress=compress,
                                 notakeover=notakeover)

        return protocol, writer

    def _post_start(self, request: BaseRequest,
                    protocol: str, writer: WebSocketWriter) -> None:
        self._ws_protocol = protocol
        self._writer = writer
        loop = self._loop
        assert loop is not None
        self._reader = FlowControlDataQueue(
            request._protocol, limit=2 ** 16, loop=loop)
        request.protocol.set_parser(WebSocketReader(
            self._reader, self._max_msg_size, compress=self._compress))
        # disable HTTP keepalive for WebSocket
        request.protocol.keep_alive(False)

    def can_prepare(self, request: BaseRequest) -> WebSocketReady:
        if self._writer is not None:
            raise RuntimeError('Already started')
        try:
            _, protocol, _, _ = self._handshake(request)
        except HTTPException:
            return WebSocketReady(False, None)
        else:
            return WebSocketReady(True, protocol)

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def close_code(self) -> Optional[int]:
        return self._close_code

    @property
    def ws_protocol(self) -> Optional[str]:
        return self._ws_protocol

    @property
    def compress(self) -> bool:
        return self._compress

    def exception(self) -> Optional[BaseException]:
        return self._exception

    async def ping(self, message: bytes=b'') -> None:
        if self._writer is None:
            raise RuntimeError('Call .prepare() first')
        await self._writer.ping(message)

    async def pong(self, message: bytes=b'') -> None:
        # unsolicited pong
        if self._writer is None:
            raise RuntimeError('Call .prepare() first')
        await self._writer.pong(message)

    async def send_str(self, data: str, compress: Optional[bool]=None) -> None:
        if self._writer is None:
            raise RuntimeError('Call .prepare() first')
        if not isinstance(data, str):
            raise TypeError('data argument must be str (%r)' % type(data))
        await self._writer.send(data, binary=False, compress=compress)

    async def send_bytes(self, data: bytes,
                         compress: Optional[bool]=None) -> None:
        if self._writer is None:
            raise RuntimeError('Call .prepare() first')
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError('data argument must be byte-ish (%r)' %
                            type(data))
        await self._writer.send(data, binary=True, compress=compress)

    async def send_json(self, data: Any, compress: Optional[bool]=None, *,
                        dumps: JSONEncoder=json.dumps) -> None:
        await self.send_str(dumps(data), compress=compress)

    async def write_eof(self) -> None:  # type: ignore
        if self._eof_sent:
            return
        if self._payload_writer is None:
            raise RuntimeError("Response has not been started")

        await self.close()
        self._eof_sent = True

    async def close(self, *, code: int=1000, message: bytes=b'') -> bool:
        if self._writer is None:
            raise RuntimeError('Call .prepare() first')

        # we need to break `receive()` cycle first,
        # `close()` may be called from different task
        if not self._closed:
            await self._stop_background_receiving()

        return await self._close(code=code, message=message)

    async def _close(self, *, code: int=1000, message: bytes= b'') -> bool:
        if self._closed:
            return False

        self._closed = True
        try:
            assert self._writer is not None
            await self._writer.close(code, message)
            assert self._payload_writer is not None
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

        if self._background_task is not None \
                or not self._receive_queue.empty():
            try:
                msg = await self._pop_msg(self._close_timeout)
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

    async def receive(self, timeout: Optional[float]=None) -> WSMessage:
        if self._reader is None:
            raise RuntimeError('Call .prepare() first')

        if self._receiving is not None:
            raise RuntimeError(
                'Concurrent call to receive() is not allowed')
        assert self._loop is not None
        self._receiving = self._loop.create_future()

        try:
            if self._closed:
                self._conn_lost += 1
                if self._conn_lost >= THRESHOLD_CONNLOST_ACCESS:
                    raise RuntimeError('WebSocket connection is closed.')
                return WS_CLOSED_MESSAGE
            elif self._closing:
                return WS_CLOSING_MESSAGE

            msg = await self._pop_msg(timeout)
            return msg

        finally:
            receiving = self._receiving
            set_result(receiving, True)
            self._receiving = None

    async def _pop_msg(self, timeout: Optional[float]=None) -> WSMessage:
        with async_timeout.timeout(timeout or self._receive_timeout,
                                   loop=self._loop):
            received = await self._receive_queue.get()
            if isinstance(received, BaseException):
                raise received
            assert isinstance(received, WSMessage)
            return received

    async def receive_str(self, *, timeout: Optional[float]=None) -> str:
        msg = await self.receive(timeout)
        if msg.type != WSMsgType.TEXT:
            raise TypeError(
                "Received message {}:{!r} is not WSMsgType.TEXT".format(
                    msg.type, msg.data))
        return msg.data

    async def receive_bytes(self, *, timeout: Optional[float]=None) -> bytes:
        msg = await self.receive(timeout)
        if msg.type != WSMsgType.BINARY:
            raise TypeError(
                "Received message {}:{!r} is not bytes".format(msg.type,
                                                               msg.data))
        return msg.data

    async def receive_json(self, *, loads: JSONDecoder=json.loads,
                           timeout: Optional[float]=None) -> Any:
        data = await self.receive_str(timeout=timeout)
        return loads(data)

    async def write(self, data: bytes) -> None:
        raise RuntimeError("Cannot call .write() for websocket")

    def __aiter__(self) -> 'WebSocketResponse':
        return self

    async def __anext__(self) -> WSMessage:
        msg = await self.receive()
        if msg.type in (WSMsgType.CLOSE,
                        WSMsgType.CLOSING,
                        WSMsgType.CLOSED):
            raise StopAsyncIteration  # NOQA
        return msg
