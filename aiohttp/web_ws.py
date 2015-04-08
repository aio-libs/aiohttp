__all__ = ('WebSocketResponse', 'MsgType')

import asyncio
import warnings

from . import hdrs
from .errors import HttpProcessingError, ClientDisconnectedError
from .websocket import do_handshake, Message, WebSocketError
from .websocket_client import MsgType, closedMessage
from .web_exceptions import (
    HTTPBadRequest, HTTPMethodNotAllowed, HTTPInternalServerError)
from .web_reqrep import StreamResponse

THRESHOLD_CONNLOST_ACCESS = 5


class WebSocketResponse(StreamResponse):

    def __init__(self, *,
                 timeout=10.0, autoclose=True, autoping=True, protocols=()):
        super().__init__(status=101)
        self._protocols = protocols
        self._protocol = None
        self._writer = None
        self._reader = None
        self._closed = False
        self._closing = False
        self._conn_lost = 0
        self._close_code = None
        self._loop = None
        self._waiting = False
        self._exception = None
        self._timeout = timeout
        self._autoclose = autoclose
        self._autoping = autoping

    def start(self, request):
        # make pre-check to don't hide it by do_handshake() exceptions
        resp_impl = self._start_pre_check(request)
        if resp_impl is not None:
            return resp_impl

        try:
            status, headers, parser, writer, protocol = do_handshake(
                request.method, request.headers, request.transport,
                self._protocols)
        except HttpProcessingError as err:
            if err.code == 405:
                raise HTTPMethodNotAllowed(
                    request.method, [hdrs.METH_GET], body=b'')
            elif err.code == 400:
                raise HTTPBadRequest(text=err.message, headers=err.headers)
            else:  # pragma: no cover
                raise HTTPInternalServerError() from err

        if self.status != status:
            self.set_status(status)
        for k, v in headers:
            self.headers[k] = v
        self.force_close()

        resp_impl = super().start(request)

        self._reader = request._reader.set_parser(parser)
        self._writer = writer
        self._protocol = protocol
        self._loop = request.app.loop

        return resp_impl

    def can_start(self, request):
        if self._writer is not None:
            raise RuntimeError('Already started')
        try:
            _, _, _, _, protocol = do_handshake(
                request.method, request.headers, request.transport,
                self._protocols)
        except HttpProcessingError:
            return False, None
        else:
            return True, protocol

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
        if self._writer is None:
            raise RuntimeError('Call .start() first')
        if self._closed:
            raise RuntimeError('websocket connection is closing')
        self._writer.ping(message)

    def pong(self, message='b'):
        # unsolicited pong
        if self._writer is None:
            raise RuntimeError('Call .start() first')
        if self._closed:
            raise RuntimeError('websocket connection is closing')
        self._writer.pong(message)

    def send_str(self, data):
        if self._writer is None:
            raise RuntimeError('Call .start() first')
        if self._closed:
            raise RuntimeError('websocket connection is closing')
        if not isinstance(data, str):
            raise TypeError('data argument must be str (%r)' % type(data))
        self._writer.send(data, binary=False)

    def send_bytes(self, data):
        if self._writer is None:
            raise RuntimeError('Call .start() first')
        if self._closed:
            raise RuntimeError('websocket connection is closing')
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError('data argument must be byte-ish (%r)' %
                            type(data))
        self._writer.send(data, binary=True)

    @asyncio.coroutine
    def wait_closed(self):  # pragma: no cover
        warnings.warn(
            'wait_closed() coroutine is deprecated. use close() instead',
            DeprecationWarning)

        return (yield from self.close())

    @asyncio.coroutine
    def write_eof(self):
        if self._eof_sent:
            return
        if self._resp_impl is None:
            raise RuntimeError("Response has not been started")

        yield from self.close()
        self._eof_sent = True

    @asyncio.coroutine
    def close(self, *, code=1000, message=b''):
        if self._writer is None:
            raise RuntimeError('Call .start() first')

        if not self._closed:
            self._closed = True
            try:
                self._writer.close(code, message)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                self._close_code = 1006
                raise
            except Exception as exc:
                self._close_code = 1006
                self._exception = exc
                return True

            if self._closing:
                return True

            while True:
                try:
                    msg = yield from asyncio.wait_for(
                        self._reader.read(),
                        timeout=self._timeout, loop=self._loop)
                except asyncio.CancelledError:
                    self._close_code = 1006
                    raise
                except Exception as exc:
                    self._close_code = 1006
                    self._exception = exc
                    return True

                if msg.tp == MsgType.close:
                    self._close_code = msg.data
                    return True
        else:
            return False

    @asyncio.coroutine
    def receive(self):
        if self._reader is None:
            raise RuntimeError('Call .start() first')
        if self._waiting:
            raise RuntimeError('Concurrent call to receive() is not allowed')

        self._waiting = True
        try:
            while True:
                if self._closed:
                    self._conn_lost += 1
                    if self._conn_lost >= THRESHOLD_CONNLOST_ACCESS:
                        raise RuntimeError('WebSocket connection is closed.')
                    return closedMessage

                try:
                    msg = yield from self._reader.read()
                except (asyncio.CancelledError, asyncio.TimeoutError):
                    raise
                except WebSocketError as exc:
                    self._close_code = exc.code
                    yield from self.close(code=exc.code)
                    return Message(MsgType.error, exc, None)
                except ClientDisconnectedError:
                    self._closed = True
                    self._close_code = 1006
                    return Message(MsgType.close, None, None)
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
    def receive_msg(self):  # pragma: no cover
        warnings.warn(
            'receive_msg() coroutine is deprecated. use receive() instead',
            DeprecationWarning)
        return (yield from self.receive())

    @asyncio.coroutine
    def receive_str(self):
        msg = yield from self.receive()
        if msg.tp != MsgType.text:
            raise TypeError(
                "Received message {}:{!r} is not str".format(msg.tp, msg.data))
        return msg.data

    @asyncio.coroutine
    def receive_bytes(self):
        msg = yield from self.receive()
        if msg.tp != MsgType.binary:
            raise TypeError(
                "Received message {}:{!r} is not bytes".format(msg.tp,
                                                               msg.data))
        return msg.data

    def write(self, data):
        raise RuntimeError("Cannot call .write() for websocket")
