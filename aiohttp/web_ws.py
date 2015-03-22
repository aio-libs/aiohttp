__all__ = ('WebSocketResponse', 'WSClientDisconnectedError',
           'MSG_BINARY', 'MSG_CLOSE', 'MSG_PING', 'MSG_TEXT')

import asyncio

from .websocket import do_handshake, MSG_BINARY, MSG_CLOSE, MSG_PING, MSG_TEXT
from .errors import HttpProcessingError, WSClientDisconnectedError

from .web_exceptions import (HTTPBadRequest, HTTPMethodNotAllowed,
                             HTTPInternalServerError)
from .web_reqrep import StreamResponse


class WebSocketResponse(StreamResponse):

    def __init__(self, *, protocols=()):
        super().__init__(status=101)
        self._protocols = protocols
        self._protocol = None
        self._writer = None
        self._reader = None
        self._closing = False
        self._loop = None
        self._closing_fut = None

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
                raise HTTPMethodNotAllowed(request.method, ['GET'])
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
        self._closing_fut = asyncio.Future(loop=self._loop)

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
    def closing(self):
        return self._closing

    @property
    def protocol(self):
        return self._protocol

    def ping(self, message='b'):
        if self._writer is None:
            raise RuntimeError('Call .start() first')
        if self._closing:
            raise RuntimeError('websocket connection is closing')
        self._writer.ping(message)

    def pong(self, message='b'):
        # unsolicited pong
        if self._writer is None:
            raise RuntimeError('Call .start() first')
        if self._closing:
            raise RuntimeError('websocket connection is closing')
        self._writer.pong(message)

    def send_str(self, data):
        if self._writer is None:
            raise RuntimeError('Call .start() first')
        if self._closing:
            raise RuntimeError('websocket connection is closing')
        if not isinstance(data, str):
            raise TypeError('data argument must be str (%r)' % type(data))
        self._writer.send(data, binary=False)

    def send_bytes(self, data):
        if self._writer is None:
            raise RuntimeError('Call .start() first')
        if self._closing:
            raise RuntimeError('websocket connection is closing')
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError('data argument must be byte-ish (%r)' %
                            type(data))
        self._writer.send(data, binary=True)

    def close(self, *, code=1000, message=b''):
        if self._writer is None:
            raise RuntimeError('Call .start() first')
        if not self._closing:
            self._closing = True
            self._writer.close(code, message)
        else:
            raise RuntimeError('Already closing')

    @asyncio.coroutine
    def wait_closed(self):
        if self._closing_fut is None:
            raise RuntimeError('Call .start() first')
        yield from self._closing_fut

    @asyncio.coroutine
    def write_eof(self):
        if self._eof_sent:
            return
        if self._resp_impl is None:
            raise RuntimeError("Response has not been started")

        yield from self.wait_closed()
        self._eof_sent = True

    @asyncio.coroutine
    def receive(self):
        if self._reader is None:
            raise RuntimeError('Call .start() first')
        while True:
            try:
                msg = yield from self._reader.read()
            except Exception as exc:
                self._closing_fut.set_exception(exc)
                raise

            if msg.tp == MSG_CLOSE:
                if self._closing:
                    exc = WSClientDisconnectedError(msg.data, msg.extra)
                    self._closing_fut.set_exception(exc)
                    raise exc
                else:
                    self._closing = True
                    self._writer.close(msg.data, msg.extra)
                    yield from self.drain()
                    exc = WSClientDisconnectedError(msg.data, msg.extra)
                    self._closing_fut.set_exception(exc)
                    raise exc
            elif not self._closing:
                if msg.tp == MSG_PING:
                    self._writer.pong(msg.data)
                elif msg.tp in (MSG_TEXT, MSG_BINARY):
                    return msg

    receive_msg = receive

    @asyncio.coroutine
    def receive_str(self):
        msg = yield from self.receive_msg()
        if msg.tp != MSG_TEXT:
            raise TypeError(
                "Received message {}:{!r} is not str".format(msg.tp, msg.data))
        return msg.data

    @asyncio.coroutine
    def receive_bytes(self):
        msg = yield from self.receive_msg()
        if msg.tp != MSG_BINARY:
            raise TypeError(
                "Received message {}:{!r} is not bytes".format(msg.tp,
                                                               msg.data))
        return msg.data

    def write(self, data):
        raise RuntimeError("Cannot call .write() for websocket")
