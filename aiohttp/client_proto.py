import asyncio
import asyncio.streams

from .client_exceptions import (ClientOSError, ClientPayloadError,
                                ServerDisconnectedError)
from .http import HttpResponseParser, StreamWriter
from .streams import EMPTY_PAYLOAD, DataQueue


class ResponseHandler(DataQueue, asyncio.streams.FlowControlMixin):
    """Helper class to adapt between Protocol and StreamReader."""

    def __init__(self, *, loop=None, **kwargs):
        asyncio.streams.FlowControlMixin.__init__(self, loop=loop)
        DataQueue.__init__(self, loop=loop)

        self.paused = False
        self.transport = None
        self.writer = None
        self._should_close = False

        self._message = None
        self._payload = None
        self._payload_parser = None
        self._reading_paused = False

        self._timer = None
        self._skip_status = ()

        self._tail = b''
        self._upgraded = False
        self._parser = None

    @property
    def upgraded(self):
        return self._upgraded

    @property
    def should_close(self):
        if (self._payload is not None and
                not self._payload.is_eof() or self._upgraded):
            return True

        return (self._should_close or self._upgraded or
                self.exception() is not None or
                self._payload_parser is not None or
                len(self) or self._tail)

    def close(self):
        transport = self.transport
        if transport is not None:
            transport.close()
            self.transport = None
            self._payload = None
        return transport

    def is_connected(self):
        return self.transport is not None

    def connection_made(self, transport):
        self.transport = transport
        self.writer = StreamWriter(self, transport, self._loop)

    def connection_lost(self, exc):
        if self._payload_parser is not None:
            try:
                self._payload_parser.feed_eof()
            except Exception:
                pass

        try:
            uncompleted = self._parser.feed_eof()
        except Exception as e:
            uncompleted = None
            if self._payload is not None:
                self._payload.set_exception(
                    ClientPayloadError('Response payload is not completed'))

        if not self.is_eof():
            if isinstance(exc, OSError):
                exc = ClientOSError(*exc.args)
            if exc is None:
                exc = ServerDisconnectedError(uncompleted)
            DataQueue.set_exception(self, exc)

        self.transport = self.writer = None
        self._should_close = True
        self._parser = None
        self._message = None
        self._payload = None
        self._payload_parser = None
        self._reading_paused = False

        super().connection_lost(exc)

    def eof_received(self):
        pass

    def pause_reading(self):
        if not self._reading_paused:
            try:
                self.transport.pause_reading()
            except (AttributeError, NotImplementedError, RuntimeError):
                pass
            self._reading_paused = True

    def resume_reading(self):
        if self._reading_paused:
            try:
                self.transport.resume_reading()
            except (AttributeError, NotImplementedError, RuntimeError):
                pass
            self._reading_paused = False

    def set_exception(self, exc):
        self._should_close = True

        super().set_exception(exc)

    def set_parser(self, parser, payload):
        self._payload = payload
        self._payload_parser = parser

        if self._tail:
            data, self._tail = self._tail, b''
            self.data_received(data)

    def set_response_params(self, *, timer=None,
                            skip_payload=False,
                            skip_status_codes=(),
                            read_until_eof=False):
        self._skip_payload = skip_payload
        self._skip_status_codes = skip_status_codes
        self._read_until_eof = read_until_eof
        self._parser = HttpResponseParser(
            self, self._loop, timer=timer,
            payload_exception=ClientPayloadError,
            read_until_eof=read_until_eof)

        if self._tail:
            data, self._tail = self._tail, b''
            self.data_received(data)

    def data_received(self, data):
        if not data:
            return

        # custom payload parser
        if self._payload_parser is not None:
            eof, tail = self._payload_parser.feed_data(data)
            if eof:
                self._payload = None
                self._payload_parser = None

                if tail:
                    self.data_received(tail)
            return
        else:
            if self._upgraded or self._parser is None:
                # i.e. websocket connection, websocket parser is not set yet
                self._tail += data
            else:
                # parse http messages
                try:
                    messages, upgraded, tail = self._parser.feed_data(data)
                except BaseException as exc:
                    self._should_close = True
                    self.transport.close()
                    self.set_exception(exc)
                    return

                self._upgraded = upgraded

                for message, payload in messages:
                    if message.should_close:
                        self._should_close = True

                    self._message = message
                    self._payload = payload

                    if (self._skip_payload or
                            message.code in self._skip_status_codes):
                        self.feed_data((message, EMPTY_PAYLOAD), 0)
                    else:
                        self.feed_data((message, payload), 0)

                if tail:
                    if upgraded:
                        self.data_received(tail)
                    else:
                        self._tail = tail
