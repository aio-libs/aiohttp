import asyncio
import asyncio.streams

from .errors import ServerDisconnectedError
from .protocol import HttpResponseParser
from .streams import EMPTY_PAYLOAD, DataQueue, StreamWriter


class HttpClientProtocol(DataQueue, asyncio.streams.FlowControlMixin):
    """Helper class to adapt between Protocol and StreamReader."""

    def __init__(self, *, loop=None, **kwargs):
        asyncio.streams.FlowControlMixin.__init__(self, loop=loop)
        DataQueue.__init__(self, loop=loop)

        self.paused = False
        self.transport = None
        self.writer = None
        self._should_close = False

        self._payload = None
        self._payload_parser = None
        self._reading_paused = False

        self._timer = None
        self._skip_status = ()

        self._tail = b''
        self._upgraded = False
        self._parser = None

    @property
    def should_close(self):
        if self._payload is not None and not self._payload.is_eof():
            return True

        return (self._should_close or self._upgraded or
                self.exception() is not None or
                self._payload_parser is not None or
                len(self) or self._tail)

    def is_connected(self):
        return self.transport is not None

    def connection_made(self, transport):
        self.transport = transport
        self.writer = StreamWriter(self, transport, self._loop)

    def connection_lost(self, exc):
        self.transport = self.writer = None

        if exc is None:
            exc = ServerDisconnectedError()

        if self._payload is not None and not self._payload.is_eof():
            self._payload.set_exception(exc)
        if not self.is_eof():
            DataQueue.set_exception(self, exc)

        super().connection_lost(exc)

    def eof_received(self):
        pass

    def set_exception(self, exc):
        self._should_close = True

        super().set_exception(exc)

    def set_parser(self, parser, payload):
        self._payload = payload
        self._payload_parser = parser

        if self._tail:
            data, self._tail = self._tail, None
            self.data_received(data)

    def set_response_params(self, *, timer=None,
                            skip_payload=False,
                            skip_status_codes=(),
                            read_until_eof=False):
        self._skip_payload = skip_payload
        self._skip_status_codes = skip_status_codes
        self._parser = HttpResponseParser(
            self, self._loop, timer=timer, readall=read_until_eof)

    def data_received(self, data):
        # custom payload parser
        if self._payload_parser is not None:
            if data:
                eof, tail = self._payload_parser.feed_data(data)
                if eof:
                    self._payload = None
                    self._payload_parser = None

                    if tail:
                        super().data_received(tail)
            return
        else:
            if self._upgraded:
                self._tail += data
            else:
                # parse http messages
                try:
                    messages, upgraded, tail = self._parser.feed_data(data)
                except BaseException:
                    self._should_close = True
                    raise

                self._upgraded = upgraded

                for message, payload in messages:
                    if (self._skip_payload or
                            message.code in self._skip_status_codes):
                        self._payload = payload
                        self.feed_data((message, EMPTY_PAYLOAD), 0)
                    else:
                        self._payload = payload
                        self.feed_data((message, payload), 0)

                if upgraded:
                    self.data_received(tail)
                else:
                    self._tail = tail
