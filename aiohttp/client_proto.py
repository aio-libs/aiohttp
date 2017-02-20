import asyncio
import asyncio.streams

from .client_exceptions import ClientOSError, ServerDisconnectedError
from .http_parser import HttpResponseParser
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
        if isinstance(exc, OSError):
            exc = ClientOSError(*exc.args)
        else:
            exc = ServerDisconnectedError(exc)

        if self._payload is not None and not self._payload.is_eof():
            self._payload.set_exception(exc)
        if not self.is_eof():
            DataQueue.set_exception(self, exc)

        self.transport = self.writer = None
        self._should_close = True
        self._parser = None
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
            data, self._tail = self._tail, None
            self.data_received(data)

    def set_response_params(self, *, timer=None,
                            skip_payload=False,
                            skip_status_codes=(),
                            read_until_eof=False):
        self._skip_payload = skip_payload
        self._skip_status_codes = skip_status_codes
        self._read_until_eof = read_until_eof
        self._parser = HttpResponseParser(
            self, self._loop, timer=timer)

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
            if self._upgraded:
                # i.e. websocket connection, websocket parser is not set yet
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
