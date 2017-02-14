import asyncio
import asyncio.streams

from . import errors, hdrs
from .errors import ServerDisconnectedError
from .protocol import HttpPayloadParser, HttpResponseParser
from .streams import (DataQueue, EmptyStreamReader, FlowControlStreamReader,
                      StreamWriter)

EMPTY_PAYLOAD = EmptyStreamReader()


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

        self._lines = []
        self._tail = b''
        self._upgrade = False
        self._response_parser = HttpResponseParser()

    @property
    def should_close(self):
        return (self._should_close or self._upgrade or
                self.exception() is not None or
                self._payload is not None or
                self._payload_parser is not None or
                self._lines or self._tail)

    def is_connected(self):
        return self.transport is not None

    def connection_made(self, transport):
        self.transport = transport
        self.writer = StreamWriter(self, transport, self._loop)

    def connection_lost(self, exc):
        self.transport = self.writer = None

        if exc is None:
            exc = ServerDisconnectedError()

        if self._payload is not None:
            self._payload.set_exception(exc)
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
        self._timer = timer
        self._skip_payload = skip_payload
        self._skip_status_codes = skip_status_codes
        self._read_until_eof = read_until_eof

    def data_received(self, data,
                      SEP=b'\r\n',
                      CONTENT_LENGTH=hdrs.CONTENT_LENGTH,
                      SEC_WEBSOCKET_KEY1=hdrs.SEC_WEBSOCKET_KEY1):

        # feed payload
        if self._payload_parser is not None:
            assert not self._lines
            if data:
                eof, tail = self._payload_parser.feed_data(data)
                if eof:
                    self._payload = None
                    self._payload_parser = None

                    if tail:
                        super().data_received(tail)

            return

        # read HTTP message (status line + headers), \r\n\r\n
        # and split by lines
        if self._tail:
            data = self._tail + data

        start_pos = 0
        while True:
            pos = data.find(SEP, start_pos)
            if pos >= start_pos:
                # line found
                self._lines.append(data[start_pos:pos])

                # \r\n\r\n found
                start_pos = pos + 2
                if data[start_pos:start_pos+2] == SEP:
                    self._lines.append(b'')

                    msg = None
                    try:
                        msg = self._response_parser.parse_message(self._lines)

                        # payload length
                        length = msg.headers.get(CONTENT_LENGTH)
                        if length is not None:
                            try:
                                length = int(length)
                            except ValueError:
                                raise errors.InvalidHeader(CONTENT_LENGTH)
                            if length < 0:
                                raise errors.InvalidHeader(CONTENT_LENGTH)

                        # do not support old websocket spec
                        if SEC_WEBSOCKET_KEY1 in msg.headers:
                            raise errors.InvalidHeader(SEC_WEBSOCKET_KEY1)
                    except:
                        self._should_close = True
                        raise
                    else:
                        self._lines.clear()

                    self._should_close = msg.should_close

                    # calculate payload
                    empty_payload = True
                    if (((length is not None and length > 0) or
                         msg.chunked) and
                        (not self._skip_payload and
                         msg.code not in self._skip_status_codes)):

                        if not msg.upgrade:
                            payload = FlowControlStreamReader(
                                self, timer=self._timer, loop=self._loop)
                            payload_parser = HttpPayloadParser(
                                payload, length=length,
                                chunked=msg.chunked, code=msg.code,
                                compression=msg.compression,
                                readall=self._read_until_eof)

                            if not payload_parser.done:
                                empty_payload = False
                                self._payload = payload
                                self._payload_parser = payload_parser
                        else:
                            payload = EMPTY_PAYLOAD
                    else:
                        payload = EMPTY_PAYLOAD

                    self._upgrade = msg.upgrade

                    self.feed_data((msg, payload), 0)

                    start_pos = start_pos + 2
                    if start_pos < len(data):
                        if self._upgrade:
                            self._tail = data[start_pos:]
                            return
                        if empty_payload:
                            continue

                        self._tail = None
                        self.data_received(data[start_pos:])
                    return
            else:
                self._tail = data[start_pos:]
                return
