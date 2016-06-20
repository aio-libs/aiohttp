"""Http2 related parsers and protocol."""

from wsgiref.handlers import format_date_time

import aiohttp.hdrs
import aiohttp.protocol

HttpVersion20 = aiohttp.protocol.HttpVersion(2, 0)


class HTTP2Parser:
    def __init__(self, conn):
        self._conn = conn

    def __call__(self, out, buf):
        """
        Receives data from the buffer, parses it, and then sends any events
        out.

        This only terminates when the connection is terminated by the remote
        peer.
        """
        while True:
            # XXX: 65kb is totally arbitrary here: consider tuning.
            data = yield from buf.readsome(size=65535)

            if not data:
                out.feed_eof()
                break

            events = self._conn.receive_data(data)
            out.feed_data(events, len(data))


class Http2Message(aiohttp.protocol.HttpMessage):
    """
    A HTTP/2-specific version of the ``HttpMessage`` ABC.
    """
    HOP_HEADERS = []

    def __init__(self, conn, transport, stream_id):
        self._conn = conn
        self._stream_id = stream_id
        super().__init__(transport, version=HttpVersion20, close=False)

    def keep_alive(self):
        return True

    def add_header(self, name, value):
        # HTTP/2 doesn't do chunked.
        if name == aiohttp.hdrs.TRANSFER_ENCODING:
            return

        # Nor does it do Connection.
        if name == aiohttp.hdrs.CONNECTION:
            return

        return super().add_header(name, value)

    def send_headers(self, *args, **kwargs):
        """
        A complete override of the equivalent method from the ABC.
        """
        assert not self.headers_sent, 'headers have been sent already'
        self.headers_sent = True

        # We always use either the EOF payload writer or the length payload
        # writer.
        self.writer = self._write_h2_payload()
        next(self.writer)
        self._add_default_headers()

        # Send the headers.
        headers = [(':status', str(self.status))]
        headers.extend(self.headers.items())
        self._conn.send_headers(stream_id=self._stream_id, headers=headers)
        headers_data = self._conn.data_to_send()

        self.output_length += len(headers_data)
        self.headers_length = len(headers_data)
        self.transport.write(headers_data)

    def write(self, chunk, *,
              drain=False, EOF_MARKER=aiohttp.protocol.EOF_MARKER,
              EOL_MARKER=aiohttp.protocol.EOL_MARKER):
        """Writes chunk of data to a stream by using different writers.

        writer uses filter to modify chunk of data.
        write_eof() indicates end of stream.
        writer can't be used after write_eof() method being called.
        write() return drain future.
        """
        assert (isinstance(chunk, (bytes, bytearray)) or
                chunk is EOF_MARKER), chunk

        size = self.output_length

        if self._send_headers and not self.headers_sent:
            self.send_headers()

        assert self.writer is not None, 'send_headers() is not called.'

        if self.filter:
            chunk = self.filter.send(chunk)
            while chunk not in (EOF_MARKER, EOL_MARKER):
                if chunk:
                    self.writer.send(chunk)
                chunk = next(self.filter)
        else:
            if chunk is not EOF_MARKER:
                self.writer.send(chunk)

        self._output_size += self.output_length - size

        if self._output_size > 64 * 1024:
            if drain:
                self._output_size = 0
                return self.transport.drain()

        return ()

    def _write_h2_payload(self):
        while True:
            try:
                chunk = yield
            except aiohttp.EofStream:
                break

            self._conn.send_data(stream_id=self._stream_id, data=chunk)
            sent_data = self._conn.data_to_send()
            self.transport.write(sent_data)
            self.output_length += len(sent_data)

        self._conn.end_stream(stream_id=self._stream_id)
        sent_data = self._conn.data_to_send()
        self.transport.write(sent_data)

    def _add_default_headers(self):
        # This is a no-op for HTTP/2, we don't want to add Connection headers.
        return


class Http2Response(Http2Message):
    """
    A HTTP/2-equivalent of aiohttp.protocol.HttpResponse
    """
    def __init__(self, conn, transport, status, stream_id):
        self._status = status
        super().__init__(conn, transport, stream_id)

    def status_line(self):
        return ""

    @staticmethod
    def calc_reason(*args, **kwargs):
        return ""

    @property
    def status(self):
        return self._status

    @property
    def reason(self):
        return ""

    def autochunked(self):
        return False

    def _add_default_headers(self):
        super()._add_default_headers()

        if aiohttp.hdrs.DATE not in self.headers:
            # format_date_time(None) is quite expensive
            self.headers.setdefault(aiohttp.hdrs.DATE, format_date_time(None))
        self.headers.setdefault(aiohttp.hdrs.SERVER, self.SERVER_SOFTWARE)
