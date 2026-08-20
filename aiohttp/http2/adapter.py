import asyncio
from typing import List, Mapping, Tuple

from aiohttp import hdrs
from aiohttp.abc import AbstractStreamWriter
from aiohttp.http_parser import RawResponseMessage
from aiohttp.http_writer import HttpVersion, HttpVersion10, HttpVersion11
from multidict import CIMultiDict
from aiohttp.streams import StreamReader
from aiohttp.helpers import HeadersDictProxy

from aiohttp.http2.stream import Stream

def get_version(protocol):
    """
    Helper to get the negotiated HTTP version from the protocol
    """
    # backwards compat
    if not hasattr(protocol, "transport"):
        return "http/1.1"
    ssl_object = protocol.transport.get_extra_info("ssl_object")
    alpn_protocol = ssl_object.selected_alpn_protocol() if ssl_object else "http/1.1"

    return alpn_protocol

def feed_response(reader, headers: Mapping[str, str], body: bytes):
    """Call when the stream receives the complete response."""
    # Build a minimal RawResponseMessage (the fields that ClientResponse uses).
    raw_headers = []
    code = 500
    # there is no guarantee that the status code comes first
    for header in headers:
        if header[0] == ":status":
            code = int(header[1])
        raw_headers.append(header)
    msg = RawResponseMessage(
        version=HttpVersion(2, 0),  # HTTP/2.0
        code=code,
        # HTTP/2 has no reason phrase
        reason="",
        headers=HeadersDictProxy(CIMultiDict(raw_headers)),
        raw_headers=raw_headers,
        should_close=False,
        # n/a
        compression=False,
        upgrade=False,
        chunked=False,
    )
    # Feed the body into the StreamReader.
    reader.feed_data(body)
    reader.feed_eof()
    return msg, reader


class Http2StreamWriter(AbstractStreamWriter):
    def __init__(
        self,
        protocol,
        loop: asyncio.AbstractEventLoop,
        req: "ClientRequest",
        *,
        on_chunk_sent=None,
        on_headers_sent=None,
    ):
        del on_chunk_sent, on_headers_sent # skip for now

        self._req = req
        self._sent_headers = False
        self._output_size = 0

        self._protocol = protocol
        # set later
        self.stream_id = req.stream_id
        self.loop = loop

    async def write_headers(self, status_line: str, headers: Mapping[str, str]):
        # status_line is ignored; we take method/path from the request.
        # Push the headers into the HPACK encoder and prepare the HEADERS frame.

        self._protocol._connection.send_headers(
            self.stream_id,
            self._req.method,
            self._req.url,
            list(headers.items()),
        )
        self._sent_headers = True

    async def write(self, chunk: bytes):

        if not self._sent_headers:
            raise RuntimeError("Headers must be written before body")
        # send_data handles flow control and DATA frames.
        await self._procotol._connection.send_data(
            self.stream_id, chunk, end_stream=False
        )
        self._output_size += len(chunk)

    async def write_eof(self, chunk: bytes = b""):
        if chunk:
            await self._protocol._connection.send_data(self.stream_id, chunk, end_stream=True)
            self._output_size += len(chunk)
        else:
            # End stream without data - send empty DATA frame with END_STREAM flag
            await self._protocol._connection.send_data(stream, b"", end_stream=True)

    async def drain(self):
        # HTTP/2 flow control is handled inside send_data; nothing to do.
        pass

    def set_eof(self):
        # Called when there is no body.
        # The HEADERS frame should have been sent with END_STREAM flag.
        pass

    # enable_compression / enable_chunking are no-ops because HTTP/2
    # compresses headers automatically and doesn't use chunked transfer encoding.
    def enable_compression(self, *args):
        pass

    def enable_chunking(self):
        pass

    @property
    def output_size(self) -> int:
        return self._output_size


from typing import Mapping
import asyncio
from aiohttp.abc import AbstractStreamWriter


class Http2StreamWriter(AbstractStreamWriter):
    def __init__(
        self,
        protocol,
        loop: asyncio.AbstractEventLoop,
        req,
        *,
        on_chunk_sent=None,
        on_headers_sent=None,
    ):
        del on_chunk_sent, on_headers_sent  # skipped for now

        self._req = req
        self._protocol = protocol
        self.stream_id = req.stream_id
        self.loop = loop

        self._headers = None
        self._headers_sent = False
        self._eof = False
        self._output_size = 0

    @property
    def protocol(self):
        return self._protocol

    @property
    def transport(self):
        return self._protocol.transport

    @property
    def buffer_size(self) -> int:
        return 0

    @property
    def output_size(self) -> int:
        return self._output_size

    def _send_headers(self, *, end_stream: bool) -> None:
        if self._headers_sent or self._headers is None:
            return

        self._protocol._connection.send_headers(
            self.stream_id,
            self._req.method,
            self._req.url,
            self._headers,
            end_stream=end_stream,
        )
        self._headers_sent = True
        self._headers = None

    async def write_headers(self, status_line: str, headers: Mapping[str, str]) -> None:
        # Buffer headers so that we can set END_STREAM on HEADERS
        # when there is no request body.
        self._headers = list(headers.items())

    async def write(
        self,
        chunk: bytes,
        *,
        drain: bool = True,
        LIMIT: int = 0x10000,
    ) -> None:
        if self._eof:
            raise RuntimeError("Cannot write after EOF")

        if not self._headers_sent:
            if self._headers is None:
                raise RuntimeError("Headers must be written before body")
            self._send_headers(end_stream=False)

        if chunk:
            await self._protocol._connection.send_data(
                self.stream_id, chunk, end_stream=False
            )
            self._output_size += len(chunk)

        # we would drain here but
        # drain is no-op in HTTP/2

    async def write_eof(self, chunk: bytes = b"") -> None:
        if self._eof:
            return

        if not self._headers_sent:
            if self._headers is None:
                raise RuntimeError("Headers must be written before body")

            if chunk:
                self._send_headers(end_stream=False)
                await self._protocol._connection.send_data(
                    self.stream_id, chunk, end_stream=True
                )
                self._output_size += len(chunk)
            else:
                # Body-less request: HEADERS frame carries END_STREAM.
                self._send_headers(end_stream=True)
        else:
            # Headers were already sent; send a final DATA frame with END_STREAM.
            await self._protocol._connection.send_data(
                self.stream_id, chunk, end_stream=True
            )
            self._output_size += len(chunk)

        self._eof = True

    def set_eof(self) -> None:
        """Called when there is no body."""
        if self._eof:
            return

        if not self._headers_sent:
            if self._headers is None:
                raise RuntimeError("Headers must be written before EOF")
            self._send_headers(end_stream=True)

        self._eof = True

    async def drain(self) -> None:
        # HTTP/2 flow control is handled inside send_data().
        pass

    def enable_compression(self, *args, **kwargs) -> None:
        # HTTP/2 compresses headers automatically; no body compression here.
        pass

    def enable_chunking(self) -> None:
        # HTTP/2 does not use chunked transfer encoding.
        pass
