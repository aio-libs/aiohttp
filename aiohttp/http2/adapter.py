"""HTTP/1.1 to HTTP/2 adapters."""

import asyncio
from typing import TYPE_CHECKING, Any, Iterable, List, Mapping, Optional, Tuple, Union

from multidict import CIMultiDict

from .. import hdrs
from ..abc import AbstractStreamWriter
from ..base_protocol import BaseProtocol
from ..helpers import HeadersDictProxy
from ..http_parser import RawResponseMessage
from ..http_writer import HttpVersion

if TYPE_CHECKING:
    from ..client_reqrep import ClientRequest


def get_version(protocol: BaseProtocol) -> str:
    """Helper to get the negotiated HTTP version from the protocol."""
    # backwards compatibility
    if not hasattr(protocol, "transport"):
        return "http/1.1"
    transport = protocol.transport
    assert transport is not None
    return _get_version(transport)


def _get_version(transport: asyncio.BaseTransport) -> str:
    ssl_object = transport.get_extra_info("ssl_object")
    alpn_protocol = ssl_object.selected_alpn_protocol() if ssl_object else "http/1.1"
    return alpn_protocol


def feed_headers(
    headers: Iterable[tuple[str, str]],
) -> RawResponseMessage:
    """Convert raw headers to the standard RawResponseMessage format"""
    # Build a minimal RawResponseMessage (the fields that ClientResponse uses).
    raw_headers: List[Tuple[bytes, bytes]] = []
    # we should consider raising an exception
    # if the server doesn't send :status
    code = 500
    ci_headers = CIMultiDict(headers)
    # there is no guarantee that the status code comes first
    for key, value in headers:
        if key == ":status":
            code = int(value)
        raw_headers.append((key.encode("latin-1"), value.encode("latin-1")))

    encoding = None
    enc = ci_headers.get(hdrs.CONTENT_ENCODING, "")
    if enc.isascii() and enc.lower() in {"gzip", "deflate", "br", "zstd"}:
        encoding = enc

    msg = RawResponseMessage(
        version=HttpVersion(2, 0),  # HTTP/2.0
        code=code,
        # HTTP/2 has no reason phrase
        reason="",
        headers=HeadersDictProxy(ci_headers),
        raw_headers=tuple(raw_headers),
        should_close=False,
        compression=encoding,
        upgrade=False,  # not implemented
        chunked=False,  # n/a
    )
    return msg


class Http2StreamWriter(AbstractStreamWriter):
    def __init__(
        self,
        protocol: Any,
        loop: asyncio.AbstractEventLoop,
        req: "ClientRequest",
        *,
        on_chunk_sent: Optional[Any] = None,
        on_headers_sent: Optional[Any] = None,
    ) -> None:
        del on_chunk_sent, on_headers_sent  # skipped for now

        self._req = req
        self._protocol = protocol
        assert req.stream_id
        self.stream_id: int = req.stream_id
        self.loop = loop

        self._headers: Optional[List[Tuple[str, str]]] = None
        self._headers_sent = False
        self._eof = False
        self.output_size = 0
        # constant
        self.buffer_size = 0

    @property
    def protocol(self) -> Any:
        return self._protocol

    @property
    def transport(self) -> Any:
        return self._protocol.transport

    def _send_headers(self, *, end_stream: bool) -> None:
        if self._headers_sent or self._headers is None:
            return

        self._protocol._connection.send_headers(
            self.stream_id,
            self._req.method,  # could be stored when `write_headers` is called
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
        chunk: Union[bytes, bytearray, memoryview, "memoryview[bytes]"],
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
                self.stream_id, bytes(chunk), end_stream=False
            )
            self.output_size += len(chunk)

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
                self.output_size += len(chunk)
            else:
                # Body-less request: HEADERS frame carries END_STREAM.
                self._send_headers(end_stream=True)
        else:
            # Headers were already sent; send a final DATA frame with END_STREAM.
            await self._protocol._connection.send_data(
                self.stream_id, chunk, end_stream=True
            )
            self.output_size += len(chunk)

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

    def enable_compression(self, *args: Any, **kwargs: Any) -> None:
        # HTTP/2 compresses headers automatically; no body compression here.
        pass

    def enable_chunking(self) -> None:
        # HTTP/2 does not use chunked transfer encoding (or, rather, chunked transfer encoding is built-in).
        pass
