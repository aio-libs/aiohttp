"""Http related parsers and protocol."""

import asyncio
import collections
import zlib
from typing import Any, Awaitable, Callable, Optional, Union  # noqa

from .abc import AbstractStreamWriter
from .base_protocol import BaseProtocol
from .helpers import NO_EXTENSIONS


__all__ = ('StreamWriter', 'HttpVersion', 'HttpVersion10', 'HttpVersion11')

HttpVersion = collections.namedtuple('HttpVersion', ['major', 'minor'])
HttpVersion10 = HttpVersion(1, 0)
HttpVersion11 = HttpVersion(1, 1)


_T_Data = Union[bytes, bytearray, memoryview]
_T_OnChunkSent = Optional[Callable[[_T_Data], Awaitable[None]]]


class StreamWriter(AbstractStreamWriter):

    def __init__(self,
                 protocol: BaseProtocol,
                 loop: asyncio.AbstractEventLoop,
                 on_chunk_sent: _T_OnChunkSent = None) -> None:
        self._protocol = protocol
        self._transport = protocol.transport

        self.loop = loop
        self.length = None
        self.chunked = False
        self.buffer_size = 0
        self.output_size = 0

        self._eof = False
        self._compress = None  # type: Any
        self._drain_waiter = None

        self._on_chunk_sent = on_chunk_sent  # type: _T_OnChunkSent

    @property
    def transport(self) -> asyncio.Transport:
        return self._transport

    @property
    def protocol(self) -> BaseProtocol:
        return self._protocol

    def enable_chunking(self) -> None:
        self.chunked = True

    def enable_compression(self, encoding: str='deflate') -> None:
        zlib_mode = (16 + zlib.MAX_WBITS
                     if encoding == 'gzip' else -zlib.MAX_WBITS)
        self._compress = zlib.compressobj(wbits=zlib_mode)

    def _write(self, chunk) -> None:
        size = len(chunk)
        self.buffer_size += size
        self.output_size += size

        if self._transport is None or self._transport.is_closing():
            raise ConnectionResetError('Cannot write to closing transport')
        self._transport.write(chunk)

    async def write(self, chunk, *, drain=True, LIMIT=0x10000) -> None:
        """Writes chunk of data to a stream.

        write_eof() indicates end of stream.
        writer can't be used after write_eof() method being called.
        write() return drain future.
        """
        if self._on_chunk_sent is not None:
            await self._on_chunk_sent(chunk)

        if self._compress is not None:
            chunk = self._compress.compress(chunk)
            if not chunk:
                return

        if self.length is not None:
            chunk_len = len(chunk)
            if self.length >= chunk_len:
                self.length = self.length - chunk_len
            else:
                chunk = chunk[:self.length]
                self.length = 0
                if not chunk:
                    return

        if chunk:
            if self.chunked:
                chunk_len = ('%x\r\n' % len(chunk)).encode('ascii')
                chunk = chunk_len + chunk + b'\r\n'

            self._write(chunk)

            if self.buffer_size > LIMIT and drain:
                self.buffer_size = 0
                await self.drain()

    async def write_headers(self, status_line, headers) -> None:
        """Write request/response status and headers."""
        # status + headers
        buf = _serialize_headers(status_line, headers)
        self._write(buf)

    async def write_eof(self, chunk=b'') -> None:
        if self._eof:
            return

        if chunk and self._on_chunk_sent is not None:
            await self._on_chunk_sent(chunk)

        if self._compress:
            if chunk:
                chunk = self._compress.compress(chunk)

            chunk = chunk + self._compress.flush()
            if chunk and self.chunked:
                chunk_len = ('%x\r\n' % len(chunk)).encode('ascii')
                chunk = chunk_len + chunk + b'\r\n0\r\n\r\n'
        else:
            if self.chunked:
                if chunk:
                    chunk_len = ('%x\r\n' % len(chunk)).encode('ascii')
                    chunk = chunk_len + chunk + b'\r\n0\r\n\r\n'
                else:
                    chunk = b'0\r\n\r\n'

        if chunk:
            self._write(chunk)

        await self.drain()

        self._eof = True
        self._transport = None

    async def drain(self) -> None:
        """Flush the write buffer.

        The intended use is to write

          await w.write(data)
          await w.drain()
        """
        if self._protocol.transport is not None:
            await self._protocol._drain_helper()


def _py_serialize_headers(status_line, headers):
    headers = status_line + '\r\n' + ''.join(
        [k + ': ' + v + '\r\n' for k, v in headers.items()])
    return headers.encode('utf-8') + b'\r\n'


_serialize_headers = _py_serialize_headers

try:
    import aiohttp._http_writer as _http_writer  # type: ignore
    _c_serialize_headers = _http_writer._serialize_headers
    if not NO_EXTENSIONS:  # pragma: no cover
        _serialize_headers = _c_serialize_headers
except ImportError:
    pass
