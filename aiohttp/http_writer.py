"""Http related parsers and protocol."""

import asyncio
import collections
import zlib

from .abc import AbstractStreamWriter


__all__ = ('StreamWriter', 'HttpVersion', 'HttpVersion10', 'HttpVersion11')

HttpVersion = collections.namedtuple('HttpVersion', ['major', 'minor'])
HttpVersion10 = HttpVersion(1, 0)
HttpVersion11 = HttpVersion(1, 1)


class StreamWriter(AbstractStreamWriter):

    def __init__(self, protocol, transport, loop, on_chunk_sent=None):
        self._protocol = protocol
        self._transport = transport

        self.loop = loop
        self.length = None
        self.chunked = False
        self.buffer_size = 0
        self.output_size = 0

        self._eof = False
        self._compress = None
        self._drain_waiter = None

        self._on_chunk_sent = on_chunk_sent

    @property
    def transport(self):
        return self._transport

    @property
    def protocol(self):
        return self._protocol

    def enable_chunking(self):
        self.chunked = True

    def enable_compression(self, encoding='deflate'):
        zlib_mode = (16 + zlib.MAX_WBITS
                     if encoding == 'gzip' else -zlib.MAX_WBITS)
        self._compress = zlib.compressobj(wbits=zlib_mode)

    def _write(self, chunk):
        size = len(chunk)
        self.buffer_size += size
        self.output_size += size

        if self._transport is None or self._transport.is_closing():
            raise asyncio.CancelledError('Cannot write to closing transport')
        self._transport.write(chunk)

    async def write(self, chunk, *, drain=True, LIMIT=0x10000):
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

    async def write_headers(self, status_line, headers, SEP=': ', END='\r\n'):
        """Write request/response status and headers."""
        # status + headers
        headers = status_line + ''.join(
            [k + SEP + v + END for k, v in headers.items()])
        headers = headers.encode('utf-8') + b'\r\n'
        self._write(headers)

    async def write_eof(self, chunk=b''):
        if self._eof:
            return

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

    async def drain(self):
        """Flush the write buffer.

        The intended use is to write

          await w.write(data)
          await w.drain()
        """
        if self._protocol.transport is not None:
            await self._protocol._drain_helper()
