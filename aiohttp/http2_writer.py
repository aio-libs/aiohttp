"""Http related parsers and protocol."""

import asyncio
import sys
from typing import Awaitable, Callable, Iterable, Optional, Sequence, Union

# Reflects h2/connection from a lower-level prespective so
# socket writing can be a bit more optimized.
from hpack.hpack import Decoder, Encoder
from hyperframe.frame import ContinuationFrame, DataFrame, Frame, HeadersFrame
from multidict import CIMultiDict

from .abc import AbstractStreamWriter
from .base_protocol import BaseProtocol
from .client_exceptions import ClientConnectionResetError
from .compression_utils import ZLibCompressor
from .helpers import NO_EXTENSIONS

MIN_PAYLOAD_FOR_WRITELINES = 2048
IS_PY313_BEFORE_313_2 = (3, 13, 0) <= sys.version_info < (3, 13, 2)
IS_PY_BEFORE_312_9 = sys.version_info < (3, 12, 9)
SKIP_WRITELINES = IS_PY313_BEFORE_313_2 or IS_PY_BEFORE_312_9

# Callbacks from aiosignal.Signal.send(...)
_T_OnChunkSent = Optional[Callable[[bytes], Awaitable[None]]]
_T_OnHeadersSent = Optional[Callable[["CIMultiDict[str]"], Awaitable[None]]]

# Possible HTTP 2 Callback idea for TraceConfig
_T_OnFrameSent = Optional[Callable[[Frame], Awaitable[None]]]


# writelines is not safe for use
# on Python 3.12+ until 3.12.9
# on Python 3.13+ until 3.13.2
# and on older versions it not any faster than write
# CVE-2024-12254: https://github.com/python/cpython/pull/127656


class H2StreamWriter(AbstractStreamWriter):
    """Http 2 stream writer for aiohttp"""

    length: Optional[int] = None
    chunked: bool = False
    _eof: bool = False
    _compress: Optional[ZLibCompressor] = None
    _stream_id: Optional[int] = None

    def __init__(
        self,
        protocol: BaseProtocol,
        loop: asyncio.AbstractEventLoop,
        stream_id: int,
        encoder: Optional[Encoder] = None,
        on_chunk_sent: _T_OnChunkSent = None,
        on_headers_sent: _T_OnHeadersSent = None,
        on_frames_sent: _T_OnFrameSent = None,
        max_frame_size: int = 0,
    ) -> None:
        """
        return `H2StreamWriter` initalized

        :param protocol: the BaseProtocol to utilize
        :param stream_id: the stream id for the given writer to utilize.
        :param encoder: the encoder to utilize for headers to be serlized with
        :param on_chunk_sent: Corresponds to a on_chunk_sent callback (TraceConfig Signal)
        :param on_headers_sent: Corresponds to a on_headers_sent callback (TraceConfig Signal)
        :param on_frames_sent: Corresponds to a on_frames_sent callback (TraceConfig Signal)
        :param max_frame_size: the amount to cutoff each frame at
        """
        self._protocol = protocol
        self.loop = loop
        self._on_chunk_sent: _T_OnChunkSent = on_chunk_sent
        self._on_headers_sent: _T_OnHeadersSent = on_headers_sent
        self._on_frames_sent: _T_OnFrameSent = on_frames_sent
        self._headers_buf: Optional[bytes] = None
        self._headers_written: bool = False

        if max_frame_size < 0:
            raise ValueError("max_frame_size should be a positive integer")
        self._max_frame_size = max_frame_size
        self._stream_id = stream_id
        self._encoder = encoder or Encoder()

    @property
    def transport(self) -> Optional[asyncio.Transport]:
        return self._protocol.transport

    @property
    def protocol(self) -> BaseProtocol:
        return self._protocol

    # TODO: h2 chunking?
    def enable_chunking(self) -> None:
        self.chunked = True

    # is_eof will help with a few things...
    async def write_headers(
        self,
        # XXX: status_line may need to be replaced with something else
        # or modified in the AbstractStreamWriter with
        # status:int, reason: bytes | str | None Maybe?
        # status_line: str,
        headers: "CIMultiDict[str]",
        *,
        huffman: bool = True,
        is_eof: bool = False,
        drain: bool = False,
    ) -> None:
        """Writes a handful of provided headers:

        :param headers: the headers to transform into http2 frames
        :param huffman: use huffman encoding
        :param is_eof: signal the end of a given handful of given frames
        :param drain: perform sendoff immediately

        """
        if self._on_headers_sent is not None:
            await self._on_headers_sent(headers)

        # TODO: http/2 bytes wrtiter for Cythonized speedups
        # for CIMultiDict[str] to Iterable[tuple[bytes, bytes]] or simillar?

        # We can go lower level with this one in the future. There's already plans to make a cython version of hpack
        # for aiohttp and also for hyper / httpx
        # I'm not in the mood to compete and I share with all intrested parties :))
        encoded_headers = self._encoder.encode(headers, huffman)

        # h2 comment: Slice into blocks of max_frame_size. Be careful with this:
        # it only works right because we never send padded frames or priority
        # information on the frames. Revisit this if we do.
        if self._max_frame_size:
            header_blocks = [
                encoded_headers[i : i + (self._max_frame_size or 0)]
                for i in range(
                    0,
                    len(encoded_headers),
                    (self._max_frame_size or 0),
                )
            ]
            frames = [HeadersFrame(self._stream_id, header_blocks[0])]
            frames.extend(
                ContinuationFrame(self._stream_id, block) for block in header_blocks[1:]
            )
            if is_eof:
                frames[-1].flags.add("END_STREAM")

            await self.send_frames(frames, drain)

        else:
            frame = HeadersFrame(self._stream_id, encoded_headers)
            if is_eof:
                frame.flags.add("END_STREAM")

            await self.send_frame(frame, drain)

    def _writelines(self, chunks: Iterable[bytes]) -> None:
        size = 0
        for chunk in chunks:
            size += len(chunk)
        self.buffer_size += size
        self.output_size += size
        transport = self._protocol.transport
        if transport is None or transport.is_closing():
            raise ClientConnectionResetError("Cannot write to closing transport")
        if SKIP_WRITELINES or size < MIN_PAYLOAD_FOR_WRITELINES:
            transport.write(b"".join(chunks))
        else:
            transport.writelines(chunks)

    # Custom (Vizonex additions)
    async def send_frames(self, frames: Sequence[Frame], drain: bool = True) -> None:
        """Writes a Sequence of frames
        :param frames: the frames that should be written.
        :param drain: Sends off data to destination immediately.
        """
        if self._on_frames_sent is not None:
            for f in frames:
                await self._on_frames_sent(f)
        self._writelines([f.serialize() for f in frames])
        if drain:
            await self.drain()

    def _write(self, chunk: Union[bytes, bytearray, memoryview]) -> None:
        size = len(chunk)
        self.buffer_size += size
        self.output_size += size
        transport = self._protocol.transport
        if transport is None or transport.is_closing():
            raise ClientConnectionResetError("Cannot write to closing transport")
        transport.write(chunk)

    async def send_frame(self, frame: Frame, drain: bool = True) -> None:
        """Writes a single frame"""
        if self._on_frames_sent is not None:
            await self._on_frames_sent(frame)
        self._write(frame.serialize())
        if drain:
            await self.drain()

    async def send_data(
        self,
        chunk: Union[bytes, bytearray, memoryview],
        is_eof: bool = False,
        pad_length: Optional[int] = None,
        drain: bool = False,
    ) -> None:
        """Sends a single data-frame, This also takes compression into account if compression is utilized"""
        # Smarter to put the chunk here than anywhere else incase
        if self._on_chunk_sent is not None:
            await self._on_chunk_sent(chunk)

        if isinstance(chunk, memoryview):
            if chunk.nbytes != len(chunk):
                # just reshape it
                chunk = chunk.cast("c")

        if self._compress is not None:
            chunk = await self._compress.compress(chunk)
            if not chunk:
                return

        if self.length is not None:
            chunk_len = len(chunk)
            if self.length >= chunk_len:
                self.length = self.length - chunk_len
            else:
                chunk = chunk[: self.length]
                self.length = 0

            if not chunk:
                return

        df = DataFrame(self._stream_id, data=chunk)
        if pad_length:
            df.flags.add("PADDED")
        if is_eof:
            df.flags.add("END_STREAM")

        await self.send_frame(chunk, drain)

    async def write(
        self, chunk: Union[bytes, bytearray, memoryview], *, drain: bool = True
    ) -> None:
        """
        Writes chunk of data to a stream.

        write_eof() indicates end of stream.
        writer can't be used after write_eof() method being called.
        write() return drain future.
        """
        await self.send_data(chunk, drain)

    async def drain(self) -> None:
        """Flush the write buffer.

        The intended use is to write::

            await w.write(data)
            await w.drain()
        """
        protocol = self._protocol
        if protocol.transport is not None and protocol._paused:
            await protocol._drain_helper()
