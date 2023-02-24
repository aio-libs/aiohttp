import asyncio
import zlib
from concurrent.futures import Executor
from typing import Any, Optional

try:
    # Protocol has been added to Python 3.8
    # noinspection PyUnresolvedReferences
    from typing import Protocol

    class Compressor(Protocol):
        def compress(self, data: bytes) -> bytes:
            ...

        def flush(self, mode: int = ...) -> bytes:
            ...

        def copy(self) -> "Compressor":
            ...

    class Decompressor(Protocol):
        unused_data: bytes
        unconsumed_tail: bytes
        eof: bool

        def decompress(self, data: bytes, max_length: int = ...) -> bytes:
            ...

        def flush(self, length: int = ...) -> bytes:
            ...

        def copy(self) -> "Decompressor":
            ...

except ImportError:
    Compressor = Any
    Decompressor = Any

MAX_SYNC_CHUNK_SIZE = 1024


class ZlibBaseHandler:
    def __init__(
        self,
        encoding: Optional[str] = None,
        mode: Optional[int] = None,
        executor: Optional[Executor] = None,
        max_sync_chunk_size: Optional[int] = MAX_SYNC_CHUNK_SIZE,
    ):
        assert (
            encoding is not None or mode is not None
        ), "Either encoding or mode must be provided"
        if mode is not None:
            self._mode = mode
        elif encoding == "gzip":
            self._mode = 16 + zlib.MAX_WBITS
        elif encoding == "deflate":
            self._mode = -zlib.MAX_WBITS
        else:
            self._mode = zlib.MAX_WBITS
        self._executor = executor
        self._max_sync_chunk_size = max_sync_chunk_size


class ZLibCompressor(ZlibBaseHandler):
    def __init__(
        self,
        encoding: Optional[str] = None,
        mode: Optional[int] = None,
        level: int = -1,
        strategy: int = zlib.Z_DEFAULT_STRATEGY,
        executor: Optional[Executor] = None,
        max_sync_chunk_size: Optional[int] = MAX_SYNC_CHUNK_SIZE,
    ):
        super().__init__(encoding, mode, executor, max_sync_chunk_size)
        self._compressor: Compressor = zlib.compressobj(
            wbits=self._mode, level=level, strategy=strategy
        )

    def compress_sync(self, data: bytes) -> bytes:
        return self._compressor.compress(data)

    async def compress(self, data: bytes) -> bytes:
        if (
            self._max_sync_chunk_size is not None
            and len(data) > self._max_sync_chunk_size
        ):
            # TODO: Replace with asyncio.to_thread as soon as we drop Python 3.8 and below
            return await asyncio.get_event_loop().run_in_executor(
                self._executor, self.compress_sync, data
            )
        return self.compress_sync(data)

    def flush(self, mode: int = zlib.Z_FINISH) -> bytes:
        return self._compressor.flush(mode)


class ZLibDecompressor(ZlibBaseHandler):
    def __init__(
        self,
        encoding: Optional[str] = None,
        mode: Optional[int] = None,
        executor: Optional[Executor] = None,
        max_sync_chunk_size: Optional[int] = MAX_SYNC_CHUNK_SIZE,
    ):
        super().__init__(encoding, mode, executor, max_sync_chunk_size)
        self._decompressor: Decompressor = zlib.decompressobj(wbits=self._mode)

    def decompress_sync(self, data: bytes, max_length: int = 0) -> bytes:
        return self._decompressor.decompress(data, max_length)

    async def decompress(self, data: bytes, max_length: int = 0) -> bytes:
        if (
            self._max_sync_chunk_size is not None
            and len(data) > self._max_sync_chunk_size
        ):
            return await asyncio.get_event_loop().run_in_executor(
                self._executor, self.decompress_sync, data, max_length
            )
        return self.decompress_sync(data, max_length)

    def flush(self, length: int = 0) -> bytes:
        return (
            self._decompressor.flush(length)
            if length > 0
            else self._decompressor.flush()
        )

    @property
    def eof(self) -> bool:
        return self._decompressor.eof
