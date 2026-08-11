import asyncio
import sys
import zlib
from abc import ABC, abstractmethod
from concurrent.futures import Executor
from typing import Any, Final, Generic, Protocol, TypedDict, TypeVar, cast

if sys.version_info >= (3, 12):
    from collections.abc import Buffer
else:
    from typing import Union

    Buffer = Union[bytes, bytearray, "memoryview[int]", "memoryview[bytes]"]

try:
    try:
        import brotlicffi as brotli
    except ImportError:
        import brotli

    HAS_BROTLI = True
except ImportError:  # pragma: no cover
    HAS_BROTLI = False

try:
    if sys.version_info >= (3, 14):
        from compression.zstd import ZstdDecompressor  # noqa: I900
    else:  # TODO(PY314): Remove mentions of backports.zstd across codebase
        from backports.zstd import ZstdDecompressor

    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False


MAX_SYNC_CHUNK_SIZE = 4096

# Unlimited decompression constants - different libraries use different conventions
ZLIB_MAX_LENGTH_UNLIMITED = 0  # zlib uses 0 to mean unlimited
ZSTD_MAX_LENGTH_UNLIMITED = -1  # zstd uses -1 to mean unlimited

# Concatenated members are decoded through a window that starts small and
# doubles. A fresh decompressor copies everything past the member it decodes
# into unused_data, so handing it the whole remaining buffer at every boundary
# is quadratic over a stream of small members.
MEMBER_WINDOW_MIN = 64
MEMBER_WINDOW_MAX = 65536

# Cap on concatenated members decoded in one call. Real payloads are unlikely
# to have more than a few members.
MAX_DECOMPRESS_MEMBERS = 1024


class TooManyMembersError(ValueError):
    """A stream concatenated more members than the caller allows."""


class ZLibCompressObjProtocol(Protocol):
    def compress(self, data: Buffer) -> bytes: ...
    def flush(self, mode: int = ..., /) -> bytes: ...


class ZLibDecompressObjProtocol(Protocol):
    def decompress(self, data: Buffer, max_length: int = ...) -> bytes: ...
    def flush(self, length: int = ..., /) -> bytes: ...

    @property
    def eof(self) -> bool: ...

    @property
    def unconsumed_tail(self) -> bytes: ...

    @property
    def unused_data(self) -> bytes: ...


class ZLibBackendProtocol(Protocol):
    MAX_WBITS: int
    Z_FULL_FLUSH: int
    Z_SYNC_FLUSH: int
    Z_BEST_SPEED: int
    Z_FINISH: int

    def compressobj(
        self,
        level: int = ...,
        method: int = ...,
        wbits: int = ...,
        memLevel: int = ...,
        strategy: int = ...,
        zdict: Buffer | None = ...,
    ) -> ZLibCompressObjProtocol: ...
    def decompressobj(
        self, wbits: int = ..., zdict: Buffer = ...
    ) -> ZLibDecompressObjProtocol: ...

    def compress(
        self, data: Buffer, /, level: int = ..., wbits: int = ...
    ) -> bytes: ...
    def decompress(
        self, data: Buffer, /, wbits: int = ..., bufsize: int = ...
    ) -> bytes: ...


class CompressObjArgs(TypedDict, total=False):
    wbits: int
    strategy: int
    level: int


class ZLibBackendWrapper:
    def __init__(self, _zlib_backend: ZLibBackendProtocol):
        self._zlib_backend: ZLibBackendProtocol = _zlib_backend

    @property
    def name(self) -> str:
        return getattr(self._zlib_backend, "__name__", "undefined")

    @property
    def MAX_WBITS(self) -> int:
        return self._zlib_backend.MAX_WBITS

    @property
    def Z_FULL_FLUSH(self) -> int:
        return self._zlib_backend.Z_FULL_FLUSH

    @property
    def Z_SYNC_FLUSH(self) -> int:
        return self._zlib_backend.Z_SYNC_FLUSH

    @property
    def Z_BEST_SPEED(self) -> int:
        return self._zlib_backend.Z_BEST_SPEED

    @property
    def Z_FINISH(self) -> int:
        return self._zlib_backend.Z_FINISH

    def compressobj(self, *args: Any, **kwargs: Any) -> ZLibCompressObjProtocol:
        return self._zlib_backend.compressobj(*args, **kwargs)

    def decompressobj(self, *args: Any, **kwargs: Any) -> ZLibDecompressObjProtocol:
        return self._zlib_backend.decompressobj(*args, **kwargs)

    def compress(self, data: Buffer, *args: Any, **kwargs: Any) -> bytes:
        return self._zlib_backend.compress(data, *args, **kwargs)

    def decompress(self, data: Buffer, *args: Any, **kwargs: Any) -> bytes:
        return self._zlib_backend.decompress(data, *args, **kwargs)

    # Everything not explicitly listed in the Protocol we just pass through
    def __getattr__(self, attrname: str) -> Any:
        return getattr(self._zlib_backend, attrname)


ZLibBackend: ZLibBackendWrapper = ZLibBackendWrapper(zlib)


def set_zlib_backend(new_zlib_backend: ZLibBackendProtocol) -> None:
    ZLibBackend._zlib_backend = new_zlib_backend


def encoding_to_mode(
    encoding: str | None = None,
    suppress_deflate_header: bool = False,
) -> int:
    if encoding == "gzip":
        return 16 + ZLibBackend.MAX_WBITS

    return -ZLibBackend.MAX_WBITS if suppress_deflate_header else ZLibBackend.MAX_WBITS


class MemberDecompressObjProtocol(Protocol):
    def decompress(self, data: Buffer, max_length: int = ...) -> bytes: ...

    @property
    def eof(self) -> bool: ...

    @property
    def unused_data(self) -> bytes: ...


_DecompressObjT = TypeVar("_DecompressObjT", bound=MemberDecompressObjProtocol)


class DecompressionBaseHandler(ABC):
    def __init__(
        self,
        executor: Executor | None = None,
        max_sync_chunk_size: int | None = MAX_SYNC_CHUNK_SIZE,
    ):
        """Base class for decompression handlers."""
        self._executor = executor
        self._max_sync_chunk_size = max_sync_chunk_size

    @abstractmethod
    def decompress_sync(
        self, data: Buffer, max_length: int = ZLIB_MAX_LENGTH_UNLIMITED
    ) -> bytes:
        """Decompress the given data."""

    async def decompress(
        self, data: Buffer, max_length: int = ZLIB_MAX_LENGTH_UNLIMITED
    ) -> bytes:
        """Decompress the given data."""
        if (
            self._max_sync_chunk_size is not None
            and len(data) > self._max_sync_chunk_size
        ):
            return await asyncio.get_event_loop().run_in_executor(
                self._executor, self.decompress_sync, data, max_length
            )
        return self.decompress_sync(data, max_length)

    @property
    @abstractmethod
    def data_available(self) -> bool:
        """Return True if more output is available by passing b""."""


class ConcatDecompressionHandler(DecompressionBaseHandler, Generic[_DecompressObjT]):
    """Handler for a codec whose streams may concatenate independent members.

    Concatenated gzip/deflate members and multi-frame zstd
    (https://datatracker.ietf.org/doc/html/rfc8878#section-3.1.1) decode the
    same way: a decompressor handles one member, then flags eof and leaves the
    rest of the input in unused_data, so every member after it needs a fresh
    one.
    """

    # Sentinel this codec's decompress() takes to mean "no output limit".
    _unlimited: int
    _decompressor: _DecompressObjT
    # Input a max_length-capped walk stopped short of, fed back on the next call.
    _pending_unused_data: bytes | None = None

    @abstractmethod
    def _new_decompressor(self) -> _DecompressObjT:
        """Return a decompressor for the next member."""

    def _decompress_members(self, first: bytes, max_length: int) -> bytes:
        """Decode the members following the one ``first`` came from."""
        remaining = memoryview(self._decompressor.unused_data)
        parts = [first]
        produced = len(first)
        pos = 0
        window = MEMBER_WINDOW_MIN
        budget = max_length
        members = 1

        while pos < len(remaining):
            if self._decompressor.eof:
                members += 1
                if members > MAX_DECOMPRESS_MEMBERS:
                    raise TooManyMembersError(
                        f"Compressed stream has more than "
                        f"{MAX_DECOMPRESS_MEMBERS} members"
                    )
                # Replace the spent decompressor before the budget check below
                # can break out of the loop: it still lists these bytes in its
                # unused_data and would hand them back on the next call.
                self._decompressor = self._new_decompressor()
                window = MEMBER_WINDOW_MIN
            if max_length != self._unlimited:
                budget = max_length - produced
                if budget <= 0:
                    self._pending_unused_data = bytes(remaining[pos:])
                    break

            end = min(pos + window, len(remaining))
            chunk = self._decompressor.decompress(remaining[pos:end], budget)
            if chunk:
                parts.append(chunk)
                produced += len(chunk)

            if self._decompressor.eof:
                pos = end - len(self._decompressor.unused_data)
            else:
                pos = end
                # Doubling the window on each iteration avoids too many calls
                # when a large member is present, while protecting us from
                # quadratic usage when members are of window+1 length.
                window = min(window * 2, MEMBER_WINDOW_MAX)

        return b"".join(parts)


class ZLibCompressor:
    def __init__(
        self,
        encoding: str | None = None,
        suppress_deflate_header: bool = False,
        level: int | None = None,
        wbits: int | None = None,
        strategy: int | None = None,
        executor: Executor | None = None,
        max_sync_chunk_size: int | None = MAX_SYNC_CHUNK_SIZE,
    ):
        self._executor = executor
        self._max_sync_chunk_size = max_sync_chunk_size
        self._mode = (
            encoding_to_mode(encoding, suppress_deflate_header)
            if wbits is None
            else wbits
        )
        self._zlib_backend: Final = ZLibBackendWrapper(ZLibBackend._zlib_backend)

        kwargs: CompressObjArgs = {}
        kwargs["wbits"] = self._mode
        if strategy is not None:
            kwargs["strategy"] = strategy
        if level is not None:
            kwargs["level"] = level
        self._compressor = self._zlib_backend.compressobj(**kwargs)

    def compress_sync(self, data: Buffer) -> bytes:
        return self._compressor.compress(data)

    async def compress(self, data: Buffer) -> bytes:
        """Compress the data and returned the compressed bytes.

        Note that flush() must be called after the last call to compress()

        If the data size is large than the max_sync_chunk_size, the compression
        will be done in the executor. Otherwise, the compression will be done
        in the event loop.

        **WARNING: This method is NOT cancellation-safe when used with flush().**
        If this operation is cancelled, the compressor state may be corrupted.
        The connection MUST be closed after cancellation to avoid data corruption
        in subsequent compress operations.

        For cancellation-safe compression (e.g., WebSocket), the caller MUST wrap
        compress() + flush() + send operations in a shield and lock to ensure atomicity.
        """
        # For large payloads, offload compression to executor to avoid blocking event loop
        should_use_executor = (
            self._max_sync_chunk_size is not None
            and len(data) > self._max_sync_chunk_size
        )
        if should_use_executor:
            return await asyncio.get_running_loop().run_in_executor(
                self._executor, self._compressor.compress, data
            )
        return self.compress_sync(data)

    def flush(self, mode: int | None = None) -> bytes:
        """Flush the compressor synchronously.

        **WARNING: This method is NOT cancellation-safe when called after compress().**
        The flush() operation accesses shared compressor state. If compress() was
        cancelled, calling flush() may result in corrupted data. The connection MUST
        be closed after compress() cancellation.

        For cancellation-safe compression (e.g., WebSocket), the caller MUST wrap
        compress() + flush() + send operations in a shield and lock to ensure atomicity.
        """
        return self._compressor.flush(
            mode if mode is not None else self._zlib_backend.Z_FINISH
        )


class ZLibDecompressor(ConcatDecompressionHandler[ZLibDecompressObjProtocol]):
    _unlimited = ZLIB_MAX_LENGTH_UNLIMITED

    def __init__(
        self,
        encoding: str | None = None,
        suppress_deflate_header: bool = False,
        executor: Executor | None = None,
        max_sync_chunk_size: int | None = MAX_SYNC_CHUNK_SIZE,
    ):
        super().__init__(executor=executor, max_sync_chunk_size=max_sync_chunk_size)
        self._mode = encoding_to_mode(encoding, suppress_deflate_header)
        self._zlib_backend: Final = ZLibBackendWrapper(ZLibBackend._zlib_backend)
        self._decompressor = self._new_decompressor()
        self._last_empty = False

    def _new_decompressor(self) -> ZLibDecompressObjProtocol:
        return self._zlib_backend.decompressobj(wbits=self._mode)

    def decompress_sync(
        self, data: Buffer, max_length: int = ZLIB_MAX_LENGTH_UNLIMITED
    ) -> bytes:
        if self._pending_unused_data is not None:
            data = self._pending_unused_data + bytes(data)
            self._pending_unused_data = None
        result = self._decompressor.decompress(
            self._decompressor.unconsumed_tail + data, max_length
        )

        # Concatenated gzip/deflate stream: decode the members after this one.
        if self._decompressor.eof and self._decompressor.unused_data:
            result = self._decompress_members(result, max_length)

        # Only way to know that isal has no further data is checking we get no output
        self._last_empty = result == b""

        # Member ended exactly at chunk boundary — no unused_data, but the
        # next feed_data() call would fail on the spent decompressor.
        # Only reset for gzip; deflate's feed_eof() relies on eof=True to
        # confirm the stream is complete.
        if self._decompressor.eof and self._mode > self._zlib_backend.MAX_WBITS:
            self._decompressor = self._new_decompressor()

        return result

    def flush(self, length: int = 0) -> bytes:
        return (
            self._decompressor.flush(length)
            if length > 0
            else self._decompressor.flush()
        )

    @property
    def data_available(self) -> bool:
        return (
            bool(self._decompressor.unconsumed_tail)
            or not self._last_empty
            or self._pending_unused_data is not None
        )

    @property
    def eof(self) -> bool:
        return self._decompressor.eof


class BrotliDecompressor(DecompressionBaseHandler):
    # Supports both 'brotlipy' and 'Brotli' packages
    # since they share an import name. The top branches
    # are for 'brotlipy' and bottom branches for 'Brotli'
    def __init__(
        self,
        executor: Executor | None = None,
        max_sync_chunk_size: int | None = MAX_SYNC_CHUNK_SIZE,
    ) -> None:
        """Decompress data using the Brotli library."""
        if not HAS_BROTLI:
            raise RuntimeError(
                "The brotli decompression is not available. "
                "Please install `Brotli` module"
            )
        self._obj = brotli.Decompressor()
        self._last_empty = False
        super().__init__(executor=executor, max_sync_chunk_size=max_sync_chunk_size)

    def decompress_sync(
        self, data: Buffer, max_length: int = ZLIB_MAX_LENGTH_UNLIMITED
    ) -> bytes:
        """Decompress the given data."""
        if hasattr(self._obj, "decompress"):
            if max_length == ZLIB_MAX_LENGTH_UNLIMITED:
                result = cast(bytes, self._obj.decompress(data))
            else:
                result = cast(bytes, self._obj.decompress(data, max_length))
        else:
            if max_length == ZLIB_MAX_LENGTH_UNLIMITED:
                result = cast(bytes, self._obj.process(data))
            else:
                result = cast(bytes, self._obj.process(data, max_length))
        # Only way to know that brotli has no further data is checking we get no output
        self._last_empty = result == b""
        return result

    def flush(self) -> bytes:
        """Flush the decompressor."""
        if hasattr(self._obj, "flush"):
            return cast(bytes, self._obj.flush())
        return b""

    @property
    def data_available(self) -> bool:
        return not self._obj.is_finished() and not self._last_empty


class ZSTDDecompressor(ConcatDecompressionHandler["ZstdDecompressor"]):
    _unlimited = ZSTD_MAX_LENGTH_UNLIMITED

    def __init__(
        self,
        executor: Executor | None = None,
        max_sync_chunk_size: int | None = MAX_SYNC_CHUNK_SIZE,
    ) -> None:
        if not HAS_ZSTD:
            raise RuntimeError(
                "The zstd decompression is not available. "
                "Please install `backports.zstd` module"
            )
        super().__init__(executor=executor, max_sync_chunk_size=max_sync_chunk_size)
        self._decompressor = self._new_decompressor()

    def _new_decompressor(self) -> "ZstdDecompressor":
        return ZstdDecompressor()

    def decompress_sync(
        self, data: Buffer, max_length: int = ZLIB_MAX_LENGTH_UNLIMITED
    ) -> bytes:
        # zstd uses -1 for unlimited, while zlib uses 0 for unlimited
        # Convert the zlib convention (0=unlimited) to zstd convention (-1=unlimited)
        zstd_max_length = (
            ZSTD_MAX_LENGTH_UNLIMITED
            if max_length == ZLIB_MAX_LENGTH_UNLIMITED
            else max_length
        )
        if self._pending_unused_data is not None:
            data = self._pending_unused_data + data
            self._pending_unused_data = None
        result = self._decompressor.decompress(data, zstd_max_length)

        # Concatenated zstd stream: decode the frames after this one.
        if self._decompressor.eof and self._decompressor.unused_data:
            result = self._decompress_members(result, zstd_max_length)

        # Frame ended exactly at chunk boundary — no unused_data, but the
        # next feed_data() call would fail on the spent decompressor.
        # Prepare a fresh one for the next chunk.
        if self._decompressor.eof:
            self._decompressor = self._new_decompressor()

        return result

    def flush(self) -> bytes:
        return b""

    @property
    def data_available(self) -> bool:
        return (
            not self._decompressor.needs_input and not self._decompressor.eof
        ) or self._pending_unused_data is not None
