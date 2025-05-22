import asyncio
import enum
import io
import json
import mimetypes
import os
import sys
import warnings
from abc import ABC, abstractmethod
from itertools import chain
from typing import (
    IO,
    TYPE_CHECKING,
    Any,
    Dict,
    Final,
    Iterable,
    Optional,
    Set,
    TextIO,
    Tuple,
    Type,
    Union,
)

from multidict import CIMultiDict

from . import hdrs
from .abc import AbstractStreamWriter
from .helpers import (
    _SENTINEL,
    content_disposition_header,
    guess_filename,
    parse_mimetype,
    sentinel,
)
from .streams import StreamReader
from .typedefs import JSONEncoder, _CIMultiDict

__all__ = (
    "PAYLOAD_REGISTRY",
    "get_payload",
    "payload_type",
    "Payload",
    "BytesPayload",
    "StringPayload",
    "IOBasePayload",
    "BytesIOPayload",
    "BufferedReaderPayload",
    "TextIOPayload",
    "StringIOPayload",
    "JsonPayload",
    "AsyncIterablePayload",
)

TOO_LARGE_BYTES_BODY: Final[int] = 2**20  # 1 MB
READ_SIZE: Final[int] = 2**16  # 64 KB
_CLOSE_FUTURES: Set[asyncio.Future[None]] = set()


if TYPE_CHECKING:
    from typing import List


class LookupError(Exception):
    pass


class Order(str, enum.Enum):
    normal = "normal"
    try_first = "try_first"
    try_last = "try_last"


def get_payload(data: Any, *args: Any, **kwargs: Any) -> "Payload":
    return PAYLOAD_REGISTRY.get(data, *args, **kwargs)


def register_payload(
    factory: Type["Payload"], type: Any, *, order: Order = Order.normal
) -> None:
    PAYLOAD_REGISTRY.register(factory, type, order=order)


class payload_type:
    def __init__(self, type: Any, *, order: Order = Order.normal) -> None:
        self.type = type
        self.order = order

    def __call__(self, factory: Type["Payload"]) -> Type["Payload"]:
        register_payload(factory, self.type, order=self.order)
        return factory


PayloadType = Type["Payload"]
_PayloadRegistryItem = Tuple[PayloadType, Any]


class PayloadRegistry:
    """Payload registry.

    note: we need zope.interface for more efficient adapter search
    """

    __slots__ = ("_first", "_normal", "_last", "_normal_lookup")

    def __init__(self) -> None:
        self._first: List[_PayloadRegistryItem] = []
        self._normal: List[_PayloadRegistryItem] = []
        self._last: List[_PayloadRegistryItem] = []
        self._normal_lookup: Dict[Any, PayloadType] = {}

    def get(
        self,
        data: Any,
        *args: Any,
        _CHAIN: "Type[chain[_PayloadRegistryItem]]" = chain,
        **kwargs: Any,
    ) -> "Payload":
        if self._first:
            for factory, type_ in self._first:
                if isinstance(data, type_):
                    return factory(data, *args, **kwargs)
        # Try the fast lookup first
        if lookup_factory := self._normal_lookup.get(type(data)):
            return lookup_factory(data, *args, **kwargs)
        # Bail early if its already a Payload
        if isinstance(data, Payload):
            return data
        # Fallback to the slower linear search
        for factory, type_ in _CHAIN(self._normal, self._last):
            if isinstance(data, type_):
                return factory(data, *args, **kwargs)
        raise LookupError()

    def register(
        self, factory: PayloadType, type: Any, *, order: Order = Order.normal
    ) -> None:
        if order is Order.try_first:
            self._first.append((factory, type))
        elif order is Order.normal:
            self._normal.append((factory, type))
            if isinstance(type, Iterable):
                for t in type:
                    self._normal_lookup[t] = factory
            else:
                self._normal_lookup[type] = factory
        elif order is Order.try_last:
            self._last.append((factory, type))
        else:
            raise ValueError(f"Unsupported order {order!r}")


class Payload(ABC):

    _default_content_type: str = "application/octet-stream"
    _size: Optional[int] = None

    def __init__(
        self,
        value: Any,
        headers: Optional[
            Union[_CIMultiDict, Dict[str, str], Iterable[Tuple[str, str]]]
        ] = None,
        content_type: Union[str, None, _SENTINEL] = sentinel,
        filename: Optional[str] = None,
        encoding: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        self._encoding = encoding
        self._filename = filename
        self._headers: _CIMultiDict = CIMultiDict()
        self._value = value
        if content_type is not sentinel and content_type is not None:
            self._headers[hdrs.CONTENT_TYPE] = content_type
        elif self._filename is not None:
            if sys.version_info >= (3, 13):
                guesser = mimetypes.guess_file_type
            else:
                guesser = mimetypes.guess_type
            content_type = guesser(self._filename)[0]
            if content_type is None:
                content_type = self._default_content_type
            self._headers[hdrs.CONTENT_TYPE] = content_type
        else:
            self._headers[hdrs.CONTENT_TYPE] = self._default_content_type
        if headers:
            self._headers.update(headers)

    @property
    def size(self) -> Optional[int]:
        """Size of the payload."""
        return self._size

    @property
    def filename(self) -> Optional[str]:
        """Filename of the payload."""
        return self._filename

    @property
    def headers(self) -> _CIMultiDict:
        """Custom item headers"""
        return self._headers

    @property
    def _binary_headers(self) -> bytes:
        return (
            "".join([k + ": " + v + "\r\n" for k, v in self.headers.items()]).encode(
                "utf-8"
            )
            + b"\r\n"
        )

    @property
    def encoding(self) -> Optional[str]:
        """Payload encoding"""
        return self._encoding

    @property
    def content_type(self) -> str:
        """Content type"""
        return self._headers[hdrs.CONTENT_TYPE]

    def set_content_disposition(
        self,
        disptype: str,
        quote_fields: bool = True,
        _charset: str = "utf-8",
        **params: Any,
    ) -> None:
        """Sets ``Content-Disposition`` header."""
        self._headers[hdrs.CONTENT_DISPOSITION] = content_disposition_header(
            disptype, quote_fields=quote_fields, _charset=_charset, **params
        )

    @abstractmethod
    def decode(self, encoding: str = "utf-8", errors: str = "strict") -> str:
        """Return string representation of the value.

        This is named decode() to allow compatibility with bytes objects.
        """

    @abstractmethod
    async def write(self, writer: AbstractStreamWriter) -> None:
        """Write payload to the writer stream.

        Args:
            writer: An AbstractStreamWriter instance that handles the actual writing

        This is a legacy method that writes the entire payload without length constraints.

        Important:
            For new implementations, use write_with_length() instead of this method.
            This method is maintained for backwards compatibility and will eventually
            delegate to write_with_length(writer, None) in all implementations.

        All payload subclasses must override this method for backwards compatibility,
        but new code should use write_with_length for more flexibility and control.
        """

    # write_with_length is new in aiohttp 3.12
    # it should be overridden by subclasses
    async def write_with_length(
        self, writer: AbstractStreamWriter, content_length: Optional[int]
    ) -> None:
        """
        Write payload with a specific content length constraint.

        Args:
            writer: An AbstractStreamWriter instance that handles the actual writing
            content_length: Maximum number of bytes to write (None for unlimited)

        This method allows writing payload content with a specific length constraint,
        which is particularly useful for HTTP responses with Content-Length header.

        Note:
            This is the base implementation that provides backwards compatibility
            for subclasses that don't override this method. Specific payload types
            should override this method to implement proper length-constrained writing.

        """
        # Backwards compatibility for subclasses that don't override this method
        # and for the default implementation
        await self.write(writer)


class BytesPayload(Payload):
    _value: bytes

    def __init__(
        self, value: Union[bytes, bytearray, memoryview], *args: Any, **kwargs: Any
    ) -> None:
        if "content_type" not in kwargs:
            kwargs["content_type"] = "application/octet-stream"

        super().__init__(value, *args, **kwargs)

        if isinstance(value, memoryview):
            self._size = value.nbytes
        elif isinstance(value, (bytes, bytearray)):
            self._size = len(value)
        else:
            raise TypeError(f"value argument must be byte-ish, not {type(value)!r}")

        if self._size > TOO_LARGE_BYTES_BODY:
            kwargs = {"source": self}
            warnings.warn(
                "Sending a large body directly with raw bytes might"
                " lock the event loop. You should probably pass an "
                "io.BytesIO object instead",
                ResourceWarning,
                **kwargs,
            )

    def decode(self, encoding: str = "utf-8", errors: str = "strict") -> str:
        return self._value.decode(encoding, errors)

    async def write(self, writer: AbstractStreamWriter) -> None:
        """Write the entire bytes payload to the writer stream.

        Args:
            writer: An AbstractStreamWriter instance that handles the actual writing

        This method writes the entire bytes content without any length constraint.

        Note:
            For new implementations that need length control, use write_with_length().
            This method is maintained for backwards compatibility and is equivalent
            to write_with_length(writer, None).
        """
        await writer.write(self._value)

    async def write_with_length(
        self, writer: AbstractStreamWriter, content_length: Optional[int]
    ) -> None:
        """
        Write bytes payload with a specific content length constraint.

        Args:
            writer: An AbstractStreamWriter instance that handles the actual writing
            content_length: Maximum number of bytes to write (None for unlimited)

        This method writes either the entire byte sequence or a slice of it
        up to the specified content_length. For BytesPayload, this operation
        is performed efficiently using array slicing.

        """
        if content_length is not None:
            await writer.write(self._value[:content_length])
        else:
            await writer.write(self._value)


class StringPayload(BytesPayload):
    def __init__(
        self,
        value: str,
        *args: Any,
        encoding: Optional[str] = None,
        content_type: Optional[str] = None,
        **kwargs: Any,
    ) -> None:

        if encoding is None:
            if content_type is None:
                real_encoding = "utf-8"
                content_type = "text/plain; charset=utf-8"
            else:
                mimetype = parse_mimetype(content_type)
                real_encoding = mimetype.parameters.get("charset", "utf-8")
        else:
            if content_type is None:
                content_type = "text/plain; charset=%s" % encoding
            real_encoding = encoding

        super().__init__(
            value.encode(real_encoding),
            encoding=real_encoding,
            content_type=content_type,
            *args,
            **kwargs,
        )


class StringIOPayload(StringPayload):
    def __init__(self, value: IO[str], *args: Any, **kwargs: Any) -> None:
        super().__init__(value.read(), *args, **kwargs)


class IOBasePayload(Payload):
    _value: io.IOBase

    def __init__(
        self, value: IO[Any], disposition: str = "attachment", *args: Any, **kwargs: Any
    ) -> None:
        if "filename" not in kwargs:
            kwargs["filename"] = guess_filename(value)

        super().__init__(value, *args, **kwargs)

        if self._filename is not None and disposition is not None:
            if hdrs.CONTENT_DISPOSITION not in self.headers:
                self.set_content_disposition(disposition, filename=self._filename)

    def _read_and_available_len(
        self, remaining_content_len: Optional[int]
    ) -> Tuple[Optional[int], bytes]:
        """
        Read the file-like object and return both its total size and the first chunk.

        Args:
            remaining_content_len: Optional limit on how many bytes to read in this operation.
                If None, READ_SIZE will be used as the default chunk size.

        Returns:
            A tuple containing:
            - The total size of the remaining unread content (None if size cannot be determined)
            - The first chunk of bytes read from the file object

        This method is optimized to perform both size calculation and initial read
        in a single operation, which is executed in a single executor job to minimize
        context switches and file operations when streaming content.

        """
        size = self.size  # Call size only once since it does I/O
        return size, self._value.read(
            min(size or READ_SIZE, remaining_content_len or READ_SIZE)
        )

    def _read(self, remaining_content_len: Optional[int]) -> bytes:
        """
        Read a chunk of data from the file-like object.

        Args:
            remaining_content_len: Optional maximum number of bytes to read.
                If None, READ_SIZE will be used as the default chunk size.

        Returns:
            A chunk of bytes read from the file object, respecting the
            remaining_content_len limit if specified.

        This method is used for subsequent reads during streaming after
        the initial _read_and_available_len call has been made.

        """
        return self._value.read(remaining_content_len or READ_SIZE)  # type: ignore[no-any-return]

    @property
    def size(self) -> Optional[int]:
        try:
            return os.fstat(self._value.fileno()).st_size - self._value.tell()
        except (AttributeError, OSError):
            return None

    async def write(self, writer: AbstractStreamWriter) -> None:
        """
        Write the entire file-like payload to the writer stream.

        Args:
            writer: An AbstractStreamWriter instance that handles the actual writing

        This method writes the entire file content without any length constraint.
        It delegates to write_with_length() with no length limit for implementation
        consistency.

        Note:
            For new implementations that need length control, use write_with_length() directly.
            This method is maintained for backwards compatibility with existing code.

        """
        await self.write_with_length(writer, None)

    async def write_with_length(
        self, writer: AbstractStreamWriter, content_length: Optional[int]
    ) -> None:
        """
        Write file-like payload with a specific content length constraint.

        Args:
            writer: An AbstractStreamWriter instance that handles the actual writing
            content_length: Maximum number of bytes to write (None for unlimited)

        This method implements optimized streaming of file content with length constraints:

        1. File reading is performed in a thread pool to avoid blocking the event loop
        2. Content is read and written in chunks to maintain memory efficiency
        3. Writing stops when either:
           - All available file content has been written (when size is known)
           - The specified content_length has been reached
        4. File resources are properly closed even if the operation is cancelled

        The implementation carefully handles both known-size and unknown-size payloads,
        as well as constrained and unconstrained content lengths.

        """
        loop = asyncio.get_running_loop()
        total_written_len = 0
        remaining_content_len = content_length

        try:
            # Get initial data and available length
            available_len, chunk = await loop.run_in_executor(
                None, self._read_and_available_len, remaining_content_len
            )
            # Process data chunks until done
            while chunk:
                chunk_len = len(chunk)

                # Write data with or without length constraint
                if remaining_content_len is None:
                    await writer.write(chunk)
                else:
                    await writer.write(chunk[:remaining_content_len])
                    remaining_content_len -= chunk_len

                total_written_len += chunk_len

                # Check if we're done writing
                if self._should_stop_writing(
                    available_len, total_written_len, remaining_content_len
                ):
                    return

                # Read next chunk
                chunk = await loop.run_in_executor(
                    None, self._read, remaining_content_len
                )
        finally:
            # Handle closing the file without awaiting to prevent cancellation issues
            # when the StreamReader reaches EOF
            self._schedule_file_close(loop)

    def _should_stop_writing(
        self,
        available_len: Optional[int],
        total_written_len: int,
        remaining_content_len: Optional[int],
    ) -> bool:
        """
        Determine if we should stop writing data.

        Args:
            available_len: Known size of the payload if available (None if unknown)
            total_written_len: Number of bytes already written
            remaining_content_len: Remaining bytes to be written for content-length limited responses

        Returns:
            True if we should stop writing data, based on either:
            - Having written all available data (when size is known)
            - Having written all requested content (when content-length is specified)

        """
        return (available_len is not None and total_written_len >= available_len) or (
            remaining_content_len is not None and remaining_content_len <= 0
        )

    def _schedule_file_close(self, loop: asyncio.AbstractEventLoop) -> None:
        """Schedule file closing without awaiting to prevent cancellation issues."""
        close_future = loop.run_in_executor(None, self._value.close)
        # Hold a strong reference to the future to prevent it from being
        # garbage collected before it completes.
        _CLOSE_FUTURES.add(close_future)
        close_future.add_done_callback(_CLOSE_FUTURES.remove)

    def decode(self, encoding: str = "utf-8", errors: str = "strict") -> str:
        return "".join(r.decode(encoding, errors) for r in self._value.readlines())


class TextIOPayload(IOBasePayload):
    _value: io.TextIOBase

    def __init__(
        self,
        value: TextIO,
        *args: Any,
        encoding: Optional[str] = None,
        content_type: Optional[str] = None,
        **kwargs: Any,
    ) -> None:

        if encoding is None:
            if content_type is None:
                encoding = "utf-8"
                content_type = "text/plain; charset=utf-8"
            else:
                mimetype = parse_mimetype(content_type)
                encoding = mimetype.parameters.get("charset", "utf-8")
        else:
            if content_type is None:
                content_type = "text/plain; charset=%s" % encoding

        super().__init__(
            value,
            content_type=content_type,
            encoding=encoding,
            *args,
            **kwargs,
        )

    def _read_and_available_len(
        self, remaining_content_len: Optional[int]
    ) -> Tuple[Optional[int], bytes]:
        """
        Read the text file-like object and return both its total size and the first chunk.

        Args:
            remaining_content_len: Optional limit on how many bytes to read in this operation.
                If None, READ_SIZE will be used as the default chunk size.

        Returns:
            A tuple containing:
            - The total size of the remaining unread content (None if size cannot be determined)
            - The first chunk of bytes read from the file object, encoded using the payload's encoding

        This method is optimized to perform both size calculation and initial read
        in a single operation, which is executed in a single executor job to minimize
        context switches and file operations when streaming content.

        Note:
            TextIOPayload handles encoding of the text content before writing it
            to the stream. If no encoding is specified, UTF-8 is used as the default.

        """
        size = self.size
        chunk = self._value.read(
            min(size or READ_SIZE, remaining_content_len or READ_SIZE)
        )
        return size, chunk.encode(self._encoding) if self._encoding else chunk.encode()

    def _read(self, remaining_content_len: Optional[int]) -> bytes:
        """
        Read a chunk of data from the text file-like object.

        Args:
            remaining_content_len: Optional maximum number of bytes to read.
                If None, READ_SIZE will be used as the default chunk size.

        Returns:
            A chunk of bytes read from the file object and encoded using the payload's
            encoding. The data is automatically converted from text to bytes.

        This method is used for subsequent reads during streaming after
        the initial _read_and_available_len call has been made. It properly
        handles text encoding, converting the text content to bytes using
        the specified encoding (or UTF-8 if none was provided).

        """
        chunk = self._value.read(remaining_content_len or READ_SIZE)
        return chunk.encode(self._encoding) if self._encoding else chunk.encode()

    def decode(self, encoding: str = "utf-8", errors: str = "strict") -> str:
        return self._value.read()


class BytesIOPayload(IOBasePayload):
    _value: io.BytesIO

    @property
    def size(self) -> int:
        position = self._value.tell()
        end = self._value.seek(0, os.SEEK_END)
        self._value.seek(position)
        return end - position

    def decode(self, encoding: str = "utf-8", errors: str = "strict") -> str:
        return self._value.read().decode(encoding, errors)

    async def write(self, writer: AbstractStreamWriter) -> None:
        return await self.write_with_length(writer, None)

    async def write_with_length(
        self, writer: AbstractStreamWriter, content_length: Optional[int]
    ) -> None:
        """
        Write BytesIO payload with a specific content length constraint.

        Args:
            writer: An AbstractStreamWriter instance that handles the actual writing
            content_length: Maximum number of bytes to write (None for unlimited)

        This implementation is specifically optimized for BytesIO objects:

        1. Reads content in chunks to maintain memory efficiency
        2. Yields control back to the event loop periodically to prevent blocking
           when dealing with large BytesIO objects
        3. Respects content_length constraints when specified
        4. Properly cleans up by closing the BytesIO object when done or on error

        The periodic yielding to the event loop is important for maintaining
        responsiveness when processing large in-memory buffers.

        """
        loop_count = 0
        remaining_bytes = content_length
        try:
            while chunk := self._value.read(READ_SIZE):
                if loop_count > 0:
                    # Avoid blocking the event loop
                    # if they pass a large BytesIO object
                    # and we are not in the first iteration
                    # of the loop
                    await asyncio.sleep(0)
                if remaining_bytes is None:
                    await writer.write(chunk)
                else:
                    await writer.write(chunk[:remaining_bytes])
                    remaining_bytes -= len(chunk)
                    if remaining_bytes <= 0:
                        return
                loop_count += 1
        finally:
            self._value.close()


class BufferedReaderPayload(IOBasePayload):
    _value: io.BufferedIOBase

    def decode(self, encoding: str = "utf-8", errors: str = "strict") -> str:
        return self._value.read().decode(encoding, errors)


class JsonPayload(BytesPayload):
    def __init__(
        self,
        value: Any,
        encoding: str = "utf-8",
        content_type: str = "application/json",
        dumps: JSONEncoder = json.dumps,
        *args: Any,
        **kwargs: Any,
    ) -> None:

        super().__init__(
            dumps(value).encode(encoding),
            content_type=content_type,
            encoding=encoding,
            *args,
            **kwargs,
        )


if TYPE_CHECKING:
    from typing import AsyncIterable, AsyncIterator

    _AsyncIterator = AsyncIterator[bytes]
    _AsyncIterable = AsyncIterable[bytes]
else:
    from collections.abc import AsyncIterable, AsyncIterator

    _AsyncIterator = AsyncIterator
    _AsyncIterable = AsyncIterable


class AsyncIterablePayload(Payload):

    _iter: Optional[_AsyncIterator] = None
    _value: _AsyncIterable

    def __init__(self, value: _AsyncIterable, *args: Any, **kwargs: Any) -> None:
        if not isinstance(value, AsyncIterable):
            raise TypeError(
                "value argument must support "
                "collections.abc.AsyncIterable interface, "
                "got {!r}".format(type(value))
            )

        if "content_type" not in kwargs:
            kwargs["content_type"] = "application/octet-stream"

        super().__init__(value, *args, **kwargs)

        self._iter = value.__aiter__()

    async def write(self, writer: AbstractStreamWriter) -> None:
        """
        Write the entire async iterable payload to the writer stream.

        Args:
            writer: An AbstractStreamWriter instance that handles the actual writing

        This method iterates through the async iterable and writes each chunk
        to the writer without any length constraint.

        Note:
            For new implementations that need length control, use write_with_length() directly.
            This method is maintained for backwards compatibility with existing code.

        """
        await self.write_with_length(writer, None)

    async def write_with_length(
        self, writer: AbstractStreamWriter, content_length: Optional[int]
    ) -> None:
        """
        Write async iterable payload with a specific content length constraint.

        Args:
            writer: An AbstractStreamWriter instance that handles the actual writing
            content_length: Maximum number of bytes to write (None for unlimited)

        This implementation handles streaming of async iterable content with length constraints:

        1. Iterates through the async iterable one chunk at a time
        2. Respects content_length constraints when specified
        3. Handles the case when the iterable might be used twice

        Since async iterables are consumed as they're iterated, there is no way to
        restart the iteration if it's already in progress or completed.

        """
        if self._iter is None:
            return

        remaining_bytes = content_length

        try:
            while True:
                if sys.version_info >= (3, 10):
                    chunk = await anext(self._iter)
                else:
                    chunk = await self._iter.__anext__()
                if remaining_bytes is None:
                    await writer.write(chunk)
                # If we have a content length limit
                elif remaining_bytes > 0:
                    await writer.write(chunk[:remaining_bytes])
                    remaining_bytes -= len(chunk)
                # We still want to exhaust the iterator even
                # if we have reached the content length limit
                # since the file handle may not get closed by
                # the iterator if we don't do this
        except StopAsyncIteration:
            # Iterator is exhausted
            self._iter = None

    def decode(self, encoding: str = "utf-8", errors: str = "strict") -> str:
        raise TypeError("Unable to decode.")


class StreamReaderPayload(AsyncIterablePayload):
    def __init__(self, value: StreamReader, *args: Any, **kwargs: Any) -> None:
        super().__init__(value.iter_any(), *args, **kwargs)


PAYLOAD_REGISTRY = PayloadRegistry()
PAYLOAD_REGISTRY.register(BytesPayload, (bytes, bytearray, memoryview))
PAYLOAD_REGISTRY.register(StringPayload, str)
PAYLOAD_REGISTRY.register(StringIOPayload, io.StringIO)
PAYLOAD_REGISTRY.register(TextIOPayload, io.TextIOBase)
PAYLOAD_REGISTRY.register(BytesIOPayload, io.BytesIO)
PAYLOAD_REGISTRY.register(BufferedReaderPayload, (io.BufferedReader, io.BufferedRandom))
PAYLOAD_REGISTRY.register(IOBasePayload, io.IOBase)
PAYLOAD_REGISTRY.register(StreamReaderPayload, StreamReader)
# try_last for giving a chance to more specialized async interables like
# multidict.BodyPartReaderPayload override the default
PAYLOAD_REGISTRY.register(AsyncIterablePayload, AsyncIterable, order=Order.try_last)
