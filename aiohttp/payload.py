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
    _encode: bool = False

    def __init__(
        self,
        value: Any,
        headers: Optional[
            Union[_CIMultiDict, Dict[str, str], Iterable[Tuple[str, str]]]
        ] = None,
        content_type: Union[None, str, _SENTINEL] = sentinel,
        filename: Optional[str] = None,
        encoding: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        self._encoding = encoding
        self._filename = filename
        self._headers: _CIMultiDict = CIMultiDict()
        self._value = value
        if content_type is not sentinel and content_type is not None:
            assert isinstance(content_type, str)
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
        **params: str,
    ) -> None:
        """Sets ``Content-Disposition`` header."""
        self._headers[hdrs.CONTENT_DISPOSITION] = content_disposition_header(
            disptype, quote_fields=quote_fields, _charset=_charset, params=params
        )

    @abstractmethod
    def decode(self, encoding: str = "utf-8", errors: str = "strict") -> str:
        """Return string representation of the value.

        This is named decode() to allow compatibility with bytes objects.
        """

    @abstractmethod
    async def write(self, writer: AbstractStreamWriter) -> None:
        """Write payload.

        writer is an AbstractStreamWriter instance:
        """

    # write_with_length is new in aiohttp 3.12
    # it should be overridden by subclasses
    async def write_with_length(
        self, writer: AbstractStreamWriter, content_length: Optional[int]
    ) -> None:
        """Write payload with a maximum length.

        writer is an AbstractStreamWriter instance:
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
            warnings.warn(
                "Sending a large body directly with raw bytes might"
                " lock the event loop. You should probably pass an "
                "io.BytesIO object instead",
                ResourceWarning,
                source=self,
            )

    def decode(self, encoding: str = "utf-8", errors: str = "strict") -> str:
        return self._value.decode(encoding, errors)

    async def write(self, writer: AbstractStreamWriter) -> None:
        await writer.write(self._value)

    async def write_with_length(
        self, writer: AbstractStreamWriter, content_length: Optional[int]
    ) -> None:
        """Write payload with a length."""
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
        self, maximum_read_len: Optional[int]
    ) -> Tuple[Optional[int], Union[str, bytes]]:
        """Read the file-like object and return its size."""
        size = self.size
        return size, self._value.read(
            min(size, maximum_read_len or READ_SIZE, READ_SIZE)
        )

    def _read(self, maximum_read_len: Optional[int]) -> Union[str, bytes]:
        """Read the file-like object."""
        return self._value.read(maximum_read_len or READ_SIZE)

    @property
    def size(self) -> Optional[int]:
        try:
            return os.fstat(self._value.fileno()).st_size - self._value.tell()
        except (AttributeError, OSError):
            return None

    async def write(self, writer: AbstractStreamWriter) -> None:
        await self.write_with_length(writer, None)

    def _ensure_bytes(self, chunk: Union[str, bytes]) -> bytes:
        """Ensure chunk is bytes."""
        return chunk.encode(self._encoding) if self._encoding else chunk.encode()

    async def write_with_length(
        self, writer: AbstractStreamWriter, content_length: Optional[int]
    ) -> None:
        """Write payload with a length.

        writer is an AbstractStreamWriter instance:
        """
        loop = asyncio.get_running_loop()
        chunk: Union[bytes, str]
        bytes_data: bytes
        total_written_len = 0
        remaining_content_length = content_length
        import pprint

        pprint.pprint(["write_with_length", content_length])
        # Check if the file-like object is seekable
        try:
            available_len, chunk = await loop.run_in_executor(
                None, self._read_and_available_len, remaining_content_length
            )
            pprint.pprint(["finished reading in executor"])
            bytes_data = self._ensure_bytes(chunk) if self._encode else chunk
            while bytes_data:
                bytes_data_len = len(bytes_data)
                pprint.pprint(["write to writer", bytes_data_len])
                if remaining_content_length is None:
                    await writer.write(bytes_data)
                else:
                    await writer.write(bytes_data[:remaining_content_length])
                    remaining_content_length -= bytes_data_len
                pprint.pprint(["done writing to writer"])
                total_written_len += bytes_data_len
                if available_len is not None and total_written_len >= available_len:
                    break
                if remaining_content_length is None or remaining_content_length <= 0:
                    break
                import pprint

                pprint.pprint(["read in executor", remaining_content_length])
                chunk = await loop.run_in_executor(
                    None, self._read, remaining_content_length
                )
                bytes_data = self._ensure_bytes(chunk) if self._encode else chunk
        finally:
            # We do not await here because we may get cancelled if we do
            # no finish fast enough since as soon as the StreamReader reaches EOF
            # the client will proceed to cancel the writer as we need to make sure
            # the task is done before we can move on to handling the next request
            # as we don't want to leak writers.
            close_future = loop.run_in_executor(None, self._value.close)
            # Hold a strong reference to the future to prevent it from being
            # garbage collected before it completes.
            _CLOSE_FUTURES.add(close_future)
            close_future.add_done_callback(_CLOSE_FUTURES.remove)
        import pprint

        pprint.pprint(["payload finished"])

    def decode(self, encoding: str = "utf-8", errors: str = "strict") -> str:
        return "".join(r.decode(encoding, errors) for r in self._value.readlines())


class TextIOPayload(IOBasePayload):
    _value: io.TextIOBase
    _encode = True

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
        if content_length:
            await self.write(writer)
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
        if self._iter:
            try:
                # iter is not None check prevents rare cases
                # when the case iterable is used twice
                while True:
                    chunk = await self._iter.__anext__()
                    await writer.write(chunk)
            except StopAsyncIteration:
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
