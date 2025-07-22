import asyncio
import io
import os
import pathlib
import sys
from abc import ABC, abstractmethod
from contextlib import suppress
from dataclasses import dataclass
from mimetypes import MimeTypes
from stat import S_ISREG
from types import MappingProxyType
from typing import (
    TYPE_CHECKING,
    Awaitable,
    BinaryIO,
    Callable,
    Final,
    Optional,
    Set,
    Tuple,
)

from . import hdrs
from .abc import AbstractStreamWriter
from .helpers import ETAG_ANY, ETag, must_be_empty_body
from .typedefs import LooseHeaders, PathLike
from .web_exceptions import (
    HTTPForbidden,
    HTTPNotFound,
    HTTPNotModified,
    HTTPPartialContent,
    HTTPPreconditionFailed,
    HTTPRequestRangeNotSatisfiable,
)
from .web_response import StreamResponse

__all__ = ("FileResponse",)

if TYPE_CHECKING:
    from .web_request import BaseRequest


_T_OnChunkSent = Optional[Callable[[bytes], Awaitable[None]]]


NOSENDFILE: Final[bool] = bool(os.environ.get("AIOHTTP_NOSENDFILE"))

CONTENT_TYPES: Final[MimeTypes] = MimeTypes()

# File extension to IANA encodings map that will be checked in the order defined.
ENCODING_EXTENSIONS = MappingProxyType(
    {ext: CONTENT_TYPES.encodings_map[ext] for ext in (".br", ".gz")}
)

FALLBACK_CONTENT_TYPE = "application/octet-stream"

# Provide additional MIME type/extension pairs to be recognized.
# https://en.wikipedia.org/wiki/List_of_archive_formats#Compression_only
ADDITIONAL_CONTENT_TYPES = MappingProxyType(
    {
        "application/gzip": ".gz",
        "application/x-brotli": ".br",
        "application/x-bzip2": ".bz2",
        "application/x-compress": ".Z",
        "application/x-xz": ".xz",
    }
)


# Add custom pairs and clear the encodings map so guess_type ignores them.
CONTENT_TYPES.encodings_map.clear()
for content_type, extension in ADDITIONAL_CONTENT_TYPES.items():
    CONTENT_TYPES.add_type(content_type, extension)


_CLOSE_FUTURES: Set[asyncio.Future[None]] = set()


@dataclass
class _ResponseOpenFile:
    fobj: BinaryIO
    size: int
    guessed_content_type: str
    etag: Optional[str]
    last_modified: Optional[float]
    encoding: Optional[str]


class BaseIOResponse(StreamResponse, ABC):
    _chunk_size: int

    def __init__(
        self,
        chunk_size: int = 256 * 1024,
        status: int = 200,
        reason: Optional[str] = None,
        headers: Optional[LooseHeaders] = None,
    ) -> None:
        super().__init__(status=status, reason=reason, headers=headers)
        self._chunk_size = chunk_size

    @abstractmethod
    async def open(self, accept_encoding: str) -> _ResponseOpenFile: ...

    @abstractmethod
    async def close(self, open_file: _ResponseOpenFile) -> None: ...

    def _seek_and_read(self, fobj: BinaryIO, offset: int, chunk_size: int) -> bytes:
        fobj.seek(offset)
        return fobj.read(chunk_size)  # type: ignore[no-any-return]

    async def _sendfile_fallback(
        self, writer: AbstractStreamWriter, fobj: BinaryIO, offset: int, count: int
    ) -> AbstractStreamWriter:
        # To keep memory usage low,fobj is transferred in chunks
        # controlled by the constructor's chunk_size argument.

        chunk_size = self._chunk_size
        loop = asyncio.get_event_loop()
        chunk = await loop.run_in_executor(
            None, self._seek_and_read, fobj, offset, chunk_size
        )
        while chunk:
            await writer.write(chunk)
            count = count - chunk_size
            if count <= 0:
                break
            chunk = await loop.run_in_executor(None, fobj.read, min(chunk_size, count))

        await writer.drain()
        return writer

    async def _sendfile(
        self, request: "BaseRequest", fobj: BinaryIO, offset: int, count: int
    ) -> AbstractStreamWriter:
        writer = await super().prepare(request)
        assert writer is not None

        if NOSENDFILE or self.compression:
            return await self._sendfile_fallback(writer, fobj, offset, count)

        loop = request._loop
        transport = request.transport
        assert transport is not None

        try:
            await loop.sendfile(transport, fobj, offset, count)
        except NotImplementedError:
            return await self._sendfile_fallback(writer, fobj, offset, count)

        await super().write_eof()
        return writer

    @staticmethod
    def _etag_match(etag_value: str, etags: Tuple[ETag, ...], *, weak: bool) -> bool:
        if len(etags) == 1 and etags[0].value == ETAG_ANY:
            return True
        return any(
            etag.value == etag_value for etag in etags if weak or not etag.is_weak
        )

    async def _not_modified(
        self,
        request: "BaseRequest",
        etag: Optional[str],
        last_modified: Optional[float],
    ) -> Optional[AbstractStreamWriter]:
        self.set_status(HTTPNotModified.status_code)
        self._length_check = False
        if etag is not None:
            self.etag = etag
        if last_modified is not None:
            self.last_modified = last_modified
        # Delete any Content-Length headers provided by user. HTTP 304
        # should always have empty response body
        return await super().prepare(request)

    async def _precondition_failed(
        self, request: "BaseRequest"
    ) -> Optional[AbstractStreamWriter]:
        self.set_status(HTTPPreconditionFailed.status_code)
        self.content_length = 0
        return await super().prepare(request)

    async def prepare(self, request: "BaseRequest") -> Optional[AbstractStreamWriter]:
        # Encoding comparisons should be case-insensitive
        # https://www.rfc-editor.org/rfc/rfc9110#section-8.4.1
        accept_encoding = request.headers.get(hdrs.ACCEPT_ENCODING, "").lower()

        open_file = None
        try:
            open_file = await self.open(accept_encoding)

            if hdrs.CONTENT_TYPE not in self.headers:
                self.headers[hdrs.CONTENT_TYPE] = open_file.guessed_content_type

            # https://www.rfc-editor.org/rfc/rfc9110#section-13.1.1-2
            if (ifmatch := request.if_match) is not None and (
                open_file.etag is None
                or not self._etag_match(open_file.etag, ifmatch, weak=False)
            ):
                return await self._precondition_failed(request)

            if (
                (unmodsince := request.if_unmodified_since) is not None
                and request.if_match is None
                and (
                    open_file.last_modified is None
                    or open_file.last_modified > unmodsince.timestamp()
                )
            ):
                return await self._precondition_failed(request)

            # https://www.rfc-editor.org/rfc/rfc9110#section-13.1.2-2
            if (
                open_file.etag is not None
                and (ifnonematch := request.if_none_match) is not None
                and self._etag_match(open_file.etag, ifnonematch, weak=True)
            ):
                return await self._not_modified(
                    request, open_file.etag, open_file.last_modified
                )

            if (
                open_file.last_modified is not None
                and (modsince := request.if_modified_since) is not None
                and open_file.last_modified <= modsince.timestamp()
            ):
                return await self._not_modified(
                    request, open_file.etag, open_file.last_modified
                )

            return await self._prepare_open_file(request, open_file)

        except PermissionError:
            self.set_status(HTTPForbidden.status_code)
            return await super().prepare(request)
        except OSError:
            # Most likely to be FileNotFoundError or OSError for circular
            # symlinks in python >= 3.13, so respond with 404.
            self.set_status(HTTPNotFound.status_code)
            return await super().prepare(request)
        finally:
            # We do not await here because we do not want to wait
            # for the executor to finish before returning the response
            # so the connection can begin servicing another request
            # as soon as possible.
            if open_file is not None:
                close_future = asyncio.ensure_future(self.close(open_file))
                # Hold a strong reference to the future to prevent it from being
                # garbage collected before it completes.
                _CLOSE_FUTURES.add(close_future)
                close_future.add_done_callback(_CLOSE_FUTURES.remove)

    async def _prepare_open_file(
        self,
        request: "BaseRequest",
        open_file: _ResponseOpenFile,
    ) -> Optional[AbstractStreamWriter]:
        status = self._status
        count: int = open_file.size
        start: Optional[int] = None

        if (
            (ifrange := request.if_range) is None
            or open_file.last_modified is None
            or open_file.last_modified <= ifrange.timestamp()
        ):
            # If-Range header check:
            # condition = cached date >= last modification date
            # return 206 if True else 200.
            # if False:
            #   Range header would not be processed, return 200
            # if True but Range header missing
            #   return 200
            try:
                rng = request.http_range
                start = rng.start
                end: Optional[int] = rng.stop
            except ValueError:
                # https://tools.ietf.org/html/rfc7233:
                # A server generating a 416 (Range Not Satisfiable) response to
                # a byte-range request SHOULD send a Content-Range header field
                # with an unsatisfied-range value.
                # The complete-length in a 416 response indicates the current
                # length of the selected representation.
                #
                # Will do the same below. Many servers ignore this and do not
                # send a Content-Range header with HTTP 416
                self._headers[hdrs.CONTENT_RANGE] = f"bytes */{open_file.size}"
                self.set_status(HTTPRequestRangeNotSatisfiable.status_code)
                return await super().prepare(request)

            # If a range request has been made, convert start, end slice
            # notation into file pointer offset and count
            if start is not None:
                if start < 0 and end is None:  # return tail of file
                    start += open_file.size
                    if start < 0:
                        # if Range:bytes=-1000 in request header but file size
                        # is only 200, there would be trouble without this
                        start = 0
                    count = open_file.size - start
                else:
                    # rfc7233:If the last-byte-pos value is
                    # absent, or if the value is greater than or equal to
                    # the current length of the representation data,
                    # the byte range is interpreted as the remainder
                    # of the representation (i.e., the server replaces the
                    # value of last-byte-pos with a value that is one less than
                    # the current length of the selected representation).
                    count = (
                        min(end if end is not None else open_file.size, open_file.size)
                        - start
                    )

                if start >= open_file.size:
                    # HTTP 416 should be returned in this case.
                    #
                    # According to https://tools.ietf.org/html/rfc7233:
                    # If a valid byte-range-set includes at least one
                    # byte-range-spec with a first-byte-pos that is less than
                    # the current length of the representation, or at least one
                    # suffix-byte-range-spec with a non-zero suffix-length,
                    # then the byte-range-set is satisfiable. Otherwise, the
                    # byte-range-set is unsatisfiable.
                    self._headers[hdrs.CONTENT_RANGE] = f"bytes */{open_file.size}"
                    self.set_status(HTTPRequestRangeNotSatisfiable.status_code)
                    return await super().prepare(request)

                status = HTTPPartialContent.status_code
                # Even though you are sending the whole file, you should still
                # return a HTTP 206 for a Range request.
                self.set_status(status)

        if open_file.encoding:
            self._headers[hdrs.CONTENT_ENCODING] = open_file.encoding
            self._headers[hdrs.VARY] = hdrs.ACCEPT_ENCODING
            # Disable compression if we are already sending
            # a compressed file since we don't want to double
            # compress.
            self._compression = False

        if open_file.etag is not None:
            self.etag = open_file.etag
        if open_file.last_modified is not None:
            self.last_modified = open_file.last_modified
        self.content_length = count

        self._headers[hdrs.ACCEPT_RANGES] = "bytes"

        if status == HTTPPartialContent.status_code:
            real_start = start
            assert real_start is not None
            self._headers[hdrs.CONTENT_RANGE] = "bytes {}-{}/{}".format(
                real_start, real_start + count - 1, open_file.size
            )

        # If we are sending 0 bytes calling sendfile() will throw a ValueError
        if count == 0 or must_be_empty_body(request.method, status):
            return await super().prepare(request)

        # be aware that start could be None or int=0 here.
        offset = start or 0

        return await self._sendfile(request, open_file.fobj, offset, count)


class FileResponse(BaseIOResponse):
    """A response object can be used to send files."""

    _path: pathlib.Path

    def __init__(
        self,
        path: PathLike,
        chunk_size: int = 256 * 1024,
        status: int = 200,
        reason: Optional[str] = None,
        headers: Optional[LooseHeaders] = None,
    ) -> None:
        self._path = pathlib.Path(path)
        super().__init__(status=status, reason=reason, headers=headers)

    def _get_file_path_stat_encoding(
        self, accept_encoding: str
    ) -> Tuple[Optional[pathlib.Path], os.stat_result, Optional[str]]:
        file_path = self._path
        for file_extension, file_encoding in ENCODING_EXTENSIONS.items():
            if file_encoding not in accept_encoding:
                continue

            compressed_path = file_path.with_suffix(file_path.suffix + file_extension)
            with suppress(OSError):
                # Do not follow symlinks and ignore any non-regular files.
                st = compressed_path.lstat()
                if S_ISREG(st.st_mode):
                    return compressed_path, st, file_encoding

        # Fallback to the uncompressed file
        st = file_path.stat()
        return file_path if S_ISREG(st.st_mode) else None, st, None

    async def open(self, accept_encoding: str) -> _ResponseOpenFile:
        def _open():
            # Guess a fallback content type, used if no Content-Type header is provided
            if sys.version_info >= (3, 13):
                guesser = CONTENT_TYPES.guess_file_type
            else:
                guesser = CONTENT_TYPES.guess_type
            content_type = guesser(self._path)[0] or FALLBACK_CONTENT_TYPE

            file_path, st, encoding = self._get_file_path_stat_encoding(accept_encoding)

            if file_path is None:
                # Forbid special files like sockets, pipes, devices, etc.
                raise PermissionError()

            return _ResponseOpenFile(
                fobj=file_path.open("rb"),
                size=st.st_size,
                guessed_content_type=content_type,
                etag=f"{st.st_mtime_ns:x}-{st.st_size:x}",
                last_modified=st.st_mtime,
                encoding=encoding,
            )

        return await asyncio.get_running_loop().run_in_executor(None, _open)

    async def close(self, open_file: _ResponseOpenFile) -> None:
        return await asyncio.get_running_loop().run_in_executor(
            None, open_file.fobj.close
        )


class IOResponse(BaseIOResponse):
    """A response object using any binary IO object"""

    _fobj: BinaryIO
    _etag: Optional[str]
    _last_modified: Optional[float]
    _content_type: str
    _close: bool

    def __init__(
        self,
        fobj: BinaryIO,
        etag: Optional[str] = None,
        last_modified: Optional[float] = None,
        content_type: str = FALLBACK_CONTENT_TYPE,
        close: bool = True,
        chunk_size: int = 256 * 1024,
        status: int = 200,
        reason: Optional[str] = None,
        headers: Optional[LooseHeaders] = None,
    ) -> None:
        self._fobj = fobj
        self._etag = etag
        self._last_modified = last_modified
        self._content_type = content_type
        self._close = close
        super().__init__(status=status, reason=reason, headers=headers)

    async def open(self, accept_encoding: str) -> _ResponseOpenFile:
        def get_size():
            self._fobj.seek(0, io.SEEK_END)
            size = self._fobj.tell()
            self._fobj.seek(0)
            return size

        size = await asyncio.get_running_loop().run_in_executor(None, get_size)
        return _ResponseOpenFile(
            self._fobj, size, self._content_type, self._etag, self._last_modified, None
        )

    async def close(self, open_file: _ResponseOpenFile) -> None:
        if self._close:
            await asyncio.get_running_loop().run_in_executor(None, open_file.fobj.close)
