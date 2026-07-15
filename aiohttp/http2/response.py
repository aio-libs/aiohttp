import json
from http.cookies import SimpleCookie
from typing import Any, Iterable, List, Optional, Tuple

from hpack import HeaderTuple
from multidict import CIMultiDict

from aiohttp.client_exceptions import ClientResponseError
from aiohttp.client_reqrep import RequestInfo

from ..compression_utils import ZLibDecompressor
from ..http_writer import HttpVersion2
from ..http_base import BaseResponse
from ..hdrs import CONTENT_ENCODING, SET_COOKIE


class Http2Response(BaseResponse):
    """A fully aiohttp.ClientResponse-compatible response for HTTP/2."""

    def __init__(
        self,
        headers: Iterable[HeaderTuple] | Iterable[Tuple[str, str]],
        body: bytes,
        method: str,
        url: Any = None,
    ) -> None:
        super().__init__()
        self.method = method
        self.url = url
        self._headers: CIMultiDict[str] = CIMultiDict(headers)

        self._raw_cookie_headers: Optional[List[str]] = self.headers.getall(
            SET_COOKIE, []
        )
        self._cookies = None

        encoding = self.headers.get(CONTENT_ENCODING, None)
        if encoding in {"gzip", "deflate"}:
            comp = ZLibDecompressor(encoding=encoding)
            body = comp.decompress_sync(body)

        self._body: bytes = body
        self._history: List[BaseRequest] = []

        # required fields
        self.reason: str = ""  # HTTP/2 doesn't carry a reason phrase
        # no status error implies a server side error
        self.status: int = int(self.headers.get(":status", 500))
        # HTTP version pseudo-attribute
        self.version = HttpVersion2

        self.connection: Optional[Any] = None

    # ----------------------------------------------------------------
    # Body access (synchronous: entire body is already in memory)
    # ----------------------------------------------------------------
    async def read(self) -> bytes:
        """Return the response body."""
        return self._body

    @property
    def body(self) -> bytes:
        return self._body

    @property 
    def request_info(self) -> RequestInfo:
        return RequestInfo(url=self.url, method=self.method, headers=self.headers)

    # ----------------------------------------------------------------
    # Connection release (stream-level cleanup)
    # ----------------------------------------------------------------
    def release(self) -> None:
        """Release the HTTP/2 stream back to the connection."""
        pass  # nothing to do; the stream has ended

    def close(self) -> None:
        if self.connection:
            self.connection.close()

    # ----------------------------------------------------------------
    # Context manager support
    # ----------------------------------------------------------------
    async def __aenter__(self) -> "Http2Response":
        return self

    async def __aexit__(
        self, exc_type: Optional[type], exc: Optional[BaseException], tb: Any
    ) -> None:
        pass
