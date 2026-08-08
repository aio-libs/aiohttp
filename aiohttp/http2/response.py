import json
from http.cookies import SimpleCookie
from typing import Any, Iterable, List, Optional, Tuple

from hpack import HeaderTuple
from multidict import CIMultiDict

from aiohttp.client_exceptions import ClientResponseError
from aiohttp.client_reqrep import RequestInfo

from ..compression_utils import ZLibDecompressor
from ..http_writer import HttpVersion2


class Http2Response:
    """A fully aiohttp.ClientResponse-compatible response for HTTP/2."""

    def __init__(
        self,
        headers: Iterable[HeaderTuple] | Iterable[Tuple[str, str]],
        body: bytes,
        *,
        method: Optional[str] = None,
        url: Optional[Any] = None,
    ) -> None:
        # Headers as case-insensitive multi-dict
        self.headers: CIMultiDict[str] = CIMultiDict(headers)  # type: ignore[arg-type]
        encoding = self.headers.get("content-encoding", None)
        if encoding in {"gzip", "deflate"}:
            comp = ZLibDecompressor(encoding=encoding)
            body = comp.decompress_sync(body)

        self.reason: str = ""  # HTTP/2 doesn't carry a reason phrase
        self._body: bytes = body
        self.url: Optional[Any] = url
        self.method: Optional[str] = method
        # redirects
        self._history: List["Http2Response"] = []

        # no status error implies a server side error
        self.status: int = int(self.headers.get(":status", 500))

        # Cookie jar integration
        self._cookies: Optional[SimpleCookie] = None

        # HTTP version pseudo-attribute
        self.version = HttpVersion2

        self._raw_cookie_headers: Optional[List[str]] = self.headers.getall(
            "set-cookie", []
        )
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

    async def text(self, encoding: str = "utf-8") -> str:
        """Decode the body to a string."""
        return self._body.decode(encoding)

    async def json(self, **kwargs: Any) -> Any:
        """Parse JSON body."""
        return json.loads(self._body, **kwargs)

    # ----------------------------------------------------------------
    # Cookies
    # ----------------------------------------------------------------
    @property
    def cookies(self) -> SimpleCookie:
        """Parse 'Set-Cookie' headers and return a SimpleCookie."""
        if self._cookies is None:
            self._cookies = SimpleCookie()
            for raw in self.headers.getall("set-cookie", []):
                self._cookies.load(raw)
        return self._cookies

    # ----------------------------------------------------------------
    # Status helpers
    # ----------------------------------------------------------------
    @property
    def ok(self) -> bool:
        """True if status is < 400."""
        return 200 <= self.status < 400

    def raise_for_status(self) -> None:
        """Raise an HTTPError for 4xx/5xx responses."""
        if not self.ok:
            raise ClientResponseError(
                request_info=RequestInfo(
                    url=self.url, method=self.method, headers=self.headers  # type: ignore[arg-type]
                ),
                history=self._history,  # type: ignore[arg-type]
                status=self.status,
                message=f"{self.status}, message='{self.reason}'",
                headers=self.headers,
            )

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
