import json
from http.cookies import SimpleCookie
from typing import Any, List, Optional, Tuple

from multidict import CIMultiDict

from ..http_writer import HttpVersion2


class Http2Response:
    """A fully aiohttp.ClientResponse-compatible response for HTTP/2."""

    def __init__(
        self,
        headers: List[Tuple[str, str]],
        body: bytes,
        *,
        method: Optional[str] = None,
        url: Optional[Any] = None,
    ) -> None:
        self.reason = ""  # HTTP/2 doesn't carry a reason phrase
        self._body = body
        self.url = url
        self.method = method
        self.history: List[Any] = []  # for redirects

        # Headers as case-insensitive multi-dict (mimics aiohttp's CIMultiDict)
        self.headers: CIMultiDict = CIMultiDict(headers)
        # no status error implies a server side error
        self.status = int(self.headers.get(":status", 500))

        # Cookie jar integration
        self._cookies: Optional[SimpleCookie] = None

        # HTTP version pseudo-attribute (aiohttp expects a namedtuple-like object)
        self.version = HttpVersion2

        self._raw_cookie_headers = None
        self.connection = None

    # ----------------------------------------------------------------
    # Body access (synchronous: entire body is already in memory)
    # ----------------------------------------------------------------
    async def read(self) -> bytes:
        """Return the response body."""
        return self._body

    @property
    def body(self):
        return self._body

    async def text(self, encoding: str = "utf-8") -> str:
        """Decode the body to a string."""
        return self._body.decode(encoding)

    async def json(self, **kwargs) -> Any:
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
            # self.headers is a CIMultiDict – use getall() to obtain all values
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
            from aiohttp.client_exceptions import ClientResponseError

            raise ClientResponseError(
                request_info=None,  # simplified
                history=self.history,
                status=self.status,
                message=f"{self.status}, message='{self.reason}'",
                headers=self.headers,
            )

    # ----------------------------------------------------------------
    # Connection release (stream-level cleanup)
    # ----------------------------------------------------------------
    def release(self) -> None:
        """Release the HTTP/2 stream back to the connection.

        In HTTP/2 the stream is already closed once the full response is
        received. This method is a no-op but required for aiohttp
        compatibility.
        """
        pass  # nothing to do; the stream has ended

    def close(self):
        if self.connection:
            self.connection.close()

    # ----------------------------------------------------------------
    # Context manager support (optional, often used with 'async with')
    # ----------------------------------------------------------------
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        pass
