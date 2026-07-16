import codecs
import contextlib
from http.cookies import SimpleCookie
from typing import Any, Callable, Optional, Tuple

from aiohttp._cookie_helpers import parse_set_cookie_headers
from aiohttp.client_exceptions import ClientResponseError, ContentTypeError
from aiohttp.hdrs import CONTENT_TYPE
from aiohttp.helpers import HeadersMixin, is_expected_content_type, parse_mimetype
from aiohttp.typedefs import DEFAULT_JSON_DECODER


class BaseResponse(HeadersMixin):
    """Shared public API for HTTP responses."""

    __slots__ = (
        "_body",
        "_cookies",
        "_headers",
        "_history",
        "_in_context",
        "_released",
        "_resolve_charset",
        "method",
        "url",
        "status",
        "reason",
        "_raw_cookie_headers",
    )

    status: int
    _body: Optional[bytes]
    _cookies: Optional[SimpleCookie]
    _headers: Any
    _history: Tuple[Any, ...]
    reason: Optional[str]
    _raw_cookie_headers: Optional[Tuple[str, ...]]

    def __init__(self) -> None:
        self._in_context = False
        self._released: bool = False
        self._resolve_charset: Callable[[Any, bytes], str] = lambda *_: "utf-8"

    # ----------------------------------------------------------------
    # Abstract / overridable protocol methods
    # ----------------------------------------------------------------
    async def read(self) -> bytes:
        """Read the entire response body."""
        raise NotImplementedError

    def release(self) -> None:
        """Release the underlying connection / stream."""
        raise NotImplementedError

    def close(self) -> None:
        """Close the connection immediately."""
        raise NotImplementedError

    async def wait_for_close(self) -> None:
        """Wait for the connection to be fully released."""
        self.release()
        raise NotImplementedError

    @property
    def headers(self) -> Any:
        return self._headers

    @property
    def history(self) -> Tuple[Any, ...]:
        return self._history

    # ----------------------------------------------------------------
    # request_info – used by raise_for_status
    # ----------------------------------------------------------------
    @property
    def request_info(self) -> Any:
        """Return a RequestInfo object for error reporting."""
        raise NotImplementedError

    # ----------------------------------------------------------------
    # Public status checks
    # ----------------------------------------------------------------
    @property
    def ok(self) -> bool:
        """True if status code is less than 400."""
        return self.status < 400

    def raise_for_status(self) -> None:
        """Raise ClientResponseError for 4xx/5xx responses."""
        if not self.ok:
            # If we're inside a context manager we defer release until __aexit__.
            if not self._in_context:
                self.release()
            # can be ""
            assert self.reason is not None
            raise ClientResponseError(
                self.request_info,
                self.history,
                status=self.status,
                message=self.reason,
                headers=self._headers,
            )

    # ----------------------------------------------------------------
    # Cookies
    # ----------------------------------------------------------------
    @property
    def cookies(self) -> SimpleCookie:
        """Parse Set-Cookie headers into a SimpleCookie."""
        if self._cookies is None:
            if self._raw_cookie_headers is not None:
                cookies = SimpleCookie()
                cookies.update(parse_set_cookie_headers(self._raw_cookie_headers))
                self._cookies = cookies
            else:
                self._cookies = SimpleCookie()
        return self._cookies

    @cookies.setter
    def cookies(self, cookies: SimpleCookie) -> None:
        """Allow overwriting the cookie jar (used by some session code)."""
        self._cookies = cookies

        # Generate raw cookie headers from the SimpleCookie
        if cookies:
            self._raw_cookie_headers = tuple(
                morsel.OutputString() for morsel in cookies.values()
            )
        else:
            self._raw_cookie_headers = None

    # ----------------------------------------------------------------
    # Body decoding
    # ----------------------------------------------------------------
    def get_encoding(self) -> str:
        """Determine the text encoding of the response body."""
        ctype = self._headers.get(CONTENT_TYPE, "").lower()
        mimetype = parse_mimetype(ctype)

        encoding = mimetype.parameters.get("charset")
        if encoding:
            with contextlib.suppress(LookupError, ValueError):
                return codecs.lookup(encoding).name

        # RFC 7159: default JSON encoding is UTF-8
        if mimetype.type == "application" and mimetype.subtype in ("json", "rdap"):
            return "utf-8"

        if self._body is None:
            raise RuntimeError(
                "Cannot compute fallback encoding of a not yet read body"
            )

        # Delegate to session‑level charset resolver
        return self._resolve_charset(self, self._body)

    async def text(self, encoding: Optional[str] = None, errors: str = "strict") -> str:
        """Read the body and decode to a string."""
        await self.read()
        if encoding is None:
            encoding = self.get_encoding()
        assert self._body is not None, "No body to decode"
        return self._body.decode(encoding, errors=errors)

    async def json(
        self,
        *,
        encoding: Optional[str] = None,
        loads: Any = DEFAULT_JSON_DECODER,
        content_type: Optional[str] = "application/json",
    ) -> Any:
        """Read the body and parse as JSON."""
        await self.read()

        if content_type and not is_expected_content_type(
            self.content_type, content_type
        ):
            raise ContentTypeError(
                self.request_info,
                self.history,
                status=self.status,
                message=(
                    "Attempt to decode JSON with "
                    f"unexpected mimetype: {self.content_type}"
                ),
                headers=self._headers,
            )

        if encoding is None:
            encoding = self.get_encoding()
        assert self._body is not None, "No body to decode"
        return loads(self._body.decode(encoding))

    # ----------------------------------------------------------------
    # Context manager
    # ----------------------------------------------------------------
    async def __aenter__(self) -> "BaseResponse":
        self._in_context = True
        return self

    async def __aexit__(
        self,
        exc_type: Optional[type],
        exc_val: Optional[BaseException],
        exc_tb: Any,
    ) -> None:
        self._in_context = False
        self.release()
        await self.wait_for_close()
