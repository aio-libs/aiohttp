import json
import os
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    Iterable,
    Mapping,
    Protocol,
    Tuple,
    Union,
)

from multidict import CIMultiDict, CIMultiDictProxy, MultiDict, MultiDictProxy, istr
from yarl import URL, Query as _Query

Query = _Query

# Try to use orjson for better performance, fallback to standard json
try:
    import orjson

    def _orjson_dumps(obj: Any) -> str:
        """orjson encoder that returns str (like json.dumps)."""
        return orjson.dumps(obj).decode("utf-8")

    def _orjson_dumps_bytes(obj: Any) -> bytes:
        """orjson encoder that returns bytes directly (fast path)."""
        return orjson.dumps(obj)

    def _orjson_loads(s: str) -> Any:
        """orjson decoder that accepts str (like json.loads)."""
        return orjson.loads(s)

    DEFAULT_JSON_ENCODER = _orjson_dumps
    DEFAULT_JSON_DECODER = _orjson_loads
    DEFAULT_JSON_BYTES_ENCODER = _orjson_dumps_bytes
except ImportError:
    DEFAULT_JSON_ENCODER = json.dumps
    DEFAULT_JSON_DECODER = json.loads

    def _json_dumps_bytes_fallback(obj: Any) -> bytes:
        return json.dumps(obj).encode("utf-8")

    DEFAULT_JSON_BYTES_ENCODER = _json_dumps_bytes_fallback

if TYPE_CHECKING:
    _CIMultiDict = CIMultiDict[str]
    _CIMultiDictProxy = CIMultiDictProxy[str]
    _MultiDict = MultiDict[str]
    _MultiDictProxy = MultiDictProxy[str]
    from http.cookies import BaseCookie, Morsel

    from .web import Request, StreamResponse
else:
    _CIMultiDict = CIMultiDict
    _CIMultiDictProxy = CIMultiDictProxy
    _MultiDict = MultiDict
    _MultiDictProxy = MultiDictProxy

Byteish = Union[bytes, bytearray, memoryview]
JSONEncoder = Callable[[Any], str]
JSONDecoder = Callable[[str], Any]
JSONBytesEncoder = Callable[[Any], bytes]
LooseHeaders = Union[
    Mapping[str, str],
    Mapping[istr, str],
    _CIMultiDict,
    _CIMultiDictProxy,
    Iterable[Tuple[Union[str, istr], str]],
]
RawHeaders = Tuple[Tuple[bytes, bytes], ...]
StrOrURL = Union[str, URL]

LooseCookiesMappings = Mapping[str, Union[str, "BaseCookie[str]", "Morsel[Any]"]]
LooseCookiesIterables = Iterable[
    Tuple[str, Union[str, "BaseCookie[str]", "Morsel[Any]"]]
]
LooseCookies = Union[
    LooseCookiesMappings,
    LooseCookiesIterables,
    "BaseCookie[str]",
]

Handler = Callable[["Request"], Awaitable["StreamResponse"]]


class Middleware(Protocol):
    def __call__(
        self, request: "Request", handler: Handler
    ) -> Awaitable["StreamResponse"]: ...


PathLike = Union[str, "os.PathLike[str]"]
