import json
import os
from collections.abc import Awaitable, Callable, Iterable, Mapping
from http.cookies import BaseCookie, Morsel
from typing import TYPE_CHECKING, Any, Protocol

from multidict import CIMultiDict, CIMultiDictProxy, MultiDict, MultiDictProxy, istr
from yarl import URL

DEFAULT_JSON_ENCODER = json.dumps
DEFAULT_JSON_DECODER = json.loads

if TYPE_CHECKING:
    from .web import Request, StreamResponse

Byteish = bytes | bytearray | memoryview
JSONEncoder = Callable[[Any], str]
JSONDecoder = Callable[[str], Any]
LooseHeaders = (
    Mapping[str, str]
    | Mapping[istr, str]
    | CIMultiDict[str]
    | CIMultiDictProxy[str]
    | Iterable[tuple[str | istr, str]]
)
RawHeaders = tuple[tuple[bytes, bytes], ...]
StrOrURL = str | URL

LooseCookiesMappings = Mapping[str, str | BaseCookie[str] | Morsel[Any]]
LooseCookiesIterables = Iterable[tuple[str, str | BaseCookie[str] | Morsel[Any]]]
LooseCookies = LooseCookiesMappings | LooseCookiesIterables | BaseCookie[str]

Handler = Callable[["Request"], Awaitable["StreamResponse"]]


class Middleware(Protocol):
    def __call__(
        self, request: "Request", handler: Handler
    ) -> Awaitable["StreamResponse"]: ...


PathLike = str | os.PathLike[str]
