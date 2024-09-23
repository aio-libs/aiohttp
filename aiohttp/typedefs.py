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
    Sequence,
    Tuple,
    Union,
)

from multidict import CIMultiDict, CIMultiDictProxy, MultiDict, MultiDictProxy, istr
from yarl import URL

try:
    # Available in yarl>=1.10.0
    from yarl import Query as _Query
except ImportError:  # pragma: no cover
    SimpleQuery = Union[str, int, float]  # pragma: no cover
    QueryVariable = Union[SimpleQuery, "Sequence[SimpleQuery]"]  # pragma: no cover
    _Query = Union[  # type: ignore[misc]  # pragma: no cover
        None, str, "Mapping[str, QueryVariable]", "Sequence[Tuple[str, QueryVariable]]"
    ]

Query = _Query

DEFAULT_JSON_ENCODER = json.dumps
DEFAULT_JSON_DECODER = json.loads

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
