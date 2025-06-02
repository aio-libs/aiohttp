import json
import os
import sys
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
    TypeVar
)

from multidict import CIMultiDict, CIMultiDictProxy, MultiDict, MultiDictProxy, istr
from yarl import URL, Query as _Query

Query = _Query

DEFAULT_JSON_ENCODER = json.dumps
DEFAULT_JSON_DECODER = json.loads

# TODO: Import ParamSpec & Concatenate  Directly when Python 3.9 support is Dropped.
if sys.version_info >= (3, 10):
    from typing import Concatenate, ParamSpec
else:
    from typing_extensions import Concatenate, ParamSpec

P = ParamSpec("P")
R = TypeVar("R")


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

