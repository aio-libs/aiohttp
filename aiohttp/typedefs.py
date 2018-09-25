import json
import os  # noqa
import pathlib  # noqa
import sys
from typing import (TYPE_CHECKING, Any, Callable, Dict, List, Mapping,  # noqa
                    Tuple, Union)

from multidict import CIMultiDict, CIMultiDictProxy, MultiDict, MultiDictProxy
from yarl import URL


DEFAULT_JSON_ENCODER = json.dumps
DEFAULT_JSON_DECODER = json.loads

if TYPE_CHECKING:  # pragma: no cover
    _CIMultiDict = CIMultiDict[str]
    _CIMultiDictProxy = CIMultiDictProxy[str]
    _MultiDict = MultiDict[str]
    _MultiDictProxy = MultiDictProxy[str]
else:
    _CIMultiDict = CIMultiDict
    _CIMultiDictProxy = CIMultiDictProxy
    _MultiDict = MultiDict
    _MultiDictProxy = MultiDictProxy

Byteish = Union[bytes, bytearray, memoryview]
JSONObj = Dict[str, Any]
JSON = Union[
    JSONObj,
    List[Union[JSONObj, Any]],
]
JSONEncoder = Callable[[JSON], str]
JSONDecoder = Callable[[str], JSON]
LooseHeaders = Union[Mapping[str, str], _CIMultiDict, _CIMultiDictProxy]
RawHeaders = Tuple[Tuple[bytes, bytes], ...]
StrOrURL = Union[str, URL]


if sys.version_info >= (3, 6):
    PathLike = Union[str, 'os.PathLike[str]']
else:
    PathLike = Union[str, pathlib.PurePath]
