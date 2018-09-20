import json
from typing import TYPE_CHECKING, Any, Callable, Mapping, Tuple, Union  # noqa

from multidict import CIMultiDict, CIMultiDictProxy, MultiDict, MultiDictProxy
from yarl import URL


DEFAULT_JSON_ENCODER = json.dumps
DEFAULT_JSON_DECODER = json.loads

if TYPE_CHECKING:
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
JSONEncoder = Callable[[Any], str]
JSONDecoder = Callable[[str], Any]
LooseHeaders = Union[Mapping[str, str], _CIMultiDict, _CIMultiDictProxy]
RawHeaders = Tuple[Tuple[bytes, bytes], ...]
StrOrURL = Union[str, URL]
