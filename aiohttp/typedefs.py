import json
from typing import Any, Callable, Mapping, Tuple, Union  # noqa

from multidict import CIMultiDict, CIMultiDictProxy
from yarl import URL


DEFAULT_JSON_ENCODER = json.dumps
DEFAULT_JSON_DECODER = json.loads

Byteish = Union[bytes, bytearray, memoryview]
JSONEncoder = Callable[[Any], str]
JSONDecoder = Callable[[str], Any]
LooseHeaders = Union[Mapping, CIMultiDict, CIMultiDictProxy]
RawHeaders = Tuple[Tuple[bytes, bytes], ...]
StrOrURL = Union[str, URL]
