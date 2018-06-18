from typing import Any, Callable, Mapping, Tuple, Union  # noqa

from multidict import CIMultiDict, CIMultiDictProxy
from yarl import URL


#  type helpers
Byteish = Union[bytes, bytearray, memoryview]
JSONDecoder = Callable[[str], Any]
LooseHeaders = Union[Mapping, CIMultiDict[str], CIMultiDictProxy[str]]
RawHeaders = Tuple[Tuple[bytes, bytes], ...]
StrOrURL = Union[str, URL]
