from typing import Any, Mapping, Tuple, Union  # noqa

from multidict import CIMultiDict, CIMultiDictProxy
from yarl import URL


#  type helpers
LooseHeaders = Union[Mapping, CIMultiDict, CIMultiDictProxy]
RawHeaders = Tuple[Tuple[bytes, bytes], ...]
StrOrURL = Union[str, URL]
