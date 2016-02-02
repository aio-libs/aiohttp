import asyncio
import sys
from abc import ABCMeta, abstractmethod


PY_35 = sys.version_info >= (3, 5)


class AbstractRouter(metaclass=ABCMeta):

    @asyncio.coroutine  # pragma: no branch
    @abstractmethod
    def resolve(self, request):
        """Return MATCH_INFO for given request"""


class AbstractMatchInfo(metaclass=ABCMeta):

    @asyncio.coroutine  # pragma: no branch
    @abstractmethod
    def handler(self, request):
        """Execute matched request handler"""

    @asyncio.coroutine  # pragma: no branch
    @abstractmethod
    def expect_handler(self, request):
        """Expect handler for 100-continue processing"""

    @property  # pragma: no branch
    @abstractmethod
    def http_exception(self):
        """HTTPException instance raised on router's resolving, or None"""

    @abstractmethod
    def get_info(self):
        """Return a dict with additional info useful for introspection"""


class AbstractView(metaclass=ABCMeta):

    def __init__(self, request):
        self._request = request

    @property
    def request(self):
        return self._request

    @asyncio.coroutine
    @abstractmethod
    def __iter__(self):
        while False:  # pragma: no cover
            yield None

    if PY_35:
        @abstractmethod
        def __await__(self):
            return
