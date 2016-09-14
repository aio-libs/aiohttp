import asyncio
import sys
from abc import ABC, abstractmethod
from collections import defaultdict
from http.cookies import SimpleCookie

PY_35 = sys.version_info >= (3, 5)


class AbstractRouter(ABC):

    @asyncio.coroutine  # pragma: no branch
    @abstractmethod
    def resolve(self, request):
        """Return MATCH_INFO for given request"""


class AbstractMatchInfo(ABC):

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

    @abstractmethod  # pragma: no branch
    def get_info(self):
        """Return a dict with additional info useful for introspection"""


class AbstractView(ABC):

    def __init__(self, request):
        self._request = request

    @property
    def request(self):
        return self._request

    @asyncio.coroutine  # pragma: no branch
    @abstractmethod
    def __iter__(self):
        while False:  # pragma: no cover
            yield None

    if PY_35:  # pragma: no branch
        @abstractmethod
        def __await__(self):
            return  # pragma: no cover


class AbstractResolver(ABC):

    @asyncio.coroutine  # pragma: no branch
    @abstractmethod
    def resolve(self, hostname):
        """Return IP address for given hostname"""

    @asyncio.coroutine  # pragma: no branch
    @abstractmethod
    def close(self):
        """Release resolver"""


class CookiesProxy:
    def __init__(self, jar):
        self._jar = jar

    def __iter__(self):
        return iter(self._jar)

    def __len__(self):
        return len(self._jar)

    def clear(self):
        self._jar.clear()


class AbstractCookieJar(ABC):

    def __init__(self, *, loop=None):
        self._cookies = defaultdict(SimpleCookie)
        self._loop = loop or asyncio.get_event_loop()

    @property
    def cookies(self):
        """The session cookies."""
        return CookiesProxy(self)

    def clear(self):
        self._cookies.clear()

    @abstractmethod
    def update_cookies(self, cookies, response_url=None):
        """Update cookies."""

    @abstractmethod
    def filter_cookies(self, request_url):
        """Returns this jar's cookies filtered by their attributes."""

    def __iter__(self):
        for val in self._cookies.values():
            yield from val.values()

    def __len__(self):
        return sum(1 for i in self)
