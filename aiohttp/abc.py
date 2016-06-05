import asyncio
import sys
from abc import ABC, abstractmethod


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


class AbstractRequest(ABC):

    @property
    @abstractmethod
    def scheme(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def method(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def version(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def host(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def path_qs(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def _splitted_path(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def raw_path(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def path(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def query_string(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def GET(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def POST(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def headers(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def raw_headers(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def if_modified_since(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def keep_alive(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def match_info(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def app(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def transport(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def cookies(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def payload(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def content(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def has_body(self):
        raise NotImplementedError

    @asyncio.coroutine
    @abstractmethod
    def release(self):
        raise NotImplementedError

    @asyncio.coroutine
    @abstractmethod
    def read(self):
        raise NotImplementedError

    @asyncio.coroutine
    @abstractmethod
    def text(self):
        raise NotImplementedError

    @asyncio.coroutine
    @abstractmethod
    def json(self):
        raise NotImplementedError

    @asyncio.coroutine
    @abstractmethod
    def post(self):
        raise NotImplementedError
