import asyncio
from abc import ABCMeta, abstractmethod


class AbstractRouter(metaclass=ABCMeta):

    @asyncio.coroutine  # pragma: no branch
    @abstractmethod
    def resolve(self, request):
        """Return MATCH_INFO for given request"""


class AbstractMatchInfo(metaclass=ABCMeta):

    @property  # pragma: no branch
    @abstractmethod
    def handler(self):
        """Return handler for match info"""

    @property  # pragma: no branch
    @abstractmethod
    def route(self):
        """Return route for match info"""


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
