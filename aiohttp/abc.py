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
