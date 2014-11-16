import asyncio
from abc import ABCMeta, abstractmethod


class AbstractRouter(metaclass=ABCMeta):

    @asyncio.coroutine
    @abstractmethod
    def resolve(self, request):
        """Return MATCH_INFO for given request"""

    @asyncio.coroutine
    @abstractmethod
    def reverse(self, method, endpoint, **kwargs):
        """Return URL string for """


class AbstractMatchInfo(metaclass=ABCMeta):

    @property
    @abstractmethod
    def handler(self):
        """Return handler for match info"""

    @property
    @abstractmethod
    def endpoint(self):
        """Return endpoint for match info"""
