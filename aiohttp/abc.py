import asyncio
from abc import ABCMeta, abstractmethod


class AbstractRouter(metaclass=ABCMeta):

    @abstractmethod
    @asyncio.coroutine
    def resolve(self, request):
        """Return MATCH_INFO for given request"""


class AbstractMatchInfo(metaclass=ABCMeta):

    @property
    @abstractmethod
    def handler(self):
        pass
