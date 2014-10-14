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
    def kind(self):
        pass

    @property
    @abstractmethod
    def handler(self):
        pass


class UrlMappingMatchInfo(AbstractMatchInfo):

    def __init__(self, matchdict, entry):
        self._matchdict = matchdict
        self._entry = entry

    @property
    def kind(self):
        return 'urlmapping'

    @property
    def handler(self):
        return self._entry.handler

    @property
    def matchdict(self):
        return self._matchdict

    @property
    def route_name(self):
        return self._entry.name
