from abc import ABCMeta, abstractmethod


class AbstractRouter(metaclass=ABCMeta):

    @abstractmethod
    def route(self, url):
        """Return ENDPOINT for given url/request"""

    @abstractmethod
    def reverse(self, endpoint):
        """Return URL for given endpoint"""


class AbstractMatch(metaclass=ABCMeta):

    def __init__(self, kind):
        self._kind = kind

    @property
    def kind(self):
        return self._kind


class UrlMappingMatch(AbstractMatch):

    def __init__(self, matchdict, route_name, route_spec, handler):
        super().__init__('urlmapping')
        self._matchdict = matchdict
        self._route_name = route_name
        self._route_spec = route_spec
        self._handler = handler

    @property
    def matchdict(self):
        return self._matchdict

    @property
    def route_name(self):
        return self._route_name
