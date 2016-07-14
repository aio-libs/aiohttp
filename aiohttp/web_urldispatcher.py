import abc
import asyncio

import keyword
import collections
import re
import os
import sys
import inspect
import warnings

from collections.abc import Sized, Iterable, Container
from pathlib import Path
from urllib.parse import urlencode, unquote
from types import MappingProxyType

from multidict import upstr

from . import hdrs
from .abc import AbstractRouter, AbstractMatchInfo, AbstractView
from .file_sender import FileSender
from .protocol import HttpVersion11
from .web_exceptions import (HTTPMethodNotAllowed, HTTPNotFound,
                             HTTPExpectationFailed)
from .web_reqrep import StreamResponse


__all__ = ('UrlDispatcher', 'UrlMappingMatchInfo',
           'AbstractResource', 'Resource', 'PlainResource', 'DynamicResource',
           'ResourceAdapter',
           'AbstractRoute', 'ResourceRoute',
           'Route', 'PlainRoute', 'DynamicRoute', 'StaticRoute', 'View')


PY_35 = sys.version_info >= (3, 5)


class AbstractResource(Sized, Iterable):

    def __init__(self, *, name=None):
        self._name = name

    @property
    def name(self):
        return self._name

    @abc.abstractmethod  # pragma: no branch
    def url(self, **kwargs):
        """Construct url for resource with additional params."""

    @asyncio.coroutine
    @abc.abstractmethod  # pragma: no branch
    def resolve(self, method, path):
        """Resolve resource

        Return (UrlMappingMatchInfo, allowed_methods) pair."""

    @abc.abstractmethod
    def get_info(self):
        """Return a dict with additional info useful for introspection"""

    @staticmethod
    def _append_query(url, query):
        if query is not None:
            return url + "?" + urlencode(query)
        else:
            return url


class AbstractRoute(abc.ABC):
    METHODS = hdrs.METH_ALL | {hdrs.METH_ANY}

    def __init__(self, method, handler, *,
                 expect_handler=None,
                 resource=None):

        if expect_handler is None:
            expect_handler = _defaultExpectHandler

        assert asyncio.iscoroutinefunction(expect_handler), \
            'Coroutine is expected, got {!r}'.format(expect_handler)

        method = upstr(method)
        if method not in self.METHODS:
            raise ValueError("{} is not allowed HTTP method".format(method))

        assert callable(handler), handler
        if asyncio.iscoroutinefunction(handler):
            pass
        elif inspect.isgeneratorfunction(handler):
            warnings.warn("Bare generators are deprecated, "
                          "use @coroutine wrapper", DeprecationWarning)
        elif (isinstance(handler, type) and
              issubclass(handler, AbstractView)):
            pass
        else:
            @asyncio.coroutine
            def handler_wrapper(*args, **kwargs):
                result = old_handler(*args, **kwargs)
                if asyncio.iscoroutine(result):
                    result = yield from result
                return result
            old_handler = handler
            handler = handler_wrapper

        self._method = method
        self._handler = handler
        self._expect_handler = expect_handler
        self._resource = resource

    @property
    def method(self):
        return self._method

    @property
    def handler(self):
        return self._handler

    @property
    @abc.abstractmethod
    def name(self):
        """Optional route's name, always equals to resource's name."""

    @property
    def resource(self):
        return self._resource

    @abc.abstractmethod
    def get_info(self):
        """Return a dict with additional info useful for introspection"""

    @abc.abstractmethod  # pragma: no branch
    def url(self, **kwargs):
        """Construct url for route with additional params."""

    @asyncio.coroutine
    def handle_expect_header(self, request):
        return (yield from self._expect_handler(request))


class UrlMappingMatchInfo(dict, AbstractMatchInfo):

    def __init__(self, match_dict, route):
        super().__init__(match_dict)
        self._route = route

    @property
    def handler(self):
        return self._route.handler

    @property
    def route(self):
        return self._route

    @property
    def expect_handler(self):
        return self._route.handle_expect_header

    @property
    def http_exception(self):
        return None

    def get_info(self):
        return self._route.get_info()

    def __repr__(self):
        return "<MatchInfo {}: {}>".format(super().__repr__(), self._route)


class MatchInfoError(UrlMappingMatchInfo):

    def __init__(self, http_exception):
        self._exception = http_exception
        super().__init__({}, SystemRoute(self._exception))

    @property
    def http_exception(self):
        return self._exception

    def __repr__(self):
        return "<MatchInfoError {}: {}>".format(self._exception.status,
                                                self._exception.reason)


@asyncio.coroutine
def _defaultExpectHandler(request):
    """Default handler for Expect header.

    Just send "100 Continue" to client.
    raise HTTPExpectationFailed if value of header is not "100-continue"
    """
    expect = request.headers.get(hdrs.EXPECT)
    if request.version == HttpVersion11:
        if expect.lower() == "100-continue":
            request.transport.write(b"HTTP/1.1 100 Continue\r\n\r\n")
        else:
            raise HTTPExpectationFailed(text="Unknown Expect: %s" % expect)


class ResourceAdapter(AbstractResource):

    def __init__(self, route):
        assert isinstance(route, Route), \
            'Instance of Route class is required, got {!r}'.format(route)
        super().__init__(name=route.name)
        self._route = route
        route._resource = self

    def url(self, **kwargs):
        return self._route.url(**kwargs)

    @asyncio.coroutine
    def resolve(self, method, path):
        route_method = self._route.method
        allowed_methods = set()
        match_dict = self._route.match(path)
        if match_dict is not None:
            allowed_methods.add(route_method)
            if route_method == hdrs.METH_ANY or route_method == method:
                return (UrlMappingMatchInfo(match_dict, self._route),
                        allowed_methods)
        return None, allowed_methods

    def get_info(self):
        return self._route.get_info()

    def __len__(self):
        return 1

    def __iter__(self):
        yield self._route


class Resource(AbstractResource):

    def __init__(self, *, name=None):
        super().__init__(name=name)
        self._routes = []

    def add_route(self, method, handler, *,
                  expect_handler=None):

        for route in self._routes:
            if route.method == method or route.method == hdrs.METH_ANY:
                raise RuntimeError("Added route will never be executed, "
                                   "method {route.method} is "
                                   "already registered".format(route=route))

        route = ResourceRoute(method, handler, self,
                              expect_handler=expect_handler)
        self.register_route(route)
        return route

    def register_route(self, route):
        assert isinstance(route, ResourceRoute), \
            'Instance of Route class is required, got {!r}'.format(route)
        self._routes.append(route)

    @asyncio.coroutine
    def resolve(self, method, path):
        allowed_methods = set()

        match_dict = self._match(path)
        if match_dict is None:
            return None, allowed_methods

        for route in self._routes:
            route_method = route.method
            allowed_methods.add(route_method)

            if route_method == method or route_method == hdrs.METH_ANY:
                return UrlMappingMatchInfo(match_dict, route), allowed_methods
        else:
            return None, allowed_methods

    def __len__(self):
        return len(self._routes)

    def __iter__(self):
        return iter(self._routes)


class PlainResource(Resource):

    def __init__(self, path, *, name=None):
        super().__init__(name=name)
        self._path = path

    def _match(self, path):
        # string comparison is about 10 times faster than regexp matching
        if self._path == path:
            return {}
        else:
            return None

    def get_info(self):
        return {'path': self._path}

    def url(self, *, query=None):
        return self._append_query(self._path, query)

    def __repr__(self):
        name = "'" + self.name + "' " if self.name is not None else ""
        return "<PlainResource {name} {path}".format(name=name,
                                                     path=self._path)


class DynamicResource(Resource):

    def __init__(self, pattern, formatter, *, name=None):
        super().__init__(name=name)
        self._pattern = pattern
        self._formatter = formatter

    def _match(self, path):
        match = self._pattern.match(path)
        if match is None:
            return None
        else:
            return {key: unquote(value) for key, value in
                    match.groupdict().items()}

    def get_info(self):
        return {'formatter': self._formatter,
                'pattern': self._pattern}

    def url(self, *, parts, query=None):
        url = self._formatter.format_map(parts)
        return self._append_query(url, query)

    def __repr__(self):
        name = "'" + self.name + "' " if self.name is not None else ""
        return ("<DynamicResource {name} {formatter}"
                .format(name=name, formatter=self._formatter))


class ResourceRoute(AbstractRoute):
    """A route with resource"""

    def __init__(self, method, handler, resource, *,
                 expect_handler=None):
        super().__init__(method, handler, expect_handler=expect_handler,
                         resource=resource)

    def __repr__(self):
        return "<ResourceRoute [{method}] {resource} -> {handler!r}".format(
            method=self.method, resource=self._resource,
            handler=self.handler)

    @property
    def name(self):
        return self._resource.name

    def url(self, **kwargs):
        """Construct url for route with additional params."""
        return self._resource.url(**kwargs)

    def get_info(self):
        return self._resource.get_info()

    _append_query = staticmethod(Resource._append_query)


class Route(AbstractRoute):
    """Old fashion route"""

    def __init__(self, method, handler, name, *, expect_handler=None):
        super().__init__(method, handler, expect_handler=expect_handler)
        self._name = name

    @property
    def name(self):
        return self._name

    @abc.abstractmethod
    def match(self, path):
        """Return dict with info for given path or
        None if route cannot process path."""

    _append_query = staticmethod(Resource._append_query)


class PlainRoute(Route):

    def __init__(self, method, handler, name, path, *, expect_handler=None):
        super().__init__(method, handler, name, expect_handler=expect_handler)
        self._path = path

    def match(self, path):
        # string comparison is about 10 times faster than regexp matching
        if self._path == path:
            return {}
        else:
            return None

    def url(self, *, query=None):
        return self._append_query(self._path, query)

    def get_info(self):
        return {'path': self._path}

    def __repr__(self):
        name = "'" + self.name + "' " if self.name is not None else ""
        return "<PlainRoute {name}[{method}] {path} -> {handler!r}".format(
            name=name, method=self.method, path=self._path,
            handler=self.handler)


class DynamicRoute(Route):

    def __init__(self, method, handler, name, pattern, formatter, *,
                 expect_handler=None):
        super().__init__(method, handler, name, expect_handler=expect_handler)
        self._pattern = pattern
        self._formatter = formatter

    def match(self, path):
        match = self._pattern.match(path)
        if match is None:
            return None
        else:
            return match.groupdict()

    def url(self, *, parts, query=None):
        url = self._formatter.format_map(parts)
        return self._append_query(url, query)

    def get_info(self):
        return {'formatter': self._formatter,
                'pattern': self._pattern}

    def __repr__(self):
        name = "'" + self.name + "' " if self.name is not None else ""
        return ("<DynamicRoute {name}[{method}] {formatter} -> {handler!r}"
                .format(name=name, method=self.method,
                        formatter=self._formatter, handler=self.handler))


class StaticRoute(Route):

    def __init__(self, name, prefix, directory, *,
                 expect_handler=None, chunk_size=256*1024,
                 response_factory=StreamResponse):
        assert prefix.startswith('/'), prefix
        assert prefix.endswith('/'), prefix
        super().__init__(
            'GET', self.handle, name, expect_handler=expect_handler)
        self._prefix = prefix
        self._prefix_len = len(self._prefix)
        try:
            directory = Path(directory)
            if str(directory).startswith('~'):
                directory = Path(os.path.expanduser(str(directory)))
            directory = directory.resolve()
            if not directory.is_dir():
                raise ValueError('Not a directory')
        except (FileNotFoundError, ValueError) as error:
            raise ValueError(
                "No directory exists at '{}'".format(directory)) from error
        self._directory = directory
        self._file_sender = FileSender(resp_factory=response_factory,
                                       chunk_size=chunk_size)

    def match(self, path):
        if not path.startswith(self._prefix):
            return None
        return {'filename': path[self._prefix_len:]}

    def url(self, *, filename, query=None):
        if isinstance(filename, Path):
            filename = str(filename)
        while filename.startswith('/'):
            filename = filename[1:]
        url = self._prefix + filename
        return self._append_query(url, query)

    def get_info(self):
        return {'directory': self._directory,
                'prefix': self._prefix}

    @asyncio.coroutine
    def handle(self, request):
        filename = request.match_info['filename']
        try:
            filepath = self._directory.joinpath(filename).resolve()
            filepath.relative_to(self._directory)
        except (ValueError, FileNotFoundError) as error:
            # relatively safe
            raise HTTPNotFound() from error
        except Exception as error:
            # perm error or other kind!
            request.app.logger.exception(error)
            raise HTTPNotFound() from error

        # Make sure that filepath is a file
        if not filepath.is_file():
            raise HTTPNotFound()

        ret = yield from self._file_sender.send(request, filepath)
        return ret

    def __repr__(self):
        name = "'" + self.name + "' " if self.name is not None else ""
        return "<StaticRoute {name}[{method}] {path} -> {directory!r}".format(
            name=name, method=self.method, path=self._prefix,
            directory=self._directory)


class SystemRoute(Route):

    def __init__(self, http_exception):
        super().__init__(hdrs.METH_ANY, self._handler, None)
        self._http_exception = http_exception

    def url(self, **kwargs):
        raise RuntimeError(".url() is not allowed for SystemRoute")

    def match(self, path):
        return None

    def get_info(self):
        return {'http_exception': self._http_exception}

    @asyncio.coroutine
    def _handler(self, request):
        raise self._http_exception

    @property
    def status(self):
        return self._http_exception.status

    @property
    def reason(self):
        return self._http_exception.reason

    def __repr__(self):
        return "<SystemRoute {self.status}: {self.reason}>".format(self=self)


class View(AbstractView):

    @asyncio.coroutine
    def __iter__(self):
        if self.request.method not in hdrs.METH_ALL:
            self._raise_allowed_methods()
        method = getattr(self, self.request.method.lower(), None)
        if method is None:
            self._raise_allowed_methods()
        resp = yield from method()
        return resp

    if PY_35:
        def __await__(self):
            return (yield from self.__iter__())

    def _raise_allowed_methods(self):
        allowed_methods = {
            m for m in hdrs.METH_ALL if hasattr(self, m.lower())}
        raise HTTPMethodNotAllowed(self.request.method, allowed_methods)


class ResourcesView(Sized, Iterable, Container):

    def __init__(self, resources):
        self._resources = resources

    def __len__(self):
        return len(self._resources)

    def __iter__(self):
        yield from self._resources

    def __contains__(self, resource):
        return resource in self._resources


class RoutesView(Sized, Iterable, Container):

    def __init__(self, resources):
        self._routes = []
        for resource in resources:
            for route in resource:
                self._routes.append(route)

    def __len__(self):
        return len(self._routes)

    def __iter__(self):
        yield from self._routes

    def __contains__(self, route):
        return route in self._routes


class UrlDispatcher(AbstractRouter, collections.abc.Mapping):

    DYN = re.compile(r'^\{(?P<var>[a-zA-Z][_a-zA-Z0-9]*)\}$')
    DYN_WITH_RE = re.compile(
        r'^\{(?P<var>[a-zA-Z][_a-zA-Z0-9]*):(?P<re>.+)\}$')
    GOOD = r'[^{}/]+'
    ROUTE_RE = re.compile(r'(\{[_a-zA-Z][^{}]*(?:\{[^{}]*\}[^{}]*)*\})')
    NAME_SPLIT_RE = re.compile('[.:-]')

    def __init__(self):
        super().__init__()
        self._resources = []
        self._named_resources = {}

    @asyncio.coroutine
    def resolve(self, request):
        path = request.raw_path
        method = request.method
        allowed_methods = set()

        for resource in self._resources:
            match_dict, allowed = yield from resource.resolve(method, path)
            if match_dict is not None:
                return match_dict
            else:
                allowed_methods |= allowed
        else:
            if allowed_methods:
                return MatchInfoError(HTTPMethodNotAllowed(method,
                                                           allowed_methods))
            else:
                return MatchInfoError(HTTPNotFound())

    def __iter__(self):
        return iter(self._named_resources)

    def __len__(self):
        return len(self._named_resources)

    def __contains__(self, name):
        return name in self._named_resources

    def __getitem__(self, name):
        return self._named_resources[name]

    def resources(self):
        return ResourcesView(self._resources)

    def routes(self):
        return RoutesView(self._resources)

    def named_resources(self):
        return MappingProxyType(self._named_resources)

    def named_routes(self):
        # NB: it's ambiguous but it's really resources.
        warnings.warn("Use .named_resources instead", DeprecationWarning)
        return self.named_resources()

    def register_route(self, route):
        warnings.warn("Use resource-based interface", DeprecationWarning)
        resource = ResourceAdapter(route)
        self._reg_resource(resource)

    def _reg_resource(self, resource):
        assert isinstance(resource, AbstractResource), \
            'Instance of AbstractResource class is required, got {!r}'.format(
                resource)

        name = resource.name

        if name is not None:
            parts = self.NAME_SPLIT_RE.split(name)
            for part in parts:
                if not part.isidentifier() or keyword.iskeyword(part):
                    raise ValueError('Incorrect route name {!r}, '
                                     'the name should be a sequence of '
                                     'python identifiers separated '
                                     'by dash, dot or column'.format(name))
            if name in self._named_resources:
                raise ValueError('Duplicate {!r}, '
                                 'already handled by {!r}'
                                 .format(name, self._named_resources[name]))
            self._named_resources[name] = resource
        self._resources.append(resource)

    def add_resource(self, path, *, name=None):
        if not path.startswith('/'):
            raise ValueError("path should be started with /")
        if not ('{' in path or '}' in path or self.ROUTE_RE.search(path)):
            resource = PlainResource(path, name=name)
            self._reg_resource(resource)
            return resource

        pattern = ''
        formatter = ''
        for part in self.ROUTE_RE.split(path):
            match = self.DYN.match(part)
            if match:
                pattern += '(?P<{}>{})'.format(match.group('var'), self.GOOD)
                formatter += '{' + match.group('var') + '}'
                continue

            match = self.DYN_WITH_RE.match(part)
            if match:
                pattern += '(?P<{var}>{re})'.format(**match.groupdict())
                formatter += '{' + match.group('var') + '}'
                continue

            if '{' in part or '}' in part:
                raise ValueError("Invalid path '{}'['{}']".format(path, part))

            formatter += part
            pattern += re.escape(part)

        try:
            compiled = re.compile('^' + pattern + '$')
        except re.error as exc:
            raise ValueError(
                "Bad pattern '{}': {}".format(pattern, exc)) from None
        resource = DynamicResource(compiled, formatter, name=name)
        self._reg_resource(resource)
        return resource

    def add_route(self, method, path, handler,
                  *, name=None, expect_handler=None):
        resource = self.add_resource(path, name=name)
        return resource.add_route(method, handler,
                                  expect_handler=expect_handler)

    def add_static(self, prefix, path, *, name=None, expect_handler=None,
                   chunk_size=256*1024, response_factory=StreamResponse):
        """
        Adds static files view
        :param prefix - url prefix
        :param path - folder with files
        """
        assert prefix.startswith('/')
        if not prefix.endswith('/'):
            prefix += '/'
        route = StaticRoute(name, prefix, path,
                            expect_handler=expect_handler,
                            chunk_size=chunk_size,
                            response_factory=response_factory)
        self.register_route(route)
        return route
