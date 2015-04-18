__all__ = ('UrlDispatcher', 'UrlMappingMatchInfo',
           'Route', 'PlainRoute', 'DynamicRoute', 'StaticRoute')

import abc
import asyncio

import collections
import mimetypes
import re
import os
import inspect

from urllib.parse import urlencode

from . import hdrs
from .abc import AbstractRouter, AbstractMatchInfo
from .protocol import HttpVersion11
from .web_exceptions import HTTPMethodNotAllowed, HTTPNotFound
from .web_reqrep import StreamResponse


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

    def __repr__(self):
        return "<MatchInfo {}: {}>".format(super().__repr__(), self._route)


@asyncio.coroutine
def _defaultExpectHandler(request):
    """Default handler for Except: 100-continue"""
    if request.version == HttpVersion11:
        request.transport.write(b"HTTP/1.1 100 Continue\r\n\r\n")


class Route(metaclass=abc.ABCMeta):

    def __init__(self, method, handler, name, expect_handler=None):
        if expect_handler is None:
            expect_handler = _defaultExpectHandler
        assert asyncio.iscoroutinefunction(expect_handler), \
            'Coroutine is expected, got {!r}'.format(expect_handler)

        self._method = method
        self._handler = handler
        self._name = name
        self._expect_handler = expect_handler

    @property
    def method(self):
        return self._method

    @property
    def handler(self):
        return self._handler

    @property
    def name(self):
        return self._name

    @abc.abstractmethod  # pragma: no branch
    def match(self, path):
        """Return dict with info for given path or
        None if route cannot process path."""

    @abc.abstractmethod  # pragma: no branch
    def url(self, **kwargs):
        """Construct url for route with additional params."""

    @asyncio.coroutine
    def handle_expect_header(self, request):
        return (yield from self._expect_handler(request))

    @staticmethod
    def _append_query(url, query):
        if query is not None:
            return url + "?" + urlencode(query)
        else:
            return url


class PlainRoute(Route):

    def __init__(self, method, handler, name, path, expect_handler=None):
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

    def __repr__(self):
        name = "'" + self.name + "' " if self.name is not None else ""
        return "<PlainRoute {name}[{method}] {path} -> {handler!r}".format(
            name=name, method=self.method, path=self._path,
            handler=self.handler)


class DynamicRoute(Route):

    def __init__(self, method, handler, name, pattern, formatter,
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

    def __repr__(self):
        name = "'" + self.name + "' " if self.name is not None else ""
        return ("<DynamicRoute {name}[{method}] {formatter} -> {handler!r}"
                .format(name=name, method=self.method,
                        formatter=self._formatter, handler=self.handler))


class StaticRoute(Route):

    limit = 8192

    def __init__(self, name, prefix, directory, expect_handler=None):
        assert prefix.startswith('/'), prefix
        assert prefix.endswith('/'), prefix
        super().__init__(
            'GET', self.handle, name, expect_handler=expect_handler)
        self._prefix = prefix
        self._prefix_len = len(self._prefix)
        self._directory = directory

    def match(self, path):
        if not path.startswith(self._prefix):
            return None
        return {'filename': path[self._prefix_len:]}

    def url(self, *, filename, query=None):
        while filename.startswith('/'):
            filename = filename[1:]
        url = self._prefix + filename
        return self._append_query(url, query)

    @asyncio.coroutine
    def handle(self, request):
        resp = StreamResponse()
        filename = request.match_info['filename']
        filepath = os.path.join(self._directory, filename)
        if '..' in filename:
            raise HTTPNotFound()
        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            raise HTTPNotFound()

        ct, encoding = mimetypes.guess_type(filename)
        if not ct:
            ct = 'application/octet-stream'
        resp.content_type = ct
        if encoding:
            resp.headers['content-encoding'] = encoding

        file_size = os.stat(filepath).st_size
        single_chunk = file_size < self.limit

        if single_chunk:
            resp.content_length = file_size
        resp.start(request)

        with open(filepath, 'rb') as f:
            chunk = f.read(self.limit)
            if single_chunk:
                resp.write(chunk)
            else:
                while chunk:
                    resp.write(chunk)
                    chunk = f.read(self.limit)

        return resp

    def __repr__(self):
        name = "'" + self.name + "' " if self.name is not None else ""
        return "<StaticRoute {name}[{method}] {path} -> {directory!r}".format(
            name=name, method=self.method, path=self._prefix,
            directory=self._directory)


class _NotFoundMatchInfo(UrlMappingMatchInfo):

    def __init__(self):
        super().__init__({}, None)

    @property
    def handler(self):
        return self._not_found

    @property
    def route(self):
        return None

    @asyncio.coroutine
    def _not_found(self, request):
        raise HTTPNotFound()

    def __repr__(self):
        return "<MatchInfo: not found>"


class _MethodNotAllowedMatchInfo(UrlMappingMatchInfo):

    def __init__(self, method, allowed_methods):
        super().__init__({}, None)
        self._method = method
        self._allowed_methods = allowed_methods

    @property
    def handler(self):
        return self._not_allowed

    @property
    def route(self):
        return None

    @asyncio.coroutine
    def _not_allowed(self, request):
        raise HTTPMethodNotAllowed(self._method, self._allowed_methods)

    def __repr__(self):
        return ("<MatchInfo: method {} is not allowed (allowed methods: {}>"
                .format(self._method,
                        ', '.join(sorted(self._allowed_methods))))


class UrlDispatcher(AbstractRouter, collections.abc.Mapping):

    DYN = re.compile(r'^\{(?P<var>[a-zA-Z][_a-zA-Z0-9]*)\}$')
    DYN_WITH_RE = re.compile(
        r'^\{(?P<var>[a-zA-Z][_a-zA-Z0-9]*):(?P<re>.+)\}$')
    GOOD = r'[^{}/]+'
    ROUTE_RE = re.compile(r'(\{[_a-zA-Z][^{}]*(?:\{[^{}]*\}[^{}]*)*\})')

    METHODS = {hdrs.METH_ANY, hdrs.METH_POST,
               hdrs.METH_GET, hdrs.METH_PUT, hdrs.METH_DELETE,
               hdrs.METH_PATCH, hdrs.METH_HEAD, hdrs.METH_OPTIONS}

    def __init__(self):
        super().__init__()
        self._urls = []
        self._routes = {}

    @asyncio.coroutine
    def resolve(self, request):
        path = request.path
        method = request.method
        allowed_methods = set()

        for route in self._urls:
            match_dict = route.match(path)
            if match_dict is None:
                continue

            route_method = route.method
            if route_method == method or route_method == hdrs.METH_ANY:
                return UrlMappingMatchInfo(match_dict, route)

            allowed_methods.add(route_method)
        else:
            if allowed_methods:
                return _MethodNotAllowedMatchInfo(method, allowed_methods)
            else:
                return _NotFoundMatchInfo()

    def __iter__(self):
        return iter(self._routes)

    def __len__(self):
        return len(self._routes)

    def __contains__(self, name):
        return name in self._routes

    def __getitem__(self, name):
        return self._routes[name]

    def register_route(self, route):
        assert isinstance(route, Route), 'Instance of Route class is required.'

        name = route.name
        if name is not None:
            if name in self._routes:
                raise ValueError('Duplicate {!r}, '
                                 'already handled by {!r}'
                                 .format(name, self._routes[name]))
            else:
                self._routes[name] = route
        self._urls.append(route)

    def add_routes(self, methods, path, handler,
                   *args, name=None, expect_handler=None):
        for method in methods:
            self.add_route(method=method, path=path, handler=handler,
                           name=name, expect_handler=expect_handler, *args)

    def add_route(self, method, path, handler,
                  *, name=None, expect_handler=None):

        assert callable(handler), handler
        if (not asyncio.iscoroutinefunction(handler) and
                not inspect.isgeneratorfunction(handler)):
            handler = asyncio.coroutine(handler)

        method = method.upper()
        assert method in self.METHODS, method

        if not ('{' in path or '}' in path or self.ROUTE_RE.search(path)):
            route = PlainRoute(
                method, handler, name, path, expect_handler=expect_handler)
            self.register_route(route)
            return route

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
        route = DynamicRoute(
            method, handler, name, compiled,
            formatter, expect_handler=expect_handler)
        self.register_route(route)
        return route

    def add_static(self, prefix, path, *, name=None, expect_handler=None):
        """
        Adds static files view
        :param prefix - url prefix
        :param path - folder with files
        """
        assert prefix.startswith('/')
        assert os.path.isdir(path), 'Path does not directory %s' % path
        path = os.path.abspath(path)
        if not prefix.endswith('/'):
            prefix += '/'
        route = StaticRoute(name, prefix, path, expect_handler=expect_handler)
        self.register_route(route)
        return route
