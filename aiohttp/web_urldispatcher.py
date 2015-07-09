__all__ = ('UrlDispatcher', 'UrlMappingMatchInfo',
           'Route', 'PlainRoute', 'DynamicRoute', 'StaticRoute')

import abc
import asyncio

import collections
import mimetypes
import re
import os
import inspect

from urllib.parse import urlencode, unquote

from . import hdrs, web_exceptions
from .abc import AbstractRouter, AbstractMatchInfo
from .protocol import HttpVersion11
from .web_exceptions import HTTPMethodNotAllowed, HTTPNotFound, HTTPNotModified
from .web_reqrep import StreamResponse
from .multidict import upstr


class UrlMappingMatchInfo(dict, AbstractMatchInfo):

    def __init__(self, match_dict, route, handler):
        # Unquote separate matching parts
        match_dict = {key: unquote(value) for key, value in match_dict.items()}

        super().__init__(match_dict)
        self._route = route
        self._handler = handler

    @property
    def handler(self):
        return self._handler

    @property
    def route(self):
        return self._route

    def __repr__(self):
        return "<MatchInfo {}: {}>".format(super().__repr__(), self._route)


@asyncio.coroutine
def defaultExpectHandler(request):
    """Default handler for Except: 100-continue"""
    if request.version == HttpVersion11:
        request.transport.write(b"HTTP/1.1 100 Continue\r\n\r\n")


class Route(metaclass=abc.ABCMeta):

    def __init__(self, name, *, expect_handler=None):
        if expect_handler is None:
            expect_handler = defaultExpectHandler
        assert asyncio.iscoroutinefunction(expect_handler), \
            'Coroutine is expected, got {!r}'.format(expect_handler)

        self._name = name
        self._expect_handler = expect_handler

    @property
    def name(self):
        return self._name

    @abc.abstractmethod  # pragma: no branch
    def match(self, request):
        """Return UrlMappingMatchInfo object."""

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


class ViewableRoute(Route):

    def __init__(self, name, *, expect_handler=None):
        super().__init__(name, expect_handler=expect_handler)
        self._views = []

    def match_view(self, request, view_name, match_dict):
        method = request.method
        allowed_methods = set()

        for view in self._views:
            if (view.name == view_name and
                (view.method == method or
                 view.method == hdrs.METH_ANY)):
                return UrlMappingMatchInfo(match_dict, self, view)
            else:
                allowed_methods.add(view.method)

        return _MethodNotAllowedMatchInfo(method, allowed_methods)

    def add_view(self, method, handler, *, name=''):
        self._views.append(View(handler, name, method))


class PlainRoute(ViewableRoute):

    def __init__(self, name, path, *, expect_handler=None):
        super().__init__(name, expect_handler=expect_handler)
        self._path = path

    def match(self, request):
        # string comparison is about 10 times faster than regexp matching
        if self._path == request.raw_path:
            return super().match_view(request, '', {})
        else:
            return None

    def url(self, *, query=None, view=None):
        return self._append_query(self._path, query)

    def __repr__(self):
        method = ','.join(set([view.method for view in self._views]))
        name = "'" + self.name + "' " if self.name is not None else ""
        return "<PlainRoute {name}[{method}] {path}".format(
            name=name, method=method, path=self._path)


class DynamicRoute(ViewableRoute):

    def __init__(self, name, pattern, formatter, *, expect_handler=None):
        super().__init__(name, expect_handler=expect_handler)
        self._pattern = pattern
        self._formatter = formatter

    def match(self, request):
        match = self._pattern.match(request.raw_path)
        if match is None:
            return None
        else:
            return super().match_view(request, '', match.groupdict())

    def url(self, *, parts, query=None, view=None):
        url = self._formatter.format_map(parts)
        return self._append_query(url, query)

    def __repr__(self):
        name = "'" + self.name + "' " if self.name is not None else ""
        method = ','.join(set([view.method for view in self._views]))
        return ("<DynamicRoute {name}[{method}] {formatter}"
                .format(name=name, method=method, formatter=self._formatter))


class SystemRoute(ViewableRoute):

    def __init__(self, status, reason=''):
        super().__init__(str(status))
        self._status = status
        self._reason = reason
        self._view = None

    def url(self, **kwargs):
        raise RuntimeError(".url() is not allowed for SystemRoute")

    def match(self, request):
        pass

    def handler(self, request, exc):
        request.match_info['exception'] = exc
        if self._view is not None:
            return (yield from self._view(request))
        else:
            return exc

    @property
    def status(self):
        return self._status

    @property
    def reason(self):
        return self._reason

    def set_view(self, handler):
        self._view = handler

    def __repr__(self):
        return "<SystemRoute {status}: {reason}>".format(
            status=self._status, reason=self._reason)


class StaticRoute(Route):

    def __init__(self, name, prefix, directory, *,
                 expect_handler=None, chunk_size=256*1024):
        assert prefix.startswith('/'), prefix
        assert prefix.endswith('/'), prefix
        super().__init__(name, expect_handler=expect_handler)
        self._prefix = prefix
        self._prefix_len = len(self._prefix)
        self._directory = os.path.abspath(directory) + os.sep
        self._chunk_size = chunk_size

        if not os.path.isdir(self._directory):
            raise ValueError(
                "No directory exists at '{}'".format(self._directory))

    def match(self, request):
        path = request.raw_path
        if not path.startswith(self._prefix):
            return None

        if request.method != hdrs.METH_GET:
            return _MethodNotAllowedMatchInfo(request.method, [hdrs.METH_GET])

        return UrlMappingMatchInfo(
            {'filename': path[self._prefix_len:]}, self, self.handler)

    def url(self, *, filename, query=None):
        while filename.startswith('/'):
            filename = filename[1:]
        url = self._prefix + filename
        return self._append_query(url, query)

    @asyncio.coroutine
    def handler(self, request):
        filename = request.match_info['filename']
        filepath = os.path.abspath(os.path.join(self._directory, filename))
        if not filepath.startswith(self._directory):
            raise HTTPNotFound()
        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            raise HTTPNotFound()

        st = os.stat(filepath)

        modsince = request.if_modified_since
        if modsince is not None and st.st_mtime <= modsince.timestamp():
            raise HTTPNotModified()

        ct, encoding = mimetypes.guess_type(filepath)
        if not ct:
            ct = 'application/octet-stream'

        resp = StreamResponse()
        resp.content_type = ct
        if encoding:
            resp.headers[hdrs.CONTENT_ENCODING] = encoding
        resp.last_modified = st.st_mtime

        file_size = st.st_size
        single_chunk = file_size < self._chunk_size

        if single_chunk:
            resp.content_length = file_size
        resp.start(request)

        with open(filepath, 'rb') as f:
            chunk = f.read(self._chunk_size)
            if single_chunk:
                resp.write(chunk)
            else:
                while chunk:
                    resp.write(chunk)
                    chunk = f.read(self._chunk_size)

        return resp

    def __repr__(self):
        name = "'" + self.name + "' " if self.name is not None else ""
        return "<StaticRoute {name}[GET] {path} -> {directory!r}".format(
            name=name, path=self._prefix, directory=self._directory)


class View(metaclass=abc.ABCMeta):

    def __init__(self, handler, name='', method=hdrs.METH_ANY):
        self._name = name
        self._method = upstr(method)
        self._handler = handler

    @property
    def method(self):
        return self._method

    @property
    def handler(self):
        return self._handler

    @property
    def name(self):
        return self._name

    @asyncio.coroutine
    def __call__(self, request):
        return (yield from self._handler(request))


class _NotFoundMatchInfo(UrlMappingMatchInfo):

    route = SystemRoute(404, 'Not Found')

    def __init__(self):
        super().__init__({}, None, self._not_found)

    @property
    def handler(self):
        return self._not_found

    @asyncio.coroutine
    def _not_found(self, request):
        raise HTTPNotFound()

    def __repr__(self):
        return "<MatchInfo: not found>"


class _MethodNotAllowedMatchInfo(UrlMappingMatchInfo):

    route = SystemRoute(405, 'Method Not Allowed')

    def __init__(self, method, allowed_methods):
        super().__init__({}, None, self._not_allowed)
        self._method = method
        self._allowed_methods = allowed_methods

    @property
    def handler(self):
        return self._not_allowed

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

    _system_routes = dict(
        (getattr(web_exceptions, name).status_code,
         SystemRoute(getattr(web_exceptions, name).status_code))
        for name in web_exceptions.__all__)

    def __init__(self):
        super().__init__()
        self._urls = []
        self._routes = {}

    @asyncio.coroutine
    def resolve(self, request):
        for route in self._urls:
            match_info = route.match(request)
            if match_info is None:
                continue

            return match_info
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

    def get_system_route(self, status_code):
        if status_code not in self._system_routes:
            self._system_routes[status_code] = SystemRoute(status_code)

        return self._system_routes[status_code]

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

    def add_view(self, method, handler, *, name='', route=None):

        assert callable(handler), handler
        if (not asyncio.iscoroutinefunction(handler) and
                not inspect.isgeneratorfunction(handler)):
            handler = asyncio.coroutine(handler)

        if route is None:
            raise ValueError('Route name is required')

        if route not in self._routes:
            raise ValueError('Route is not found {}'.format(route))

        route = self._routes[route]
        route.add_view(method, handler, name=name)

    def add_route(self, name, path, *, expect_handler=None):

        if not path.startswith('/'):
            raise ValueError("path should be started with /")

        if not ('{' in path or '}' in path or self.ROUTE_RE.search(path)):
            route = PlainRoute(name, path, expect_handler=expect_handler)
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
            name, compiled, formatter, expect_handler=expect_handler)
        self.register_route(route)
        return route

    def add_static(self, prefix, path, *, name=None, expect_handler=None,
                   chunk_size=256*1024):
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
                            chunk_size=chunk_size)
        self.register_route(route)
        return route
