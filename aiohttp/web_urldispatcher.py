import abc
import asyncio

import keyword
import collections
import mimetypes
import re
import os
import sys
import inspect
import warnings

from collections.abc import Sized, Iterable, Container
from pathlib import Path
from urllib.parse import urlencode, unquote
from types import MappingProxyType

from . import hdrs
from .abc import AbstractRouter, AbstractMatchInfo, AbstractView
from .protocol import HttpVersion11
from .web_exceptions import (HTTPMethodNotAllowed, HTTPNotFound,
                             HTTPNotModified, HTTPExpectationFailed)
from .web_reqrep import StreamResponse
from .multidict import upstr


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


class AbstractRoute(metaclass=abc.ABCMeta):
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
            handler = asyncio.coroutine(handler)

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
    """Default handler for Except header.

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
        self._chunk_size = chunk_size
        self._response_factory = response_factory

        if bool(os.environ.get("AIOHTTP_NOSENDFILE")):
            self._sendfile = self._sendfile_fallback

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

    def _sendfile_cb(self, fut, out_fd, in_fd, offset, count, loop,
                     registered):
        if registered:
            loop.remove_writer(out_fd)
        try:
            n = os.sendfile(out_fd, in_fd, offset, count)
            if n == 0:  # EOF reached
                n = count
        except (BlockingIOError, InterruptedError):
            n = 0
        except Exception as exc:
            fut.set_exception(exc)
            return

        if n < count:
            loop.add_writer(out_fd, self._sendfile_cb, fut, out_fd, in_fd,
                            offset + n, count - n, loop, True)
        else:
            fut.set_result(None)

    @asyncio.coroutine
    def _sendfile_system(self, req, resp, fobj, count):
        """
        Write `count` bytes of `fobj` to `resp` starting from `offset` using
        the ``sendfile`` system call.

        `req` should be a :obj:`aiohttp.web.Request` instance.

        `resp` should be a :obj:`aiohttp.web.StreamResponse` instance.

        `fobj` should be an open file object.

        `offset` should be an integer >= 0.

        `count` should be an integer > 0.
        """
        transport = req.transport

        if transport.get_extra_info("sslcontext"):
            yield from self._sendfile_fallback(req, resp, fobj, count)
            return

        yield from resp.drain()

        loop = req.app.loop
        out_fd = transport.get_extra_info("socket").fileno()
        in_fd = fobj.fileno()
        fut = asyncio.Future(loop=loop)

        self._sendfile_cb(fut, out_fd, in_fd, 0, count, loop, False)

        yield from fut

    @asyncio.coroutine
    def _sendfile_fallback(self, req, resp, fobj, count):
        """
        Mimic the :meth:`_sendfile_system` method, but without using the
        ``sendfile`` system call. This should be used on systems that don't
        support the ``sendfile`` system call.

        To avoid blocking the event loop & to keep memory usage low, `fobj` is
        transferred in chunks controlled by the `chunk_size` argument to
        :class:`StaticRoute`.
        """
        chunk_size = self._chunk_size

        chunk = fobj.read(chunk_size)
        while chunk and count > chunk_size:
            resp.write(chunk)
            yield from resp.drain()
            count = count - chunk_size
            chunk = fobj.read(chunk_size)

        if chunk:
            resp.write(chunk[:count])
            yield from resp.drain()

    if hasattr(os, "sendfile"):  # pragma: no cover
        _sendfile = _sendfile_system
    else:  # pragma: no cover
        _sendfile = _sendfile_fallback

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
            request.logger.exception(error)
            raise HTTPNotFound() from error

        st = filepath.stat()

        modsince = request.if_modified_since
        if modsince is not None and st.st_mtime <= modsince.timestamp():
            raise HTTPNotModified()

        ct, encoding = mimetypes.guess_type(str(filepath))
        if not ct:
            ct = 'application/octet-stream'

        resp = self._response_factory()
        resp.content_type = ct
        if encoding:
            resp.headers[hdrs.CONTENT_ENCODING] = encoding
        resp.last_modified = st.st_mtime

        file_size = st.st_size

        resp.content_length = file_size
        resp.set_tcp_cork(True)
        try:
            yield from resp.prepare(request)

            with filepath.open('rb') as f:
                yield from self._sendfile(request, resp, f, file_size)

        finally:
            resp.set_tcp_nodelay(True)

        return resp

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
        allowed_methods = {m for m in hdrs.METH_ALL if hasattr(self, m)}
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
