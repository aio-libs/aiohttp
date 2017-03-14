import abc
import asyncio
import collections
import inspect
import keyword
import os
import re
import sys
import warnings
from collections.abc import Container, Iterable, Sized
from pathlib import Path
from types import MappingProxyType

# do not use yarl.quote directly,
# use `URL(path).raw_path` instead of `quote(path)`
# Escaping of the URLs need to be consitent with the escaping done by yarl
from yarl import URL, unquote

from . import hdrs
from .abc import AbstractMatchInfo, AbstractRouter, AbstractView
from .file_sender import FileSender
from .protocol import HttpVersion11
from .web_exceptions import (HTTPExpectationFailed, HTTPForbidden,
                             HTTPMethodNotAllowed, HTTPNotFound)
from .web_reqrep import Response, StreamResponse

__all__ = ('UrlDispatcher', 'UrlMappingMatchInfo',
           'AbstractResource', 'Resource', 'PlainResource', 'DynamicResource',
           'AbstractRoute', 'ResourceRoute',
           'StaticResource', 'View')


PY_35 = sys.version_info >= (3, 5)


HTTP_METHOD_RE = re.compile(r"^[0-9A-Za-z!#\$%&'\*\+\-\.\^_`\|~]+$")


class AbstractResource(Sized, Iterable):

    def __init__(self, *, name=None):
        self._name = name

    @property
    def name(self):
        return self._name

    @abc.abstractmethod  # pragma: no branch
    def url(self, **kwargs):
        """Construct url for resource with additional params.

        Deprecated, use url_for() instead.

        """
        warnings.warn(".url(...) is deprecated, use .url_for instead",
                      DeprecationWarning,
                      stacklevel=3)

    @abc.abstractmethod  # pragma: no branch
    def url_for(self, **kwargs):
        """Construct url for resource with additional params."""

    @asyncio.coroutine
    @abc.abstractmethod  # pragma: no branch
    def resolve(self, request):
        """Resolve resource

        Return (UrlMappingMatchInfo, allowed_methods) pair."""

    @abc.abstractmethod
    def add_prefix(self, prefix):
        """Add a prefix to processed URLs.

        Required for subapplications support.

        """

    @abc.abstractmethod
    def get_info(self):
        """Return a dict with additional info useful for introspection"""

    def freeze(self):
        pass


class AbstractRoute(abc.ABC):

    def __init__(self, method, handler, *,
                 expect_handler=None,
                 resource=None):

        if expect_handler is None:
            expect_handler = _defaultExpectHandler

        assert asyncio.iscoroutinefunction(expect_handler), \
            'Coroutine is expected, got {!r}'.format(expect_handler)

        method = method.upper()
        if not HTTP_METHOD_RE.match(method):
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
    def url_for(self, *args, **kwargs):
        """Construct url for route with additional params."""

    @abc.abstractmethod  # pragma: no branch
    def url(self, **kwargs):
        """Construct url for resource with additional params.

        Deprecated, use url_for() instead.

        """
        warnings.warn(".url(...) is deprecated, use .url_for instead",
                      DeprecationWarning,
                      stacklevel=3)

    @asyncio.coroutine
    def handle_expect_header(self, request):
        return (yield from self._expect_handler(request))


class UrlMappingMatchInfo(dict, AbstractMatchInfo):

    def __init__(self, match_dict, route):
        super().__init__(match_dict)
        self._route = route
        self._apps = []
        self._frozen = False

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

    @property
    def apps(self):
        return tuple(self._apps)

    def add_app(self, app):
        if self._frozen:
            raise RuntimeError("Cannot change apps stack after .freeze() call")
        self._apps.insert(0, app)

    def freeze(self):
        self._frozen = True

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
    def resolve(self, request):
        allowed_methods = set()

        match_dict = self._match(request.rel_url.raw_path)
        if match_dict is None:
            return None, allowed_methods

        for route in self._routes:
            route_method = route.method
            allowed_methods.add(route_method)

            if route_method == request.method or route_method == hdrs.METH_ANY:
                return UrlMappingMatchInfo(match_dict, route), allowed_methods
        else:
            return None, allowed_methods

        yield  # pragma: no cover

    def __len__(self):
        return len(self._routes)

    def __iter__(self):
        return iter(self._routes)


class PlainResource(Resource):

    def __init__(self, path, *, name=None):
        super().__init__(name=name)
        assert not path or path.startswith('/')
        self._path = path

    def freeze(self):
        if not self._path:
            self._path = '/'

    def add_prefix(self, prefix):
        assert prefix.startswith('/')
        assert not prefix.endswith('/')
        assert len(prefix) > 1
        self._path = prefix + self._path

    def _match(self, path):
        # string comparison is about 10 times faster than regexp matching
        if self._path == path:
            return {}
        else:
            return None

    def get_info(self):
        return {'path': self._path}

    def url(self, *, query=None):
        super().url()
        return str(self.url_for().with_query(query))

    def url_for(self):
        return URL(self._path)

    def __repr__(self):
        name = "'" + self.name + "' " if self.name is not None else ""
        return "<PlainResource {name} {path}".format(name=name,
                                                     path=self._path)


class DynamicResource(Resource):

    def __init__(self, pattern, formatter, *, name=None):
        super().__init__(name=name)
        assert pattern.pattern.startswith('\\/')
        assert formatter.startswith('/')
        self._pattern = pattern
        self._formatter = formatter

    def add_prefix(self, prefix):
        assert prefix.startswith('/')
        assert not prefix.endswith('/')
        assert len(prefix) > 1
        self._pattern = re.compile(re.escape(prefix)+self._pattern.pattern)
        self._formatter = prefix + self._formatter

    def _match(self, path):
        match = self._pattern.fullmatch(path)
        if match is None:
            return None
        else:
            return {key: unquote(value) for key, value in
                    match.groupdict().items()}

    def get_info(self):
        return {'formatter': self._formatter,
                'pattern': self._pattern}

    def url_for(self, **parts):
        url = self._formatter.format_map(parts)
        return URL(url)

    def url(self, *, parts, query=None):
        super().url(**parts)
        return str(self.url_for(**parts).with_query(query))

    def __repr__(self):
        name = "'" + self.name + "' " if self.name is not None else ""
        return ("<DynamicResource {name} {formatter}"
                .format(name=name, formatter=self._formatter))


class PrefixResource(AbstractResource):

    def __init__(self, prefix, *, name=None):
        assert not prefix or prefix.startswith('/'), prefix
        assert prefix in ('', '/') or not prefix.endswith('/'), prefix
        super().__init__(name=name)
        self._prefix = URL(prefix).raw_path

    def add_prefix(self, prefix):
        assert prefix.startswith('/')
        assert not prefix.endswith('/')
        assert len(prefix) > 1
        self._prefix = prefix + self._prefix


class StaticResource(PrefixResource):

    def __init__(self, prefix, directory, *, name=None,
                 expect_handler=None, chunk_size=256*1024,
                 response_factory=StreamResponse,
                 show_index=False, follow_symlinks=False):
        super().__init__(prefix, name=name)
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
        self._show_index = show_index
        self._follow_symlinks = follow_symlinks
        self._expect_handler = expect_handler

        self._routes = {'GET': ResourceRoute('GET', self._handle, self,
                                             expect_handler=expect_handler),

                        'HEAD': ResourceRoute('HEAD', self._handle, self,
                                              expect_handler=expect_handler)}

    def url(self, *, filename, query=None):
        return str(self.url_for(filename=filename).with_query(query))

    def url_for(self, *, filename):
        if isinstance(filename, Path):
            filename = str(filename)
        while filename.startswith('/'):
            filename = filename[1:]
        filename = '/' + filename
        url = self._prefix + URL(filename).raw_path
        return URL(url)

    def get_info(self):
        return {'directory': self._directory,
                'prefix': self._prefix}

    def set_options_route(self, handler):
        if 'OPTIONS' in self._routes:
            raise RuntimeError('OPTIONS route was set already')
        self._routes['OPTIONS'] = ResourceRoute(
            'OPTIONS', handler, self,
            expect_handler=self._expect_handler)

    @asyncio.coroutine
    def resolve(self, request):
        path = request.rel_url.raw_path
        method = request.method
        allowed_methods = set(self._routes)
        if not path.startswith(self._prefix):
            return None, set()

        if method not in allowed_methods:
            return None, allowed_methods

        match_dict = {'filename': unquote(path[len(self._prefix)+1:])}
        return (UrlMappingMatchInfo(match_dict, self._routes[method]),
                allowed_methods)
        yield  # pragma: no cover

    def __len__(self):
        return len(self._routes)

    def __iter__(self):
        return iter(self._routes.values())

    @asyncio.coroutine
    def _handle(self, request):
        filename = unquote(request.match_info['filename'])
        try:
            filepath = self._directory.joinpath(filename).resolve()
            if not self._follow_symlinks:
                filepath.relative_to(self._directory)
        except (ValueError, FileNotFoundError) as error:
            # relatively safe
            raise HTTPNotFound() from error
        except Exception as error:
            # perm error or other kind!
            request.app.logger.exception(error)
            raise HTTPNotFound() from error

        # on opening a dir, load it's contents if allowed
        if filepath.is_dir():
            if self._show_index:
                try:
                    ret = Response(text=self._directory_as_html(filepath),
                                   content_type="text/html")
                except PermissionError:
                    raise HTTPForbidden()
            else:
                raise HTTPForbidden()
        elif filepath.is_file():
            ret = yield from self._file_sender.send(request, filepath)
        else:
            raise HTTPNotFound

        return ret

    def _directory_as_html(self, filepath):
        "returns directory's index as html"
        # sanity check
        assert filepath.is_dir()

        posix_dir_len = len(self._directory.as_posix())

        # remove the beginning of posix path, so it would be relative
        # to our added static path
        relative_path_to_dir = filepath.as_posix()[posix_dir_len:]
        index_of = "Index of /{}".format(relative_path_to_dir)
        head = "<head>\n<title>{}</title>\n</head>".format(index_of)
        h1 = "<h1>{}</h1>".format(index_of)

        index_list = []
        dir_index = filepath.iterdir()
        for _file in sorted(dir_index):
            # show file url as relative to static path
            file_url = _file.as_posix()[posix_dir_len:]

            # if file is a directory, add '/' to the end of the name
            if _file.is_dir():
                file_name = "{}/".format(_file.name)
            else:
                file_name = _file.name

            index_list.append(
                '<li><a href="{url}">{name}</a></li>'.format(url=file_url,
                                                             name=file_name)
            )
        ul = "<ul>\n{}\n</ul>".format('\n'.join(index_list))
        body = "<body>\n{}\n{}\n</body>".format(h1, ul)

        html = "<html>\n{}\n{}\n</html>".format(head, body)

        return html

    def __repr__(self):
        name = "'" + self.name + "'" if self.name is not None else ""
        return "<StaticResource {name} {path} -> {directory!r}".format(
            name=name, path=self._prefix, directory=self._directory)


class PrefixedSubAppResource(PrefixResource):

    def __init__(self, prefix, app):
        super().__init__(prefix)
        self._app = app
        for resource in app.router.resources():
            resource.add_prefix(prefix)

    def add_prefix(self, prefix):
        super().add_prefix(prefix)
        for resource in self._app.router.resources():
            resource.add_prefix(prefix)

    def url_for(self, *args, **kwargs):
        raise RuntimeError(".url_for() is not supported "
                           "by sub-application root")

    def url(self, **kwargs):
        """Construct url for route with additional params."""
        raise RuntimeError(".url() is not supported "
                           "by sub-application root")

    def get_info(self):
        return {'app': self._app,
                'prefix': self._prefix}

    @asyncio.coroutine
    def resolve(self, request):
        if not request.url.raw_path.startswith(self._prefix):
            return None, set()
        match_info = yield from self._app.router.resolve(request)
        match_info.add_app(self._app)
        if isinstance(match_info.http_exception, HTTPMethodNotAllowed):
            methods = match_info.http_exception.allowed_methods
        else:
            methods = set()
        return (match_info, methods)

    def __len__(self):
        return len(self._app.router.routes())

    def __iter__(self):
        return iter(self._app.router.routes())

    def __repr__(self):
        return "<PrefixedSubAppResource {prefix} -> {app!r}>".format(
            prefix=self._prefix, app=self._app)


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

    def url_for(self, *args, **kwargs):
        """Construct url for route with additional params."""
        return self._resource.url_for(*args, **kwargs)

    def url(self, **kwargs):
        """Construct url for route with additional params."""
        super().url(**kwargs)
        return self._resource.url(**kwargs)

    def get_info(self):
        return self._resource.get_info()


class SystemRoute(AbstractRoute):

    def __init__(self, http_exception):
        super().__init__(hdrs.METH_ANY, self._handler)
        self._http_exception = http_exception

    def url_for(self, *args, **kwargs):
        raise RuntimeError(".url_for() is not allowed for SystemRoute")

    def url(self, *args, **kwargs):
        raise RuntimeError(".url() is not allowed for SystemRoute")

    @property
    def name(self):
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

    DYN = re.compile(r'\{(?P<var>[_a-zA-Z][_a-zA-Z0-9]*)\}')
    DYN_WITH_RE = re.compile(
        r'\{(?P<var>[_a-zA-Z][_a-zA-Z0-9]*):(?P<re>.+)\}')
    GOOD = r'[^{}/]+'
    ROUTE_RE = re.compile(r'(\{[_a-zA-Z][^{}]*(?:\{[^{}]*\}[^{}]*)*\})')
    NAME_SPLIT_RE = re.compile(r'[.:-]')

    def __init__(self):
        super().__init__()
        self._resources = []
        self._named_resources = {}

    @asyncio.coroutine
    def resolve(self, request):
        method = request.method
        allowed_methods = set()

        for resource in self._resources:
            match_dict, allowed = yield from resource.resolve(request)
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

    def register_resource(self, resource):
        assert isinstance(resource, AbstractResource), \
            'Instance of AbstractResource class is required, got {!r}'.format(
                resource)
        if self.frozen:
            raise RuntimeError(
                "Cannot register a resource into frozen router.")

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
        if path and not path.startswith('/'):
            raise ValueError("path should be started with / or be empty")
        if not ('{' in path or '}' in path or self.ROUTE_RE.search(path)):
            url = URL(path)
            resource = PlainResource(url.raw_path, name=name)
            self.register_resource(resource)
            return resource

        pattern = ''
        formatter = ''
        for part in self.ROUTE_RE.split(path):
            match = self.DYN.fullmatch(part)
            if match:
                pattern += '(?P<{}>{})'.format(match.group('var'), self.GOOD)
                formatter += '{' + match.group('var') + '}'
                continue

            match = self.DYN_WITH_RE.fullmatch(part)
            if match:
                pattern += '(?P<{var}>{re})'.format(**match.groupdict())
                formatter += '{' + match.group('var') + '}'
                continue

            if '{' in part or '}' in part:
                raise ValueError("Invalid path '{}'['{}']".format(path, part))

            path = URL(part).raw_path
            formatter += path
            pattern += re.escape(path)

        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            raise ValueError(
                "Bad pattern '{}': {}".format(pattern, exc)) from None
        resource = DynamicResource(compiled, formatter, name=name)
        self.register_resource(resource)
        return resource

    def add_route(self, method, path, handler,
                  *, name=None, expect_handler=None):
        resource = self.add_resource(path, name=name)
        return resource.add_route(method, handler,
                                  expect_handler=expect_handler)

    def add_static(self, prefix, path, *, name=None, expect_handler=None,
                   chunk_size=256*1024, response_factory=StreamResponse,
                   show_index=False, follow_symlinks=False):
        """Add static files view.

        prefix - url prefix
        path - folder with files

        """
        # TODO: implement via PrefixedResource, not ResourceAdapter
        assert prefix.startswith('/')
        if prefix.endswith('/'):
            prefix = prefix[:-1]
        resource = StaticResource(prefix, path,
                                  name=name,
                                  expect_handler=expect_handler,
                                  chunk_size=chunk_size,
                                  response_factory=response_factory,
                                  show_index=show_index,
                                  follow_symlinks=follow_symlinks)
        self.register_resource(resource)
        return resource

    def add_head(self, *args, **kwargs):
        """
        Shortcut for add_route with method HEAD
        """
        return self.add_route(hdrs.METH_HEAD, *args, **kwargs)

    def add_get(self, *args, name=None, allow_head=True, **kwargs):
        """
        Shortcut for add_route with method GET, if allow_head is true another
        route is added allowing head requests to the same endpoint
        """
        if allow_head:
            # the head route can't have "name" set or it would conflict with
            # the GET route below
            self.add_route(hdrs.METH_HEAD, *args, **kwargs)
        return self.add_route(hdrs.METH_GET, *args, name=name, **kwargs)

    def add_post(self, *args, **kwargs):
        """
        Shortcut for add_route with method POST
        """
        return self.add_route(hdrs.METH_POST, *args, **kwargs)

    def add_put(self, *args, **kwargs):
        """
        Shortcut for add_route with method PUT
        """
        return self.add_route(hdrs.METH_PUT, *args, **kwargs)

    def add_patch(self, *args, **kwargs):
        """
        Shortcut for add_route with method PATCH
        """
        return self.add_route(hdrs.METH_PATCH, *args, **kwargs)

    def add_delete(self, *args, **kwargs):
        """
        Shortcut for add_route with method DELETE
        """
        return self.add_route(hdrs.METH_DELETE, *args, **kwargs)

    def freeze(self):
        super().freeze()
        for resource in self._resources:
            resource.freeze()
