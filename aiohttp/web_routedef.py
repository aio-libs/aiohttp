import abc
from collections.abc import Sequence

import attr

from . import hdrs


__all__ = ('RouteDef', 'StaticDef', 'RouteTableDef', 'head', 'get',
           'post', 'patch', 'put', 'delete', 'route', 'view',
           'static')


class AbstractRouteDef(abc.ABC):
    @abc.abstractmethod
    def register(self, router):
        pass  # pragma: no cover


@attr.s(frozen=True, repr=False, slots=True)
class RouteDef(AbstractRouteDef):
    method = attr.ib(type=str)
    path = attr.ib(type=str)
    handler = attr.ib()
    kwargs = attr.ib()

    def __repr__(self):
        info = []
        for name, value in sorted(self.kwargs.items()):
            info.append(", {}={!r}".format(name, value))
        return ("<RouteDef {method} {path} -> {handler.__name__!r}"
                "{info}>".format(method=self.method, path=self.path,
                                 handler=self.handler, info=''.join(info)))

    def register(self, router):
        if self.method in hdrs.METH_ALL:
            reg = getattr(router, 'add_'+self.method.lower())
            reg(self.path, self.handler, **self.kwargs)
        else:
            router.add_route(self.method, self.path, self.handler,
                             **self.kwargs)


@attr.s(frozen=True, repr=False, slots=True)
class StaticDef(AbstractRouteDef):
    prefix = attr.ib(type=str)
    path = attr.ib(type=str)
    kwargs = attr.ib()

    def __repr__(self):
        info = []
        for name, value in sorted(self.kwargs.items()):
            info.append(", {}={!r}".format(name, value))
        return ("<StaticDef {prefix} -> {path}"
                "{info}>".format(prefix=self.prefix, path=self.path,
                                 info=''.join(info)))

    def register(self, router):
        router.add_static(self.prefix, self.path, **self.kwargs)


def route(method, path, handler, **kwargs):
    return RouteDef(method, path, handler, kwargs)


def head(path, handler, **kwargs):
    return route(hdrs.METH_HEAD, path, handler, **kwargs)


def get(path, handler, *, name=None, allow_head=True, **kwargs):
    return route(hdrs.METH_GET, path, handler, name=name,
                 allow_head=allow_head, **kwargs)


def post(path, handler, **kwargs):
    return route(hdrs.METH_POST, path, handler, **kwargs)


def put(path, handler, **kwargs):
    return route(hdrs.METH_PUT, path, handler, **kwargs)


def patch(path, handler, **kwargs):
    return route(hdrs.METH_PATCH, path, handler, **kwargs)


def delete(path, handler, **kwargs):
    return route(hdrs.METH_DELETE, path, handler, **kwargs)


def view(path, handler, **kwargs):
    return route(hdrs.METH_ANY, path, handler, **kwargs)


def static(prefix, path, **kwargs):
    return StaticDef(prefix, path, kwargs)


class RouteTableDef(Sequence):
    """Route definition table"""
    def __init__(self):
        self._items = []

    def __repr__(self):
        return "<RouteTableDef count={}>".format(len(self._items))

    def __getitem__(self, index):
        return self._items[index]

    def __iter__(self):
        return iter(self._items)

    def __len__(self):
        return len(self._items)

    def __contains__(self, item):
        return item in self._items

    def route(self, method, path, **kwargs):
        def inner(handler):
            self._items.append(RouteDef(method, path, handler, kwargs))
            return handler
        return inner

    def head(self, path, **kwargs):
        return self.route(hdrs.METH_HEAD, path, **kwargs)

    def get(self, path, **kwargs):
        return self.route(hdrs.METH_GET, path, **kwargs)

    def post(self, path, **kwargs):
        return self.route(hdrs.METH_POST, path, **kwargs)

    def put(self, path, **kwargs):
        return self.route(hdrs.METH_PUT, path, **kwargs)

    def patch(self, path, **kwargs):
        return self.route(hdrs.METH_PATCH, path, **kwargs)

    def delete(self, path, **kwargs):
        return self.route(hdrs.METH_DELETE, path, **kwargs)

    def view(self, path, **kwargs):
        return self.route(hdrs.METH_ANY, path, **kwargs)

    def static(self, prefix, path, **kwargs):
        self._items.append(StaticDef(prefix, path, kwargs))
