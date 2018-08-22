import asyncio
import warnings
from collections import MutableMapping
from functools import partial
from typing import TYPE_CHECKING, Awaitable, Callable

from . import hdrs
from .abc import AbstractAccessLogger, AbstractMatchInfo, AbstractRouter
from .frozenlist import FrozenList
from .helpers import DEBUG, AccessLogger
from .log import web_logger
from .signals import Signal
from .web_middlewares import _fix_request_current_app
from .web_request import Request
from .web_response import StreamResponse
from .web_server import Server
from .web_urldispatcher import (Domain, MaskDomain,
                                MatchedSubAppResource, PrefixedSubAppResource,
                                UrlDispatcher)


__all__ = ('Application', 'CleanupError')


if TYPE_CHECKING:  # pragma: no branch
    _AppSignal = Signal[Callable[['Application'], Awaitable[None]]]
    _RespPrepareSignal = Signal[Callable[[Request, StreamResponse],
                                         Awaitable[None]]]
else:
    # No type checker mode, skip types
    _AppSignal = Signal
    _RespPrepareSignal = Signal


class Application(MutableMapping):
    ATTRS = frozenset([
        'logger', '_debug', '_router', '_loop', '_handler_args',
        '_middlewares', '_middlewares_handlers', '_run_middlewares',
        '_state', '_frozen', '_subapps',
        '_on_response_prepare', '_on_startup', '_on_shutdown',
        '_on_cleanup', '_client_max_size', '_cleanup_ctx'])

    def __init__(self, *,
                 logger=web_logger,
                 router=None,
                 middlewares=(),
                 handler_args=None,
                 client_max_size=1024**2,
                 loop=None,
                 debug=...):
        if router is None:
            router = UrlDispatcher()
        else:
            warnings.warn("router argument is deprecated", DeprecationWarning,
                          stacklevel=2)
        assert isinstance(router, AbstractRouter), router

        if loop is not None:
            warnings.warn("loop argument is deprecated", DeprecationWarning,
                          stacklevel=2)

        self._debug = debug
        self._router = router  # type: UrlDispatcher
        self._loop = loop
        self._handler_args = handler_args
        self.logger = logger

        self._middlewares = FrozenList(middlewares)
        self._middlewares_handlers = None  # initialized on freezing
        self._run_middlewares = None  # initialized on freezing
        self._state = {}
        self._frozen = False
        self._subapps = []

        self._on_response_prepare = Signal(self)  # type: _RespPrepareSignal
        self._on_startup = Signal(self)  # type: _AppSignal
        self._on_shutdown = Signal(self)  # type: _AppSignal
        self._on_cleanup = Signal(self)  # type: _AppSignal
        self._cleanup_ctx = CleanupContext()
        self._on_startup.append(self._cleanup_ctx._on_startup)
        self._on_cleanup.append(self._cleanup_ctx._on_cleanup)
        self._client_max_size = client_max_size

    def __init_subclass__(cls):
        warnings.warn("Inheritance class {} from web.Application "
                      "is discouraged".format(cls.__name__),
                      DeprecationWarning,
                      stacklevel=2)

    if DEBUG:
        def __setattr__(self, name, val):
            if name not in self.ATTRS:
                warnings.warn("Setting custom web.Application.{} attribute "
                              "is discouraged".format(name),
                              DeprecationWarning,
                              stacklevel=2)
            super().__setattr__(name, val)

    # MutableMapping API

    def __eq__(self, other):
        return self is other

    def __getitem__(self, key):
        return self._state[key]

    def _check_frozen(self):
        if self._frozen:
            warnings.warn("Changing state of started or joined "
                          "application is deprecated",
                          DeprecationWarning,
                          stacklevel=3)

    def __setitem__(self, key, value):
        self._check_frozen()
        self._state[key] = value

    def __delitem__(self, key):
        self._check_frozen()
        del self._state[key]

    def __len__(self):
        return len(self._state)

    def __iter__(self):
        return iter(self._state)

    ########
    @property
    def loop(self):
        return self._loop

    def _set_loop(self, loop):
        if loop is None:
            loop = asyncio.get_event_loop()
        if self._loop is not None and self._loop is not loop:
            raise RuntimeError(
                "web.Application instance initialized with different loop")

        self._loop = loop

        # set loop debug
        if self._debug is ...:
            self._debug = loop.get_debug()

        # set loop to sub applications
        for subapp in self._subapps:
            subapp._set_loop(loop)

    @property
    def frozen(self) -> bool:
        return self._frozen

    def freeze(self) -> None:
        if self._frozen:
            return

        self._frozen = True
        self._middlewares.freeze()
        self._router.freeze()
        self._on_response_prepare.freeze()
        self._cleanup_ctx.freeze()
        self._on_startup.freeze()
        self._on_shutdown.freeze()
        self._on_cleanup.freeze()
        self._middlewares_handlers = tuple(self._prepare_middleware())

        # If current app and any subapp do not have middlewares avoid run all
        # of the code footprint that it implies, which have a middleware
        # hardcoded per app that sets up the current_app attribute. If no
        # middlewares are configured the handler will receive the proper
        # current_app without needing all of this code.
        self._run_middlewares = True if self.middlewares else False

        for subapp in self._subapps:
            subapp.freeze()
            self._run_middlewares =\
                self._run_middlewares or subapp._run_middlewares

    @property
    def debug(self) -> bool:
        return self._debug

    def _reg_subapp_signals(self, subapp):

        def reg_handler(signame):
            subsig = getattr(subapp, signame)

            async def handler(app):
                await subsig.send(subapp)
            appsig = getattr(self, signame)
            appsig.append(handler)

        reg_handler('on_startup')
        reg_handler('on_shutdown')
        reg_handler('on_cleanup')

    def add_subapp(self, prefix: str, subapp: 'Application'):
        if not isinstance(prefix, str):
            raise TypeError("Prefix must be str")
        prefix = prefix.rstrip('/')
        if not prefix:
            raise ValueError("Prefix cannot be empty")
        factory = partial(PrefixedSubAppResource, prefix, subapp)
        return self._add_subapp(factory, subapp)

    def _add_subapp(self, resource_factory: Callable, subapp: 'Application'):
        if self.frozen:
            raise RuntimeError(
                "Cannot add sub application to frozen application")
        if subapp.frozen:
            raise RuntimeError("Cannot add frozen application")
        resource = resource_factory()
        self.router.register_resource(resource)
        self._reg_subapp_signals(subapp)
        self._subapps.append(subapp)
        subapp.freeze()
        if self._loop is not None:
            subapp._set_loop(self._loop)
        return resource

    def add_domain(self, domain: str, subapp: 'Application'):
        if not isinstance(domain, str):
            raise TypeError("Domain must be str")
        elif '*' in domain:
            rule = MaskDomain(domain)  # type: Domain
        else:
            rule = Domain(domain)
        factory = partial(MatchedSubAppResource, rule, subapp)
        return self._add_subapp(factory, subapp)

    def add_routes(self, routes):
        self.router.add_routes(routes)

    @property
    def on_response_prepare(self) -> _RespPrepareSignal:
        return self._on_response_prepare

    @property
    def on_startup(self) -> _AppSignal:
        return self._on_startup

    @property
    def on_shutdown(self) -> _AppSignal:
        return self._on_shutdown

    @property
    def on_cleanup(self) -> _AppSignal:
        return self._on_cleanup

    @property
    def cleanup_ctx(self):
        return self._cleanup_ctx

    @property
    def router(self) -> UrlDispatcher:
        return self._router

    @property
    def middlewares(self):
        return self._middlewares

    def _make_handler(self, *,
                      loop=None,
                      access_log_class=AccessLogger,
                      **kwargs):

        if not issubclass(access_log_class, AbstractAccessLogger):
            raise TypeError(
                'access_log_class must be subclass of '
                'aiohttp.abc.AbstractAccessLogger, got {}'.format(
                    access_log_class))

        self._set_loop(loop)
        self.freeze()

        kwargs['debug'] = self.debug
        if self._handler_args:
            for k, v in self._handler_args.items():
                kwargs[k] = v

        return Server(self._handle, request_factory=self._make_request,
                      access_log_class=access_log_class,
                      loop=self.loop, **kwargs)

    def make_handler(self, *,
                     loop=None,
                     access_log_class=AccessLogger,
                     **kwargs):

        warnings.warn("Application.make_handler(...) is deprecated, "
                      "use AppRunner API instead",
                      DeprecationWarning,
                      stacklevel=2)

        return self._make_handler(loop=loop,
                                  access_log_class=access_log_class,
                                  **kwargs)

    async def startup(self) -> None:
        """Causes on_startup signal

        Should be called in the event loop along with the request handler.
        """
        await self.on_startup.send(self)

    async def shutdown(self) -> None:
        """Causes on_shutdown signal

        Should be called before cleanup()
        """
        await self.on_shutdown.send(self)

    async def cleanup(self) -> None:
        """Causes on_cleanup signal

        Should be called after shutdown()
        """
        await self.on_cleanup.send(self)

    def _make_request(self, message, payload, protocol, writer, task,
                      _cls=Request):
        return _cls(
            message, payload, protocol, writer, task,
            self._loop,
            client_max_size=self._client_max_size)

    def _prepare_middleware(self):
        for m in reversed(self._middlewares):
            if getattr(m, '__middleware_version__', None) == 1:
                yield m, True
            else:
                warnings.warn('old-style middleware "{!r}" deprecated, '
                              'see #2252'.format(m),
                              DeprecationWarning, stacklevel=2)
                yield m, False

        yield _fix_request_current_app(self), True

    async def _handle(self, request):
        match_info = await self._router.resolve(request)
        if DEBUG:  # pragma: no cover
            if not isinstance(match_info, AbstractMatchInfo):
                raise TypeError("match_info should be AbstractMAtchInfo "
                                "instance, not {!r}".format(match_info))
        match_info.add_app(self)

        match_info.freeze()

        resp = None
        request._match_info = match_info
        expect = request.headers.get(hdrs.EXPECT)
        if expect:
            resp = await match_info.expect_handler(request)
            await request.writer.drain()

        if resp is None:
            handler = match_info.handler

            if self._run_middlewares:
                for app in match_info.apps[::-1]:
                    for m, new_style in app._middlewares_handlers:
                        if new_style:
                            handler = partial(m, handler=handler)
                        else:
                            handler = await m(app, handler)

            resp = await handler(request)

        if DEBUG:
            if not isinstance(resp, StreamResponse):
                msg = ("Handler {!r} should return response instance, "
                       "got {!r} [middlewares {!r}]").format(
                           match_info.handler, type(resp),
                           [middleware
                            for app in match_info.apps
                            for middleware in app.middlewares])
                raise TypeError(msg)
        return resp

    def __call__(self):
        """gunicorn compatibility"""
        return self

    def __repr__(self):
        return "<Application 0x{:x}>".format(id(self))


class CleanupError(RuntimeError):
    @property
    def exceptions(self):
        return self.args[1]


class CleanupContext(FrozenList):

    def __init__(self):
        super().__init__()
        self._exits = []

    async def _on_startup(self, app):
        for cb in self:
            it = cb(app).__aiter__()
            await it.__anext__()
            self._exits.append(it)

    async def _on_cleanup(self, app):
        errors = []
        for it in reversed(self._exits):
            try:
                await it.__anext__()
            except StopAsyncIteration:
                pass
            except Exception as exc:
                errors.append(exc)
            else:
                errors.append(RuntimeError("{!r} has more than one 'yield'"
                                           .format(it)))
        if errors:
            if len(errors) == 1:
                raise errors[0]
            else:
                raise CleanupError("Multiple errors on cleanup stage", errors)
