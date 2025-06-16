import asyncio
import logging
import warnings
from functools import lru_cache, partial, update_wrapper
from typing import (
    TYPE_CHECKING,
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
    final,
    overload,
)

from aiosignal import Signal
from frozenlist import FrozenList

from . import hdrs
from .helpers import AppKey
from .log import web_logger
from .typedefs import Handler, Middleware
from .web_exceptions import NotAppKeyWarning
from .web_middlewares import _fix_request_current_app
from .web_request import Request
from .web_response import StreamResponse
from .web_routedef import AbstractRouteDef
from .web_urldispatcher import (
    AbstractResource,
    AbstractRoute,
    Domain,
    MaskDomain,
    MatchedSubAppResource,
    PrefixedSubAppResource,
    SystemRoute,
    UrlDispatcher,
)

__all__ = ("Application", "CleanupError")


if TYPE_CHECKING:
    _AppSignal = Signal[Callable[["Application"], Awaitable[None]]]
    _RespPrepareSignal = Signal[Callable[[Request, StreamResponse], Awaitable[None]]]
    _Middlewares = FrozenList[Middleware]
    _MiddlewaresHandlers = Sequence[Middleware]
    _Subapps = List["Application"]
else:
    # No type checker mode, skip types
    _AppSignal = Signal
    _RespPrepareSignal = Signal
    _Handler = Callable
    _Middlewares = FrozenList
    _MiddlewaresHandlers = Sequence
    _Subapps = List

_T = TypeVar("_T")
_U = TypeVar("_U")
_Resource = TypeVar("_Resource", bound=AbstractResource)


def _build_middlewares(
    handler: Handler, apps: Tuple["Application", ...]
) -> Callable[[Request], Awaitable[StreamResponse]]:
    """Apply middlewares to handler."""
    # The slice is to reverse the order of the apps
    # so they are applied in the order they were added
    for app in apps[::-1]:
        assert app.pre_frozen, "middleware handlers are not ready"
        for m in app._middlewares_handlers:
            handler = update_wrapper(partial(m, handler=handler), handler)
    return handler


_cached_build_middleware = lru_cache(maxsize=1024)(_build_middlewares)


@final
class Application(MutableMapping[Union[str, AppKey[Any]], Any]):
    __slots__ = (
        "logger",
        "_router",
        "_loop",
        "_handler_args",
        "_middlewares",
        "_middlewares_handlers",
        "_run_middlewares",
        "_state",
        "_frozen",
        "_pre_frozen",
        "_subapps",
        "_on_response_prepare",
        "_on_startup",
        "_on_shutdown",
        "_on_cleanup",
        "_client_max_size",
        "_cleanup_ctx",
    )

    def __init__(
        self,
        *,
        logger: logging.Logger = web_logger,
        middlewares: Iterable[Middleware] = (),
        handler_args: Optional[Mapping[str, Any]] = None,
        client_max_size: int = 1024**2,
        debug: Any = ...,  # mypy doesn't support ellipsis
    ) -> None:
        if debug is not ...:
            warnings.warn(
                "debug argument is no-op since 4.0 and scheduled for removal in 5.0",
                DeprecationWarning,
                stacklevel=2,
            )
        self._router = UrlDispatcher()
        self._handler_args = handler_args
        self.logger = logger

        self._middlewares: _Middlewares = FrozenList(middlewares)

        # initialized on freezing
        self._middlewares_handlers: _MiddlewaresHandlers = tuple()
        # initialized on freezing
        self._run_middlewares: Optional[bool] = None

        self._state: Dict[Union[AppKey[Any], str], object] = {}
        self._frozen = False
        self._pre_frozen = False
        self._subapps: _Subapps = []

        self._on_response_prepare: _RespPrepareSignal = Signal(self)
        self._on_startup: _AppSignal = Signal(self)
        self._on_shutdown: _AppSignal = Signal(self)
        self._on_cleanup: _AppSignal = Signal(self)
        self._cleanup_ctx = CleanupContext()
        self._on_startup.append(self._cleanup_ctx._on_startup)
        self._on_cleanup.append(self._cleanup_ctx._on_cleanup)
        self._client_max_size = client_max_size

    def __init_subclass__(cls: Type["Application"]) -> None:
        raise TypeError(
            "Inheritance class {} from web.Application "
            "is forbidden".format(cls.__name__)
        )

    # MutableMapping API

    def __eq__(self, other: object) -> bool:
        return self is other

    @overload  # type: ignore[override]
    def __getitem__(self, key: AppKey[_T]) -> _T: ...

    @overload
    def __getitem__(self, key: str) -> Any: ...

    def __getitem__(self, key: Union[str, AppKey[_T]]) -> Any:
        return self._state[key]

    def _check_frozen(self) -> None:
        if self._frozen:
            raise RuntimeError(
                "Changing state of started or joined application is forbidden"
            )

    @overload  # type: ignore[override]
    def __setitem__(self, key: AppKey[_T], value: _T) -> None: ...

    @overload
    def __setitem__(self, key: str, value: Any) -> None: ...

    def __setitem__(self, key: Union[str, AppKey[_T]], value: Any) -> None:
        self._check_frozen()
        if not isinstance(key, AppKey):
            warnings.warn(
                "It is recommended to use web.AppKey instances for keys.\n"
                + "https://docs.aiohttp.org/en/stable/web_advanced.html"
                + "#application-s-config",
                category=NotAppKeyWarning,
                stacklevel=2,
            )
        self._state[key] = value

    def __delitem__(self, key: Union[str, AppKey[_T]]) -> None:
        self._check_frozen()
        del self._state[key]

    def __len__(self) -> int:
        return len(self._state)

    def __iter__(self) -> Iterator[Union[str, AppKey[Any]]]:
        return iter(self._state)

    def __hash__(self) -> int:
        return id(self)

    @overload  # type: ignore[override]
    def get(self, key: AppKey[_T], default: None = ...) -> Optional[_T]: ...

    @overload
    def get(self, key: AppKey[_T], default: _U) -> Union[_T, _U]: ...

    @overload
    def get(self, key: str, default: Any = ...) -> Any: ...

    def get(self, key: Union[str, AppKey[_T]], default: Any = None) -> Any:
        return self._state.get(key, default)

    ########
    def _set_loop(self, loop: Optional[asyncio.AbstractEventLoop]) -> None:
        warnings.warn(
            "_set_loop() is no-op since 4.0 and scheduled for removal in 5.0",
            DeprecationWarning,
            stacklevel=2,
        )

    @property
    def pre_frozen(self) -> bool:
        return self._pre_frozen

    def pre_freeze(self) -> None:
        if self._pre_frozen:
            return

        self._pre_frozen = True
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
            subapp.pre_freeze()
            self._run_middlewares = self._run_middlewares or subapp._run_middlewares

    @property
    def frozen(self) -> bool:
        return self._frozen

    def freeze(self) -> None:
        if self._frozen:
            return

        self.pre_freeze()
        self._frozen = True
        for subapp in self._subapps:
            subapp.freeze()

    @property
    def debug(self) -> bool:
        warnings.warn(
            "debug property is deprecated since 4.0 and scheduled for removal in 5.0",
            DeprecationWarning,
            stacklevel=2,
        )
        return asyncio.get_event_loop().get_debug()

    def _reg_subapp_signals(self, subapp: "Application") -> None:
        def reg_handler(signame: str) -> None:
            subsig = getattr(subapp, signame)

            async def handler(app: "Application") -> None:
                await subsig.send(subapp)

            appsig = getattr(self, signame)
            appsig.append(handler)

        reg_handler("on_startup")
        reg_handler("on_shutdown")
        reg_handler("on_cleanup")

    def add_subapp(self, prefix: str, subapp: "Application") -> PrefixedSubAppResource:
        if not isinstance(prefix, str):
            raise TypeError("Prefix must be str")
        prefix = prefix.rstrip("/")
        if not prefix:
            raise ValueError("Prefix cannot be empty")
        factory = partial(PrefixedSubAppResource, prefix, subapp)
        return self._add_subapp(factory, subapp)

    def _add_subapp(
        self, resource_factory: Callable[[], _Resource], subapp: "Application"
    ) -> _Resource:
        if self.frozen:
            raise RuntimeError("Cannot add sub application to frozen application")
        if subapp.frozen:
            raise RuntimeError("Cannot add frozen application")
        resource = resource_factory()
        self.router.register_resource(resource)
        self._reg_subapp_signals(subapp)
        self._subapps.append(subapp)
        subapp.pre_freeze()
        return resource

    def add_domain(self, domain: str, subapp: "Application") -> MatchedSubAppResource:
        if not isinstance(domain, str):
            raise TypeError("Domain must be str")
        elif "*" in domain:
            rule: Domain = MaskDomain(domain)
        else:
            rule = Domain(domain)
        factory = partial(MatchedSubAppResource, rule, subapp)
        return self._add_subapp(factory, subapp)

    def add_routes(self, routes: Iterable[AbstractRouteDef]) -> List[AbstractRoute]:
        return self.router.add_routes(routes)

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
    def cleanup_ctx(self) -> "CleanupContext":
        return self._cleanup_ctx

    @property
    def router(self) -> UrlDispatcher:
        return self._router

    @property
    def middlewares(self) -> _Middlewares:
        return self._middlewares

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
        if self.on_cleanup.frozen:
            await self.on_cleanup.send(self)
        else:
            # If an exception occurs in startup, ensure cleanup contexts are completed.
            await self._cleanup_ctx._on_cleanup(self)

    def _prepare_middleware(self) -> Iterator[Middleware]:
        yield from reversed(self._middlewares)
        yield _fix_request_current_app(self)

    async def _handle(self, request: Request) -> StreamResponse:
        match_info = await self._router.resolve(request)
        match_info.add_app(self)
        match_info.freeze()

        request._match_info = match_info

        if request.headers.get(hdrs.EXPECT):
            resp = await match_info.expect_handler(request)
            await request.writer.drain()
            if resp is not None:
                return resp

        handler = match_info.handler

        if self._run_middlewares:
            # If its a SystemRoute, don't cache building the middlewares since
            # they are constructed for every MatchInfoError as a new handler
            # is made each time.
            if isinstance(match_info.route, SystemRoute):
                handler = _build_middlewares(handler, match_info.apps)
            else:
                handler = _cached_build_middleware(handler, match_info.apps)

        return await handler(request)

    def __call__(self) -> "Application":
        """gunicorn compatibility"""
        return self

    def __repr__(self) -> str:
        return f"<Application 0x{id(self):x}>"

    def __bool__(self) -> bool:
        return True


class CleanupError(RuntimeError):
    @property
    def exceptions(self) -> List[BaseException]:
        return cast(List[BaseException], self.args[1])


if TYPE_CHECKING:
    _CleanupContextBase = FrozenList[Callable[[Application], AsyncIterator[None]]]
else:
    _CleanupContextBase = FrozenList


class CleanupContext(_CleanupContextBase):
    def __init__(self) -> None:
        super().__init__()
        self._exits: List[AsyncIterator[None]] = []

    async def _on_startup(self, app: Application) -> None:
        for cb in self:
            it = cb(app).__aiter__()
            await it.__anext__()
            self._exits.append(it)

    async def _on_cleanup(self, app: Application) -> None:
        errors = []
        for it in reversed(self._exits):
            try:
                await it.__anext__()
            except StopAsyncIteration:
                pass
            except (Exception, asyncio.CancelledError) as exc:
                errors.append(exc)
            else:
                errors.append(RuntimeError(f"{it!r} has more than one 'yield'"))
        if errors:
            if len(errors) == 1:
                raise errors[0]
            else:
                raise CleanupError("Multiple errors on cleanup stage", errors)
