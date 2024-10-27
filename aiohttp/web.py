import asyncio
import contextvars
import enum
import functools
import logging
import os
import signal
import socket
import sys
import threading
import warnings
from argparse import ArgumentParser
from asyncio import Task, constants, coroutines, events, exceptions, tasks
from collections.abc import Iterable
from importlib import import_module
from types import FrameType, TracebackType
from typing import (
    Any,
    Awaitable,
    Callable,
    Iterable as TypingIterable,
    List,
    Optional,
    Set,
    Type,
    Union,
    cast,
    final,
)

from .abc import AbstractAccessLogger
from .helpers import AppKey
from .log import access_logger
from .typedefs import PathLike
from .web_app import Application, CleanupError
from .web_exceptions import (
    HTTPAccepted,
    HTTPBadGateway,
    HTTPBadRequest,
    HTTPClientError,
    HTTPConflict,
    HTTPCreated,
    HTTPError,
    HTTPException,
    HTTPExpectationFailed,
    HTTPFailedDependency,
    HTTPForbidden,
    HTTPFound,
    HTTPGatewayTimeout,
    HTTPGone,
    HTTPInsufficientStorage,
    HTTPInternalServerError,
    HTTPLengthRequired,
    HTTPMethodNotAllowed,
    HTTPMisdirectedRequest,
    HTTPMove,
    HTTPMovedPermanently,
    HTTPMultipleChoices,
    HTTPNetworkAuthenticationRequired,
    HTTPNoContent,
    HTTPNonAuthoritativeInformation,
    HTTPNotAcceptable,
    HTTPNotExtended,
    HTTPNotFound,
    HTTPNotImplemented,
    HTTPNotModified,
    HTTPOk,
    HTTPPartialContent,
    HTTPPaymentRequired,
    HTTPPermanentRedirect,
    HTTPPreconditionFailed,
    HTTPPreconditionRequired,
    HTTPProxyAuthenticationRequired,
    HTTPRedirection,
    HTTPRequestEntityTooLarge,
    HTTPRequestHeaderFieldsTooLarge,
    HTTPRequestRangeNotSatisfiable,
    HTTPRequestTimeout,
    HTTPRequestURITooLong,
    HTTPResetContent,
    HTTPSeeOther,
    HTTPServerError,
    HTTPServiceUnavailable,
    HTTPSuccessful,
    HTTPTemporaryRedirect,
    HTTPTooManyRequests,
    HTTPUnauthorized,
    HTTPUnavailableForLegalReasons,
    HTTPUnprocessableEntity,
    HTTPUnsupportedMediaType,
    HTTPUpgradeRequired,
    HTTPUseProxy,
    HTTPVariantAlsoNegotiates,
    HTTPVersionNotSupported,
    NotAppKeyWarning,
)
from .web_fileresponse import FileResponse
from .web_log import AccessLogger
from .web_middlewares import middleware, normalize_path_middleware
from .web_protocol import PayloadAccessError, RequestHandler, RequestPayloadError
from .web_request import BaseRequest, FileField, Request
from .web_response import ContentCoding, Response, StreamResponse, json_response
from .web_routedef import (
    AbstractRouteDef,
    RouteDef,
    RouteTableDef,
    StaticDef,
    delete,
    get,
    head,
    options,
    patch,
    post,
    put,
    route,
    static,
    view,
)
from .web_runner import (
    AppRunner,
    BaseRunner,
    BaseSite,
    GracefulExit,
    NamedPipeSite,
    ServerRunner,
    SockSite,
    TCPSite,
    UnixSite,
)
from .web_server import Server
from .web_urldispatcher import (
    AbstractResource,
    AbstractRoute,
    DynamicResource,
    PlainResource,
    PrefixedSubAppResource,
    Resource,
    ResourceRoute,
    StaticResource,
    UrlDispatcher,
    UrlMappingMatchInfo,
    View,
)
from .web_ws import WebSocketReady, WebSocketResponse, WSMsgType

__all__ = (
    # web_app
    "AppKey",
    "Application",
    "CleanupError",
    # web_exceptions
    "NotAppKeyWarning",
    "HTTPAccepted",
    "HTTPBadGateway",
    "HTTPBadRequest",
    "HTTPClientError",
    "HTTPConflict",
    "HTTPCreated",
    "HTTPError",
    "HTTPException",
    "HTTPExpectationFailed",
    "HTTPFailedDependency",
    "HTTPForbidden",
    "HTTPFound",
    "HTTPGatewayTimeout",
    "HTTPGone",
    "HTTPInsufficientStorage",
    "HTTPInternalServerError",
    "HTTPLengthRequired",
    "HTTPMethodNotAllowed",
    "HTTPMisdirectedRequest",
    "HTTPMove",
    "HTTPMovedPermanently",
    "HTTPMultipleChoices",
    "HTTPNetworkAuthenticationRequired",
    "HTTPNoContent",
    "HTTPNonAuthoritativeInformation",
    "HTTPNotAcceptable",
    "HTTPNotExtended",
    "HTTPNotFound",
    "HTTPNotImplemented",
    "HTTPNotModified",
    "HTTPOk",
    "HTTPPartialContent",
    "HTTPPaymentRequired",
    "HTTPPermanentRedirect",
    "HTTPPreconditionFailed",
    "HTTPPreconditionRequired",
    "HTTPProxyAuthenticationRequired",
    "HTTPRedirection",
    "HTTPRequestEntityTooLarge",
    "HTTPRequestHeaderFieldsTooLarge",
    "HTTPRequestRangeNotSatisfiable",
    "HTTPRequestTimeout",
    "HTTPRequestURITooLong",
    "HTTPResetContent",
    "HTTPSeeOther",
    "HTTPServerError",
    "HTTPServiceUnavailable",
    "HTTPSuccessful",
    "HTTPTemporaryRedirect",
    "HTTPTooManyRequests",
    "HTTPUnauthorized",
    "HTTPUnavailableForLegalReasons",
    "HTTPUnprocessableEntity",
    "HTTPUnsupportedMediaType",
    "HTTPUpgradeRequired",
    "HTTPUseProxy",
    "HTTPVariantAlsoNegotiates",
    "HTTPVersionNotSupported",
    # web_fileresponse
    "FileResponse",
    # web_middlewares
    "middleware",
    "normalize_path_middleware",
    # web_protocol
    "PayloadAccessError",
    "RequestHandler",
    "RequestPayloadError",
    # web_request
    "BaseRequest",
    "FileField",
    "Request",
    # web_response
    "ContentCoding",
    "Response",
    "StreamResponse",
    "json_response",
    # web_routedef
    "AbstractRouteDef",
    "RouteDef",
    "RouteTableDef",
    "StaticDef",
    "delete",
    "get",
    "head",
    "options",
    "patch",
    "post",
    "put",
    "route",
    "static",
    "view",
    # web_runner
    "AppRunner",
    "BaseRunner",
    "BaseSite",
    "GracefulExit",
    "ServerRunner",
    "SockSite",
    "TCPSite",
    "UnixSite",
    "NamedPipeSite",
    # web_server
    "Server",
    # web_urldispatcher
    "AbstractResource",
    "AbstractRoute",
    "DynamicResource",
    "PlainResource",
    "PrefixedSubAppResource",
    "Resource",
    "ResourceRoute",
    "StaticResource",
    "UrlDispatcher",
    "UrlMappingMatchInfo",
    "View",
    # web_ws
    "WebSocketReady",
    "WebSocketResponse",
    "WSMsgType",
    # web
    "run_app",
    "Runner",
)

try:
    from ssl import SSLContext
except ImportError:  # pragma: no cover
    SSLContext = Any  # type: ignore[misc,assignment]

# Only display warning when using -Wdefault, -We, -X dev or similar.
warnings.filterwarnings("ignore", category=NotAppKeyWarning, append=True)

HostSequence = TypingIterable[str]


class _State(enum.Enum):
    CREATED = "created"
    INITIALIZED = "initialized"
    CLOSED = "closed"


@final
class Runner:
    """A context manager that controls event loop life cycle"""

    def __init__(
        self,
        *,
        debug: Optional[bool] = None,
        loop_factory: Optional[Callable[[], asyncio.AbstractEventLoop]] = None,
    ):
        self._state = _State.CREATED
        self._debug = debug
        self._loop_factory = loop_factory
        self._loop = None
        self._context = None
        self._interrupt_count = 0
        self._set_event_loop = False

    def __enter__(self) -> "Runner":
        self._lazy_init()
        return self

    def __exit__(
        self,
        exc_type: Optional[type],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self.close()

    def close(self) -> None:
        """Shutdown and close event loop."""
        if self._state is not _State.INITIALIZED:
            return
        loop = self._loop
        try:
            _cancel_tasks(tasks.all_tasks(loop), loop)
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.run_until_complete(
                loop.shutdown_default_executor(constants.THREAD_JOIN_TIMEOUT)
            )
        finally:
            if self._set_event_loop:
                events.set_event_loop(None)
            loop.close()
            self._loop = None
            self._state = _State.CLOSED

    def get_loop(self) -> asyncio.AbstractEventLoop:
        """Return embedded event loop."""
        self._lazy_init()
        return self._loop

    def run(
        self, coro: Awaitable, *, context: Optional[contextvars.Context] = None
    ) -> Any:
        """Run a coroutine inside the embedded event loop."""
        if not coroutines.iscoroutine(coro):
            raise ValueError(f"a coroutine was expected, got {coro!r}")

        if events._get_running_loop() is not None:
            # fail fast with short traceback
            raise RuntimeError(
                "Runner.run() cannot be called from a running event loop"
            )

        self._lazy_init()

        if context is None:
            context = self._context
        task = self._loop.create_task(coro, context=context)

        if (
            threading.current_thread() is threading.main_thread()
            and signal.getsignal(signal.SIGINT) is signal.default_int_handler
        ):
            sigint_handler = functools.partial(self._on_sigint, main_task=task)
            try:
                signal.signal(signal.SIGINT, sigint_handler)
            except ValueError:
                # `signal.signal` may throw if `threading.main_thread` does
                # not support signals (e.g. embedded interpreter with signals
                # not registered - see gh-91880)
                sigint_handler = None
        else:
            sigint_handler = None

        self._interrupt_count = 0
        try:
            return self._loop.run_until_complete(task)
        except exceptions.CancelledError:
            if self._interrupt_count > 0:
                uncancel = getattr(task, "uncancel", None)
                if uncancel is not None and uncancel() == 0:
                    raise KeyboardInterrupt()
            raise  # CancelledError
        finally:
            if (
                sigint_handler is not None
                and signal.getsignal(signal.SIGINT) is sigint_handler
            ):
                signal.signal(signal.SIGINT, signal.default_int_handler)

    def run_app(
        self,
        app: Union[Application, Awaitable[Application]],
        *,
        host: Optional[Union[str, HostSequence]] = None,
        port: Optional[int] = None,
        path: Union[PathLike, TypingIterable[PathLike], None] = None,
        sock: Optional[Union[socket.socket, TypingIterable[socket.socket]]] = None,
        shutdown_timeout: float = 60.0,
        keepalive_timeout: float = 75.0,
        ssl_context: Optional[SSLContext] = None,
        print: Optional[Callable[..., None]] = print,
        backlog: int = 128,
        access_log_class: Type[AbstractAccessLogger] = AccessLogger,
        access_log_format: str = AccessLogger.LOG_FORMAT,
        access_log: Optional[logging.Logger] = access_logger,
        handle_signals: bool = True,
        reuse_address: Optional[bool] = None,
        reuse_port: Optional[bool] = None,
        handler_cancellation: bool = False,
    ) -> None:
        """Run an app locally"""
        self._lazy_init()

        if (
            self._loop.get_debug()
            and access_log
            and access_log.name == "aiohttp.access"
        ):
            if access_log.level == logging.NOTSET:
                access_log.setLevel(logging.DEBUG)
            if not access_log.hasHandlers():
                access_log.addHandler(logging.StreamHandler())

        main_task = self._loop.create_task(
            _run_app(
                app,
                host=host,
                port=port,
                path=path,
                sock=sock,
                shutdown_timeout=shutdown_timeout,
                keepalive_timeout=keepalive_timeout,
                ssl_context=ssl_context,
                print=print,
                backlog=backlog,
                access_log_class=access_log_class,
                access_log_format=access_log_format,
                access_log=access_log,
                handle_signals=handle_signals,
                reuse_address=reuse_address,
                reuse_port=reuse_port,
                handler_cancellation=handler_cancellation,
            )
        )

        try:
            if self._set_event_loop:
                asyncio.set_event_loop(self._loop)
            self._loop.run_until_complete(main_task)
        except (GracefulExit, KeyboardInterrupt):  # pragma: no cover
            pass
        finally:
            _cancel_tasks({main_task}, self._loop)
            _cancel_tasks(asyncio.all_tasks(self._loop), self._loop)
            self._loop.run_until_complete(self._loop.shutdown_asyncgens())
            self.close()
            asyncio.set_event_loop(None)

    def _lazy_init(self) -> None:
        if self._state is _State.CLOSED:
            raise RuntimeError("Runner is closed")
        if self._state is _State.INITIALIZED:
            return
        if self._loop_factory is None:
            self._loop = events.new_event_loop()
            if not self._set_event_loop:
                # Call set_event_loop only once to avoid calling
                # attach_loop multiple times on child watchers
                events.set_event_loop(self._loop)
                self._set_event_loop = True
        else:
            try:
                self._loop = self._loop_factory()
            except RuntimeError:
                self._loop = events.new_event_loop()
                events.set_event_loop(self._loop)
                self._set_event_loop = True
        if self._debug is not None:
            self._loop.set_debug(self._debug)
        self._context = contextvars.copy_context()
        self._state = _State.INITIALIZED

    def _on_sigint(
        self, signum: int, frame: Optional[FrameType], main_task: Task
    ) -> None:
        self._interrupt_count += 1
        if self._interrupt_count == 1 and not main_task.done():
            main_task.cancel()
            # wakeup loop if it is blocked by select() with long timeout
            self._loop.call_soon_threadsafe(lambda: None)
            return
        raise KeyboardInterrupt()


async def _run_app(
    app: Union[Application, Awaitable[Application]],
    *,
    host: Optional[Union[str, HostSequence]] = None,
    port: Optional[int] = None,
    path: Union[PathLike, TypingIterable[PathLike], None] = None,
    sock: Optional[Union[socket.socket, TypingIterable[socket.socket]]] = None,
    shutdown_timeout: float = 60.0,
    keepalive_timeout: float = 75.0,
    ssl_context: Optional[SSLContext] = None,
    print: Optional[Callable[..., None]] = print,
    backlog: int = 128,
    access_log_class: Type[AbstractAccessLogger] = AccessLogger,
    access_log_format: str = AccessLogger.LOG_FORMAT,
    access_log: Optional[logging.Logger] = access_logger,
    handle_signals: bool = True,
    reuse_address: Optional[bool] = None,
    reuse_port: Optional[bool] = None,
    handler_cancellation: bool = False,
) -> None:
    # An internal function to actually do all dirty job for application running
    if asyncio.iscoroutine(app):
        app = await app

    app = cast(Application, app)

    runner = AppRunner(
        app,
        handle_signals=handle_signals,
        access_log_class=access_log_class,
        access_log_format=access_log_format,
        access_log=access_log,
        keepalive_timeout=keepalive_timeout,
        shutdown_timeout=shutdown_timeout,
        handler_cancellation=handler_cancellation,
    )

    await runner.setup()

    sites: List[BaseSite] = []

    try:
        if host is not None:
            if isinstance(host, (str, bytes, bytearray, memoryview)):
                sites.append(
                    TCPSite(
                        runner,
                        host,
                        port,
                        ssl_context=ssl_context,
                        backlog=backlog,
                        reuse_address=reuse_address,
                        reuse_port=reuse_port,
                    )
                )
            else:
                for h in host:
                    sites.append(
                        TCPSite(
                            runner,
                            h,
                            port,
                            ssl_context=ssl_context,
                            backlog=backlog,
                            reuse_address=reuse_address,
                            reuse_port=reuse_port,
                        )
                    )
        elif path is None and sock is None or port is not None:
            sites.append(
                TCPSite(
                    runner,
                    port=port,
                    ssl_context=ssl_context,
                    backlog=backlog,
                    reuse_address=reuse_address,
                    reuse_port=reuse_port,
                )
            )

        if path is not None:
            if isinstance(path, (str, os.PathLike)):
                sites.append(
                    UnixSite(
                        runner,
                        path,
                        ssl_context=ssl_context,
                        backlog=backlog,
                    )
                )
            else:
                for p in path:
                    sites.append(
                        UnixSite(
                            runner,
                            p,
                            ssl_context=ssl_context,
                            backlog=backlog,
                        )
                    )

        if sock is not None:
            if not isinstance(sock, Iterable):
                sites.append(
                    SockSite(
                        runner,
                        sock,
                        ssl_context=ssl_context,
                        backlog=backlog,
                    )
                )
            else:
                for s in sock:
                    sites.append(
                        SockSite(
                            runner,
                            s,
                            ssl_context=ssl_context,
                            backlog=backlog,
                        )
                    )
        for site in sites:
            await site.start()

        if print:  # pragma: no branch
            names = sorted(str(s.name) for s in runner.sites)
            print(
                "======== Running on {} ========\n"
                "(Press CTRL+C to quit)".format(", ".join(names))
            )

        # sleep forever by 1 hour intervals,
        while True:
            await asyncio.sleep(3600)
    finally:
        await runner.cleanup()


def _cancel_tasks(
    to_cancel: Set["asyncio.Task[Any]"], loop: asyncio.AbstractEventLoop
) -> None:
    if not to_cancel:
        return

    for task in to_cancel:
        task.cancel()

    loop.run_until_complete(asyncio.gather(*to_cancel, return_exceptions=True))

    for task in to_cancel:
        if task.cancelled():
            continue
        if task.exception() is not None:
            loop.call_exception_handler(
                {
                    "message": "unhandled exception during asyncio.run() shutdown",
                    "exception": task.exception(),
                    "task": task,
                }
            )


def run_app(
    app: Union[Application, Awaitable[Application]],
    *,
    debug: bool = False,
    host: Optional[Union[str, HostSequence]] = None,
    port: Optional[int] = None,
    path: Union[PathLike, TypingIterable[PathLike], None] = None,
    sock: Optional[Union[socket.socket, TypingIterable[socket.socket]]] = None,
    shutdown_timeout: float = 60.0,
    keepalive_timeout: float = 75.0,
    ssl_context: Optional[SSLContext] = None,
    print: Optional[Callable[..., None]] = print,
    backlog: int = 128,
    access_log_class: Type[AbstractAccessLogger] = AccessLogger,
    access_log_format: str = AccessLogger.LOG_FORMAT,
    access_log: Optional[logging.Logger] = access_logger,
    handle_signals: bool = True,
    reuse_address: Optional[bool] = None,
    reuse_port: Optional[bool] = None,
    handler_cancellation: bool = False,
    loop: Optional[asyncio.AbstractEventLoop] = None,
) -> None:
    """Run an app locally"""
    if loop is not None:

        def loop_factory():
            return loop

    else:
        loop_factory = events.get_running_loop
    with Runner(debug=debug, loop_factory=loop_factory) as runner:
        runner.run_app(
            app,
            host=host,
            port=port,
            path=path,
            sock=sock,
            shutdown_timeout=shutdown_timeout,
            keepalive_timeout=keepalive_timeout,
            ssl_context=ssl_context,
            print=print,
            backlog=backlog,
            access_log_class=access_log_class,
            access_log_format=access_log_format,
            access_log=access_log,
            handle_signals=handle_signals,
            reuse_address=reuse_address,
            reuse_port=reuse_port,
            handler_cancellation=handler_cancellation,
        )


def main(argv: List[str]) -> None:
    arg_parser = ArgumentParser(
        description="aiohttp.web Application server", prog="aiohttp.web"
    )
    arg_parser.add_argument(
        "entry_func",
        help=(
            "Callable returning the `aiohttp.web.Application` instance to "
            "run. Should be specified in the 'module:function' syntax."
        ),
        metavar="entry-func",
    )
    arg_parser.add_argument(
        "-H",
        "--hostname",
        help="TCP/IP hostname to serve on (default: %(default)r)",
        default="localhost",
    )
    arg_parser.add_argument(
        "-P",
        "--port",
        help="TCP/IP port to serve on (default: %(default)r)",
        type=int,
        default="8080",
    )
    arg_parser.add_argument(
        "-U",
        "--path",
        help="Unix file system path to serve on. Specifying a path will cause "
        "hostname and port arguments to be ignored.",
    )
    args, extra_argv = arg_parser.parse_known_args(argv)

    # Import logic
    mod_str, _, func_str = args.entry_func.partition(":")
    if not func_str or not mod_str:
        arg_parser.error("'entry-func' not in 'module:function' syntax")
    if mod_str.startswith("."):
        arg_parser.error("relative module names not supported")
    try:
        module = import_module(mod_str)
    except ImportError as ex:
        arg_parser.error(f"unable to import {mod_str}: {ex}")
    try:
        func = getattr(module, func_str)
    except AttributeError:
        arg_parser.error(f"module {mod_str!r} has no attribute {func_str!r}")

    # Compatibility logic
    if args.path is not None and not hasattr(socket, "AF_UNIX"):
        arg_parser.error(
            "file system paths not supported by your operating" " environment"
        )

    logging.basicConfig(level=logging.DEBUG)

    app = func(extra_argv)
    run_app(app, host=args.hostname, port=args.port, path=args.path)
    arg_parser.exit(message="Stopped\n")


if __name__ == "__main__":  # pragma: no branch
    main(sys.argv[1:])  # pragma: no cover
