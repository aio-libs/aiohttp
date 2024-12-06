import asyncio
import contextvars
import enum
import logging
import os
import socket
import sys
import warnings
from argparse import ArgumentParser
from asyncio import constants, events, tasks
from collections.abc import Iterable
from contextlib import suppress
from importlib import import_module
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
    "WebRunner",
)

try:
    from ssl import SSLContext
except ImportError:  # pragma: no cover
    SSLContext = Any  # type: ignore[misc,assignment]

# Only display warning when using -Wdefault, -We, -X dev or similar.
warnings.filterwarnings("ignore", category=NotAppKeyWarning, append=True)

HostSequence = TypingIterable[str]

if sys.version_info >= (3, 11):

    class _State(enum.Enum):
        CREATED = "created"
        INITIALIZED = "initialized"
        CLOSED = "closed"

    class WebRunner(asyncio.Runner):  # type: ignore
        """A context manager that controls event loop life cycle"""

        def __init__(
            self,
            *,
            debug: Optional[bool] = None,
            loop_factory: Optional[Callable[[], asyncio.AbstractEventLoop]] = None,
        ):
            super().__init__(debug=debug, loop_factory=loop_factory)

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
                self._loop.run_until_complete(main_task)
            except (GracefulExit, KeyboardInterrupt):  # pragma: no cover
                pass
            finally:
                _cancel_tasks({main_task}, self._loop)
                self.close()

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
            if isinstance(host, str):
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
    if sys.version_info >= (3, 11):
        loop_factory = None if loop is None else lambda: loop
        with WebRunner(debug=debug, loop_factory=loop_factory) as runner:
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
    else:
        if loop is None:
            loop = asyncio.new_event_loop()
        loop.set_debug(debug)

        # Configure if and only if in debugging mode and using the default logger
        if loop.get_debug() and access_log and access_log.name == "aiohttp.access":
            if access_log.level == logging.NOTSET:
                access_log.setLevel(logging.DEBUG)
            if not access_log.hasHandlers():
                access_log.addHandler(logging.StreamHandler())

        main_task = loop.create_task(
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
            asyncio.set_event_loop(loop)
            loop.run_until_complete(main_task)
        except (GracefulExit, KeyboardInterrupt):  # pragma: no cover
            pass
        finally:
            try:
                main_task.cancel()
                with suppress(asyncio.CancelledError):
                    loop.run_until_complete(main_task)
            finally:
                _cancel_tasks(asyncio.all_tasks(loop), loop)
                loop.run_until_complete(loop.shutdown_asyncgens())
                loop.close()
                asyncio.set_event_loop(None)


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
        help="TCP/IP hostname to serve on (default: localhost)",
        default=None,
    )
    arg_parser.add_argument(
        "-P",
        "--port",
        help="TCP/IP port to serve on (default: %(default)r)",
        type=int,
        default=8080,
    )
    arg_parser.add_argument(
        "-U",
        "--path",
        help="Unix file system path to serve on. Can be combined with hostname "
        "to serve on both Unix and TCP.",
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
            "file system paths not supported by your operating environment"
        )

    logging.basicConfig(level=logging.DEBUG)

    if args.path and args.hostname is None:
        host = port = None
    else:
        host = args.hostname or "localhost"
        port = args.port

    app = func(extra_argv)
    run_app(app, host=host, port=port, path=args.path)
    arg_parser.exit(message="Stopped\n")


if __name__ == "__main__":  # pragma: no branch
    main(sys.argv[1:])  # pragma: no cover
