import asyncio
import logging
import socket
import sys
from argparse import ArgumentParser
from collections.abc import Iterable
from importlib import import_module
from typing import Any, Awaitable, Callable, List, Optional, Type, Union, cast

from .abc import AbstractAccessLogger
from .helpers import all_tasks
from .log import access_logger
from .web_app import Application as Application
from .web_app import CleanupError as CleanupError
from .web_exceptions import HTTPAccepted as HTTPAccepted
from .web_exceptions import HTTPBadGateway as HTTPBadGateway
from .web_exceptions import HTTPBadRequest as HTTPBadRequest
from .web_exceptions import HTTPClientError as HTTPClientError
from .web_exceptions import HTTPConflict as HTTPConflict
from .web_exceptions import HTTPCreated as HTTPCreated
from .web_exceptions import HTTPError as HTTPError
from .web_exceptions import HTTPException as HTTPException
from .web_exceptions import HTTPExpectationFailed as HTTPExpectationFailed
from .web_exceptions import HTTPFailedDependency as HTTPFailedDependency
from .web_exceptions import HTTPForbidden as HTTPForbidden
from .web_exceptions import HTTPFound as HTTPFound
from .web_exceptions import HTTPGatewayTimeout as HTTPGatewayTimeout
from .web_exceptions import HTTPGone as HTTPGone
from .web_exceptions import HTTPInsufficientStorage as HTTPInsufficientStorage
from .web_exceptions import HTTPInternalServerError as HTTPInternalServerError
from .web_exceptions import HTTPLengthRequired as HTTPLengthRequired
from .web_exceptions import HTTPMethodNotAllowed as HTTPMethodNotAllowed
from .web_exceptions import HTTPMisdirectedRequest as HTTPMisdirectedRequest
from .web_exceptions import HTTPMovedPermanently as HTTPMovedPermanently
from .web_exceptions import HTTPMultipleChoices as HTTPMultipleChoices
from .web_exceptions import (
    HTTPNetworkAuthenticationRequired as HTTPNetworkAuthenticationRequired,
)
from .web_exceptions import HTTPNoContent as HTTPNoContent
from .web_exceptions import (
    HTTPNonAuthoritativeInformation as HTTPNonAuthoritativeInformation,
)
from .web_exceptions import HTTPNotAcceptable as HTTPNotAcceptable
from .web_exceptions import HTTPNotExtended as HTTPNotExtended
from .web_exceptions import HTTPNotFound as HTTPNotFound
from .web_exceptions import HTTPNotImplemented as HTTPNotImplemented
from .web_exceptions import HTTPNotModified as HTTPNotModified
from .web_exceptions import HTTPOk as HTTPOk
from .web_exceptions import HTTPPartialContent as HTTPPartialContent
from .web_exceptions import HTTPPaymentRequired as HTTPPaymentRequired
from .web_exceptions import HTTPPermanentRedirect as HTTPPermanentRedirect
from .web_exceptions import HTTPPreconditionFailed as HTTPPreconditionFailed
from .web_exceptions import (
    HTTPPreconditionRequired as HTTPPreconditionRequired,
)
from .web_exceptions import (
    HTTPProxyAuthenticationRequired as HTTPProxyAuthenticationRequired,
)
from .web_exceptions import HTTPRedirection as HTTPRedirection
from .web_exceptions import (
    HTTPRequestEntityTooLarge as HTTPRequestEntityTooLarge,
)
from .web_exceptions import (
    HTTPRequestHeaderFieldsTooLarge as HTTPRequestHeaderFieldsTooLarge,
)
from .web_exceptions import (
    HTTPRequestRangeNotSatisfiable as HTTPRequestRangeNotSatisfiable,
)
from .web_exceptions import HTTPRequestTimeout as HTTPRequestTimeout
from .web_exceptions import HTTPRequestURITooLong as HTTPRequestURITooLong
from .web_exceptions import HTTPResetContent as HTTPResetContent
from .web_exceptions import HTTPSeeOther as HTTPSeeOther
from .web_exceptions import HTTPServerError as HTTPServerError
from .web_exceptions import HTTPServiceUnavailable as HTTPServiceUnavailable
from .web_exceptions import HTTPSuccessful as HTTPSuccessful
from .web_exceptions import HTTPTemporaryRedirect as HTTPTemporaryRedirect
from .web_exceptions import HTTPTooManyRequests as HTTPTooManyRequests
from .web_exceptions import HTTPUnauthorized as HTTPUnauthorized
from .web_exceptions import (
    HTTPUnavailableForLegalReasons as HTTPUnavailableForLegalReasons,
)
from .web_exceptions import HTTPUnprocessableEntity as HTTPUnprocessableEntity
from .web_exceptions import (
    HTTPUnsupportedMediaType as HTTPUnsupportedMediaType,
)
from .web_exceptions import HTTPUpgradeRequired as HTTPUpgradeRequired
from .web_exceptions import HTTPUseProxy as HTTPUseProxy
from .web_exceptions import (
    HTTPVariantAlsoNegotiates as HTTPVariantAlsoNegotiates,
)
from .web_exceptions import HTTPVersionNotSupported as HTTPVersionNotSupported
from .web_fileresponse import FileResponse as FileResponse
from .web_log import AccessLogger
from .web_middlewares import middleware as middleware
from .web_middlewares import (
    normalize_path_middleware as normalize_path_middleware,
)
from .web_protocol import PayloadAccessError as PayloadAccessError
from .web_protocol import RequestHandler as RequestHandler
from .web_protocol import RequestPayloadError as RequestPayloadError
from .web_request import BaseRequest as BaseRequest
from .web_request import FileField as FileField
from .web_request import Request as Request
from .web_response import ContentCoding as ContentCoding
from .web_response import Response as Response
from .web_response import StreamResponse as StreamResponse
from .web_response import json_response as json_response
from .web_routedef import AbstractRouteDef as AbstractRouteDef
from .web_routedef import RouteDef as RouteDef
from .web_routedef import RouteTableDef as RouteTableDef
from .web_routedef import StaticDef as StaticDef
from .web_routedef import delete as delete
from .web_routedef import get as get
from .web_routedef import head as head
from .web_routedef import options as options
from .web_routedef import patch as patch
from .web_routedef import post as post
from .web_routedef import put as put
from .web_routedef import route as route
from .web_routedef import static as static
from .web_routedef import view as view
from .web_runner import AppRunner as AppRunner
from .web_runner import BaseRunner as BaseRunner
from .web_runner import BaseSite as BaseSite
from .web_runner import GracefulExit as GracefulExit
from .web_runner import NamedPipeSite as NamedPipeSite
from .web_runner import ServerRunner as ServerRunner
from .web_runner import SockSite as SockSite
from .web_runner import TCPSite as TCPSite
from .web_runner import UnixSite as UnixSite
from .web_server import Server as Server
from .web_urldispatcher import AbstractResource as AbstractResource
from .web_urldispatcher import AbstractRoute as AbstractRoute
from .web_urldispatcher import DynamicResource as DynamicResource
from .web_urldispatcher import PlainResource as PlainResource
from .web_urldispatcher import Resource as Resource
from .web_urldispatcher import ResourceRoute as ResourceRoute
from .web_urldispatcher import StaticResource as StaticResource
from .web_urldispatcher import UrlDispatcher as UrlDispatcher
from .web_urldispatcher import UrlMappingMatchInfo as UrlMappingMatchInfo
from .web_urldispatcher import View as View
from .web_ws import WebSocketReady as WebSocketReady
from .web_ws import WebSocketResponse as WebSocketResponse
from .web_ws import WSMsgType as WSMsgType

__all__ = (
    # web_app
    'Application',
    'CleanupError',
    # web_exceptions
    'HTTPAccepted',
    'HTTPBadGateway',
    'HTTPBadRequest',
    'HTTPClientError',
    'HTTPConflict',
    'HTTPCreated',
    'HTTPError',
    'HTTPException',
    'HTTPExpectationFailed',
    'HTTPFailedDependency',
    'HTTPForbidden',
    'HTTPFound',
    'HTTPGatewayTimeout',
    'HTTPGone',
    'HTTPInsufficientStorage',
    'HTTPInternalServerError',
    'HTTPLengthRequired',
    'HTTPMethodNotAllowed',
    'HTTPMisdirectedRequest',
    'HTTPMovedPermanently',
    'HTTPMultipleChoices',
    'HTTPNetworkAuthenticationRequired',
    'HTTPNoContent',
    'HTTPNonAuthoritativeInformation',
    'HTTPNotAcceptable',
    'HTTPNotExtended',
    'HTTPNotFound',
    'HTTPNotImplemented',
    'HTTPNotModified',
    'HTTPOk',
    'HTTPPartialContent',
    'HTTPPaymentRequired',
    'HTTPPermanentRedirect',
    'HTTPPreconditionFailed',
    'HTTPPreconditionRequired',
    'HTTPProxyAuthenticationRequired',
    'HTTPRedirection',
    'HTTPRequestEntityTooLarge',
    'HTTPRequestHeaderFieldsTooLarge',
    'HTTPRequestRangeNotSatisfiable',
    'HTTPRequestTimeout',
    'HTTPRequestURITooLong',
    'HTTPResetContent',
    'HTTPSeeOther',
    'HTTPServerError',
    'HTTPServiceUnavailable',
    'HTTPSuccessful',
    'HTTPTemporaryRedirect',
    'HTTPTooManyRequests',
    'HTTPUnauthorized',
    'HTTPUnavailableForLegalReasons',
    'HTTPUnprocessableEntity',
    'HTTPUnsupportedMediaType',
    'HTTPUpgradeRequired',
    'HTTPUseProxy',
    'HTTPVariantAlsoNegotiates',
    'HTTPVersionNotSupported',
    # web_fileresponse
    'FileResponse',
    # web_middlewares
    'middleware',
    'normalize_path_middleware',
    # web_protocol
    'PayloadAccessError',
    'RequestHandler',
    'RequestPayloadError',
    # web_request
    'BaseRequest',
    'FileField',
    'Request',
    # web_response
    'ContentCoding',
    'Response',
    'StreamResponse',
    'json_response',
    # web_routedef
    'AbstractRouteDef',
    'RouteDef',
    'RouteTableDef',
    'StaticDef',
    'delete',
    'get',
    'head',
    'options',
    'patch',
    'post',
    'put',
    'route',
    'static',
    'view',
    # web_runner
    'AppRunner',
    'BaseRunner',
    'BaseSite',
    'GracefulExit',
    'ServerRunner',
    'SockSite',
    'TCPSite',
    'UnixSite',
    'NamedPipeSite',
    # web_server
    'Server',
    # web_urldispatcher
    'AbstractResource',
    'AbstractRoute',
    'DynamicResource',
    'PlainResource',
    'Resource',
    'ResourceRoute',
    'StaticResource',
    'UrlDispatcher',
    'UrlMappingMatchInfo',
    'View',
    # web_ws
    'WebSocketReady',
    'WebSocketResponse',
    'WSMsgType',
    # web
    'run_app',
)


try:
    from ssl import SSLContext
except ImportError:  # pragma: no cover
    SSLContext = Any  # type: ignore


async def _run_app(app: Union[Application, Awaitable[Application]], *,
                   host: Optional[str]=None,
                   port: Optional[int]=None,
                   path: Optional[str]=None,
                   sock: Optional[socket.socket]=None,
                   shutdown_timeout: float=60.0,
                   ssl_context: Optional[SSLContext]=None,
                   print: Callable[..., None]=print,
                   backlog: int=128,
                   access_log_class: Type[AbstractAccessLogger]=AccessLogger,
                   access_log_format: str=AccessLogger.LOG_FORMAT,
                   access_log: Optional[logging.Logger]=access_logger,
                   handle_signals: bool=True,
                   reuse_address: Optional[bool]=None,
                   reuse_port: Optional[bool]=None) -> None:
    # A internal functio to actually do all dirty job for application running
    if asyncio.iscoroutine(app):
        app = await app  # type: ignore

    app = cast(Application, app)

    runner = AppRunner(app, handle_signals=handle_signals,
                       access_log_class=access_log_class,
                       access_log_format=access_log_format,
                       access_log=access_log)

    await runner.setup()

    sites = []  # type: List[BaseSite]

    try:
        if host is not None:
            if isinstance(host, (str, bytes, bytearray, memoryview)):
                sites.append(TCPSite(runner, host, port,
                                     shutdown_timeout=shutdown_timeout,
                                     ssl_context=ssl_context,
                                     backlog=backlog,
                                     reuse_address=reuse_address,
                                     reuse_port=reuse_port))
            else:
                for h in host:
                    sites.append(TCPSite(runner, h, port,
                                         shutdown_timeout=shutdown_timeout,
                                         ssl_context=ssl_context,
                                         backlog=backlog,
                                         reuse_address=reuse_address,
                                         reuse_port=reuse_port))
        elif path is None and sock is None or port is not None:
            sites.append(TCPSite(runner, port=port,
                                 shutdown_timeout=shutdown_timeout,
                                 ssl_context=ssl_context, backlog=backlog,
                                 reuse_address=reuse_address,
                                 reuse_port=reuse_port))

        if path is not None:
            if isinstance(path, (str, bytes, bytearray, memoryview)):
                sites.append(UnixSite(runner, path,
                                      shutdown_timeout=shutdown_timeout,
                                      ssl_context=ssl_context,
                                      backlog=backlog))
            else:
                for p in path:
                    sites.append(UnixSite(runner, p,
                                          shutdown_timeout=shutdown_timeout,
                                          ssl_context=ssl_context,
                                          backlog=backlog))

        if sock is not None:
            if not isinstance(sock, Iterable):
                sites.append(SockSite(runner, sock,
                                      shutdown_timeout=shutdown_timeout,
                                      ssl_context=ssl_context,
                                      backlog=backlog))
            else:
                for s in sock:
                    sites.append(SockSite(runner, s,
                                          shutdown_timeout=shutdown_timeout,
                                          ssl_context=ssl_context,
                                          backlog=backlog))
        for site in sites:
            await site.start()

        if print:  # pragma: no branch
            names = sorted(str(s.name) for s in runner.sites)
            print("======== Running on {} ========\n"
                  "(Press CTRL+C to quit)".format(', '.join(names)))
        while True:
            await asyncio.sleep(3600)  # sleep forever by 1 hour intervals
    finally:
        await runner.cleanup()


def _cancel_all_tasks(loop: asyncio.AbstractEventLoop) -> None:
    to_cancel = all_tasks(loop)
    if not to_cancel:
        return

    for task in to_cancel:
        task.cancel()

    loop.run_until_complete(
        asyncio.gather(*to_cancel, loop=loop, return_exceptions=True))

    for task in to_cancel:
        if task.cancelled():
            continue
        if task.exception() is not None:
            loop.call_exception_handler({
                'message': 'unhandled exception during asyncio.run() shutdown',
                'exception': task.exception(),
                'task': task,
            })


def run_app(app: Union[Application, Awaitable[Application]], *,
            host: Optional[str]=None,
            port: Optional[int]=None,
            path: Optional[str]=None,
            sock: Optional[socket.socket]=None,
            shutdown_timeout: float=60.0,
            ssl_context: Optional[SSLContext]=None,
            print: Callable[..., None]=print,
            backlog: int=128,
            access_log_class: Type[AbstractAccessLogger]=AccessLogger,
            access_log_format: str=AccessLogger.LOG_FORMAT,
            access_log: Optional[logging.Logger]=access_logger,
            handle_signals: bool=True,
            reuse_address: Optional[bool]=None,
            reuse_port: Optional[bool]=None) -> None:
    """Run an app locally"""
    loop = asyncio.get_event_loop()

    # Configure if and only if in debugging mode and using the default logger
    if loop.get_debug() and access_log and access_log.name == 'aiohttp.access':
        if access_log.level == logging.NOTSET:
            access_log.setLevel(logging.DEBUG)
        if not access_log.hasHandlers():
            access_log.addHandler(logging.StreamHandler())

    try:
        loop.run_until_complete(_run_app(app,
                                         host=host,
                                         port=port,
                                         path=path,
                                         sock=sock,
                                         shutdown_timeout=shutdown_timeout,
                                         ssl_context=ssl_context,
                                         print=print,
                                         backlog=backlog,
                                         access_log_class=access_log_class,
                                         access_log_format=access_log_format,
                                         access_log=access_log,
                                         handle_signals=handle_signals,
                                         reuse_address=reuse_address,
                                         reuse_port=reuse_port))
    except (GracefulExit, KeyboardInterrupt):  # pragma: no cover
        pass
    finally:
        _cancel_all_tasks(loop)
        if sys.version_info >= (3, 6):  # don't use PY_36 to pass mypy
            loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()


def main(argv: List[str]) -> None:
    arg_parser = ArgumentParser(
        description="aiohttp.web Application server",
        prog="aiohttp.web"
    )
    arg_parser.add_argument(
        "entry_func",
        help=("Callable returning the `aiohttp.web.Application` instance to "
              "run. Should be specified in the 'module:function' syntax."),
        metavar="entry-func"
    )
    arg_parser.add_argument(
        "-H", "--hostname",
        help="TCP/IP hostname to serve on (default: %(default)r)",
        default="localhost"
    )
    arg_parser.add_argument(
        "-P", "--port",
        help="TCP/IP port to serve on (default: %(default)r)",
        type=int,
        default="8080"
    )
    arg_parser.add_argument(
        "-U", "--path",
        help="Unix file system path to serve on. Specifying a path will cause "
             "hostname and port arguments to be ignored.",
    )
    args, extra_argv = arg_parser.parse_known_args(argv)

    # Import logic
    mod_str, _, func_str = args.entry_func.partition(":")
    if not func_str or not mod_str:
        arg_parser.error(
            "'entry-func' not in 'module:function' syntax"
        )
    if mod_str.startswith("."):
        arg_parser.error("relative module names not supported")
    try:
        module = import_module(mod_str)
    except ImportError as ex:
        arg_parser.error("unable to import %s: %s" % (mod_str, ex))
    try:
        func = getattr(module, func_str)
    except AttributeError:
        arg_parser.error("module %r has no attribute %r" % (mod_str, func_str))

    # Compatibility logic
    if args.path is not None and not hasattr(socket, 'AF_UNIX'):
        arg_parser.error("file system paths not supported by your operating"
                         " environment")

    logging.basicConfig(level=logging.DEBUG)

    app = func(extra_argv)
    run_app(app, host=args.hostname, port=args.port, path=args.path)
    arg_parser.exit(message="Stopped\n")


if __name__ == "__main__":  # pragma: no branch
    main(sys.argv[1:])  # pragma: no cover
