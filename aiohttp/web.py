import asyncio
import logging
import socket
import sys
from argparse import ArgumentParser
from collections.abc import Iterable
from importlib import import_module
from typing import Any, Awaitable, Callable, List, Optional, Type, Union, cast

from . import (web_app, web_exceptions, web_fileresponse, web_middlewares,
               web_protocol, web_request, web_response, web_routedef,
               web_runner, web_server, web_urldispatcher, web_ws)
from .abc import AbstractAccessLogger
from .helpers import all_tasks
from .log import access_logger
from .web_app import CleanupError  # noqa
from .web_app import Application
from .web_exceptions import HTTPAccepted  # noqa
from .web_exceptions import HTTPBadGateway  # noqa
from .web_exceptions import HTTPBadRequest  # noqa
from .web_exceptions import HTTPClientError  # noqa
from .web_exceptions import HTTPConflict  # noqa
from .web_exceptions import HTTPCreated  # noqa
from .web_exceptions import HTTPError  # noqa
from .web_exceptions import HTTPException  # noqa
from .web_exceptions import HTTPExpectationFailed  # noqa
from .web_exceptions import HTTPFailedDependency  # noqa
from .web_exceptions import HTTPForbidden  # noqa
from .web_exceptions import HTTPFound  # noqa
from .web_exceptions import HTTPGatewayTimeout  # noqa
from .web_exceptions import HTTPGone  # noqa
from .web_exceptions import HTTPInsufficientStorage  # noqa
from .web_exceptions import HTTPInternalServerError  # noqa
from .web_exceptions import HTTPLengthRequired  # noqa
from .web_exceptions import HTTPMethodNotAllowed  # noqa
from .web_exceptions import HTTPMisdirectedRequest  # noqa
from .web_exceptions import HTTPMovedPermanently  # noqa
from .web_exceptions import HTTPMultipleChoices  # noqa
from .web_exceptions import HTTPNetworkAuthenticationRequired  # noqa
from .web_exceptions import HTTPNoContent  # noqa
from .web_exceptions import HTTPNonAuthoritativeInformation  # noqa
from .web_exceptions import HTTPNotAcceptable  # noqa
from .web_exceptions import HTTPNotExtended  # noqa
from .web_exceptions import HTTPNotFound  # noqa
from .web_exceptions import HTTPNotImplemented  # noqa
from .web_exceptions import HTTPNotModified  # noqa
from .web_exceptions import HTTPOk  # noqa
from .web_exceptions import HTTPPartialContent  # noqa
from .web_exceptions import HTTPPaymentRequired  # noqa
from .web_exceptions import HTTPPermanentRedirect  # noqa
from .web_exceptions import HTTPPreconditionFailed  # noqa
from .web_exceptions import HTTPPreconditionRequired  # noqa
from .web_exceptions import HTTPProxyAuthenticationRequired  # noqa
from .web_exceptions import HTTPRedirection  # noqa
from .web_exceptions import HTTPRequestEntityTooLarge  # noqa
from .web_exceptions import HTTPRequestHeaderFieldsTooLarge  # noqa
from .web_exceptions import HTTPRequestRangeNotSatisfiable  # noqa
from .web_exceptions import HTTPRequestTimeout  # noqa
from .web_exceptions import HTTPRequestURITooLong  # noqa
from .web_exceptions import HTTPResetContent  # noqa
from .web_exceptions import HTTPSeeOther  # noqa
from .web_exceptions import HTTPServerError  # noqa
from .web_exceptions import HTTPServiceUnavailable  # noqa
from .web_exceptions import HTTPSuccessful  # noqa
from .web_exceptions import HTTPTemporaryRedirect  # noqa
from .web_exceptions import HTTPTooManyRequests  # noqa
from .web_exceptions import HTTPUnauthorized  # noqa
from .web_exceptions import HTTPUnavailableForLegalReasons  # noqa
from .web_exceptions import HTTPUnprocessableEntity  # noqa
from .web_exceptions import HTTPUnsupportedMediaType  # noqa
from .web_exceptions import HTTPUpgradeRequired  # noqa
from .web_exceptions import HTTPUseProxy  # noqa
from .web_exceptions import HTTPVariantAlsoNegotiates  # noqa
from .web_exceptions import HTTPVersionNotSupported  # noqa
from .web_fileresponse import FileResponse  # noqa
from .web_log import AccessLogger
from .web_middlewares import middleware, normalize_path_middleware  # noqa
from .web_protocol import PayloadAccessError  # noqa
from .web_protocol import RequestHandler  # noqa
from .web_protocol import RequestPayloadError  # noqa
from .web_request import BaseRequest, FileField, Request  # noqa
from .web_response import ContentCoding  # noqa
from .web_response import Response  # noqa
from .web_response import StreamResponse  # noqa
from .web_response import json_response  # noqa
from .web_routedef import AbstractRouteDef  # noqa
from .web_routedef import RouteDef  # noqa
from .web_routedef import RouteTableDef  # noqa
from .web_routedef import StaticDef  # noqa
from .web_routedef import delete  # noqa
from .web_routedef import get  # noqa
from .web_routedef import head  # noqa
from .web_routedef import options  # noqa
from .web_routedef import patch  # noqa
from .web_routedef import post  # noqa
from .web_routedef import put  # noqa
from .web_routedef import route  # noqa
from .web_routedef import static  # noqa
from .web_routedef import view  # noqa
from .web_runner import (AppRunner, BaseRunner, BaseSite, GracefulExit,  # noqa
                         ServerRunner, SockSite, TCPSite, UnixSite)
from .web_server import Server  # noqa
from .web_urldispatcher import AbstractResource  # noqa
from .web_urldispatcher import AbstractRoute  # noqa
from .web_urldispatcher import DynamicResource  # noqa
from .web_urldispatcher import PlainResource  # noqa
from .web_urldispatcher import Resource  # noqa
from .web_urldispatcher import ResourceRoute  # noqa
from .web_urldispatcher import StaticResource  # noqa
from .web_urldispatcher import UrlDispatcher  # noqa
from .web_urldispatcher import UrlMappingMatchInfo  # noqa
from .web_urldispatcher import View  # noqa
from .web_ws import WebSocketReady  # noqa
from .web_ws import WebSocketResponse  # noqa
from .web_ws import WSMsgType  # noqa


__all__ = (web_protocol.__all__ +
           web_app.__all__ +
           web_fileresponse.__all__ +
           web_request.__all__ +
           web_response.__all__ +
           web_routedef.__all__ +
           web_exceptions.__all__ +
           web_urldispatcher.__all__ +
           web_ws.__all__ +
           web_server.__all__ +
           web_runner.__all__ +
           web_middlewares.__all__ +
           ('run_app', 'BaseSite', 'TCPSite', 'UnixSite',
            'SockSite', 'BaseRunner',
            'AppRunner', 'ServerRunner', 'GracefulExit'))


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
                   access_log: logging.Logger=access_logger,
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
            access_log: logging.Logger=access_logger,
            handle_signals: bool=True,
            reuse_address: Optional[bool]=None,
            reuse_port: Optional[bool]=None) -> None:
    """Run an app locally"""
    loop = asyncio.get_event_loop()

    # Configure if and only if in debugging mode and using the default logger
    if loop.get_debug() and access_log.name == 'aiohttp.access':
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
