import asyncio
import socket
import sys
from argparse import ArgumentParser
from collections import Iterable
from importlib import import_module

from . import (helpers, web_app, web_exceptions, web_fileresponse,
               web_middlewares, web_protocol, web_request, web_response,
               web_runner, web_server, web_urldispatcher, web_ws)
from .log import access_logger
from .web_app import *  # noqa
from .web_exceptions import *  # noqa
from .web_fileresponse import *  # noqa
from .web_middlewares import *  # noqa
from .web_protocol import *  # noqa
from .web_request import *  # noqa
from .web_response import *  # noqa
from .web_runner import *  # noqa
from .web_runner import AppRunner, GracefulExit, SockSite, TCPSite, UnixSite
from .web_server import *  # noqa
from .web_urldispatcher import *  # noqa
from .web_ws import *  # noqa


__all__ = (web_protocol.__all__ +
           web_app.__all__ +
           web_fileresponse.__all__ +
           web_request.__all__ +
           web_response.__all__ +
           web_exceptions.__all__ +
           web_urldispatcher.__all__ +
           web_ws.__all__ +
           web_server.__all__ +
           web_runner.__all__ +
           web_middlewares.__all__ +
           ('run_app',))


def run_app(app, *, host=None, port=None, path=None, sock=None,
            shutdown_timeout=60.0, ssl_context=None,
            print=print, backlog=128, access_log_class=helpers.AccessLogger,
            access_log_format=helpers.AccessLogger.LOG_FORMAT,
            access_log=access_logger, handle_signals=True,
            reuse_address=None, reuse_port=None):
    """Run an app locally"""
    loop = asyncio.get_event_loop()

    if asyncio.iscoroutine(app):
        app = loop.run_until_complete(app)

    runner = AppRunner(app, handle_signals=handle_signals,
                       access_log_class=access_log_class,
                       access_log_format=access_log_format,
                       access_log=access_log)

    loop.run_until_complete(runner.setup())

    sites = []

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
            loop.run_until_complete(site.start())
        try:
            if print:  # pragma: no branch
                names = sorted(str(s.name) for s in runner.sites)
                print("======== Running on {} ========\n"
                      "(Press CTRL+C to quit)".format(', '.join(names)))
            loop.run_forever()
        except (GracefulExit, KeyboardInterrupt):  # pragma: no cover
            pass
    finally:
        loop.run_until_complete(runner.cleanup())
    if hasattr(loop, 'shutdown_asyncgens'):
        loop.run_until_complete(loop.shutdown_asyncgens())
    loop.close()


def main(argv):
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

    app = func(extra_argv)
    run_app(app, host=args.hostname, port=args.port, path=args.path)
    arg_parser.exit(message="Stopped\n")


if __name__ == "__main__":  # pragma: no branch
    main(sys.argv[1:])  # pragma: no cover
