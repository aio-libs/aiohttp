import asyncio
import sys
import warnings
from argparse import ArgumentParser
from importlib import import_module

from . import hdrs, web_exceptions, web_reqrep, web_urldispatcher, web_ws
from .abc import AbstractMatchInfo, AbstractRouter
from .helpers import sentinel
from .log import web_logger
from .protocol import HttpVersion  # noqa
from .server import ServerHttpProtocol
from .signals import PostSignal, PreSignal, Signal
from .web_exceptions import *  # noqa
from .web_reqrep import *  # noqa
from .web_urldispatcher import *  # noqa
from .web_ws import *  # noqa


__all__ = (web_reqrep.__all__ +
           web_exceptions.__all__ +
           web_urldispatcher.__all__ +
           web_ws.__all__ +
           ('Application', 'RequestHandler',
            'RequestHandlerFactory', 'HttpVersion',
            'MsgType'))


class RequestHandler(ServerHttpProtocol):

    _meth = 'none'
    _path = 'none'

    def __init__(self, manager, app, router, *,
                 secure_proxy_ssl_header=None, **kwargs):
        super().__init__(**kwargs)

        self._manager = manager
        self._app = app
        self._router = router
        self._middlewares = app.middlewares
        self._secure_proxy_ssl_header = secure_proxy_ssl_header

    def __repr__(self):
        return "<{} {}:{} {}>".format(
            self.__class__.__name__, self._meth, self._path,
            'connected' if self.transport is not None else 'disconnected')

    def connection_made(self, transport):
        super().connection_made(transport)

        self._manager.connection_made(self, transport)

    def connection_lost(self, exc):
        self._manager.connection_lost(self, exc)

        super().connection_lost(exc)

    @asyncio.coroutine
    def handle_request(self, message, payload):
        self._manager._requests_count += 1
        if self.access_log:
            now = self._loop.time()

        app = self._app
        request = web_reqrep.Request(
            app, message, payload,
            self.transport, self.reader, self.writer,
            secure_proxy_ssl_header=self._secure_proxy_ssl_header)
        self._meth = request.method
        self._path = request.path
        try:
            match_info = yield from self._router.resolve(request)

            assert isinstance(match_info, AbstractMatchInfo), match_info

            resp = None
            request._match_info = match_info
            expect = request.headers.get(hdrs.EXPECT)
            if expect:
                resp = (
                    yield from match_info.expect_handler(request))

            if resp is None:
                handler = match_info.handler
                for factory in reversed(self._middlewares):
                    handler = yield from factory(app, handler)
                resp = yield from handler(request)

            assert isinstance(resp, web_reqrep.StreamResponse), \
                ("Handler {!r} should return response instance, "
                 "got {!r} [middlewares {!r}]").format(
                     match_info.handler, type(resp), self._middlewares)
        except web_exceptions.HTTPException as exc:
            resp = exc

        resp_msg = yield from resp.prepare(request)
        yield from resp.write_eof()

        # notify server about keep-alive
        self.keep_alive(resp.keep_alive)

        # log access
        if self.access_log:
            self.log_access(message, None, resp_msg, self._loop.time() - now)

        # for repr
        self._meth = 'none'
        self._path = 'none'


class RequestHandlerFactory:

    def __init__(self, app, router, *,
                 handler=RequestHandler, loop=None,
                 secure_proxy_ssl_header=None, **kwargs):
        self._app = app
        self._router = router
        self._handler = handler
        self._loop = loop
        self._connections = {}
        self._secure_proxy_ssl_header = secure_proxy_ssl_header
        self._kwargs = kwargs
        self._kwargs.setdefault('logger', app.logger)
        self._requests_count = 0

    @property
    def requests_count(self):
        """Number of processed requests."""
        return self._requests_count

    @property
    def secure_proxy_ssl_header(self):
        return self._secure_proxy_ssl_header

    @property
    def connections(self):
        return list(self._connections.keys())

    def connection_made(self, handler, transport):
        self._connections[handler] = transport

    def connection_lost(self, handler, exc=None):
        if handler in self._connections:
            del self._connections[handler]

    @asyncio.coroutine
    def finish_connections(self, timeout=None):
        coros = [conn.shutdown(timeout) for conn in self._connections]
        yield from asyncio.gather(*coros, loop=self._loop)
        self._connections.clear()

    def __call__(self):
        return self._handler(
            self, self._app, self._router, loop=self._loop,
            secure_proxy_ssl_header=self._secure_proxy_ssl_header,
            **self._kwargs)


class Application(dict):

    def __init__(self, *, logger=web_logger, loop=None,
                 router=None, handler_factory=RequestHandlerFactory,
                 middlewares=(), debug=False):
        if loop is None:
            loop = asyncio.get_event_loop()
        if router is None:
            router = web_urldispatcher.UrlDispatcher()
        assert isinstance(router, AbstractRouter), router

        self._debug = debug
        self._router = router
        self._handler_factory = handler_factory
        self._loop = loop
        self.logger = logger

        self._middlewares = list(middlewares)

        self._on_pre_signal = PreSignal()
        self._on_post_signal = PostSignal()
        self._on_response_prepare = Signal(self)
        self._on_startup = Signal(self)
        self._on_shutdown = Signal(self)
        self._on_cleanup = Signal(self)

    @property
    def debug(self):
        return self._debug

    @property
    def on_response_prepare(self):
        return self._on_response_prepare

    @property
    def on_pre_signal(self):
        return self._on_pre_signal

    @property
    def on_post_signal(self):
        return self._on_post_signal

    @property
    def on_startup(self):
        return self._on_startup

    @property
    def on_shutdown(self):
        return self._on_shutdown

    @property
    def on_cleanup(self):
        return self._on_cleanup

    @property
    def router(self):
        return self._router

    @property
    def loop(self):
        return self._loop

    @property
    def middlewares(self):
        return self._middlewares

    def make_handler(self, **kwargs):
        debug = kwargs.pop('debug', sentinel)
        if debug is not sentinel:
            warnings.warn(
                "`debug` parameter is deprecated. "
                "Use Application's debug mode instead", DeprecationWarning)
            if debug != self.debug:
                raise ValueError(
                    "The value of `debug` parameter conflicts with the debug "
                    "settings of the `Application` instance. The "
                    "application's debug mode setting should be used instead "
                    "as a single point to setup a debug mode. For more "
                    "information please check "
                    "http://aiohttp.readthedocs.io/en/stable/"
                    "web_reference.html#aiohttp.web.Application"
                )
        return self._handler_factory(self, self.router, debug=self.debug,
                                     loop=self.loop, **kwargs)

    @asyncio.coroutine
    def startup(self):
        """Causes on_startup signal

        Should be called in the event loop along with the request handler.
        """
        yield from self.on_startup.send(self)

    @asyncio.coroutine
    def shutdown(self):
        """Causes on_shutdown signal

        Should be called before cleanup()
        """
        yield from self.on_shutdown.send(self)

    @asyncio.coroutine
    def cleanup(self):
        """Causes on_cleanup signal

        Should be called after shutdown()
        """
        yield from self.on_cleanup.send(self)

    @asyncio.coroutine
    def finish(self):
        """Finalize an application.

        Deprecated alias for .cleanup()
        """
        warnings.warn("Use .cleanup() instead", DeprecationWarning)
        yield from self.cleanup()

    def register_on_finish(self, func, *args, **kwargs):
        warnings.warn("Use .on_cleanup.append() instead", DeprecationWarning)
        self.on_cleanup.append(lambda app: func(app, *args, **kwargs))

    def copy(self):
        raise NotImplementedError

    def __call__(self):
        """gunicorn compatibility"""
        return self

    def __repr__(self):
        return "<Application>"


def run_app(app, *, host='0.0.0.0', port=None,
            shutdown_timeout=60.0, ssl_context=None,
            print=print, backlog=128):
    """Run an app locally"""
    if port is None:
        if not ssl_context:
            port = 8080
        else:
            port = 8443

    loop = app.loop

    handler = app.make_handler()
    server = loop.create_server(handler, host, port, ssl=ssl_context,
                                backlog=backlog)
    srv, startup_res = loop.run_until_complete(asyncio.gather(server,
                                                              app.startup(),
                                                              loop=loop))

    scheme = 'https' if ssl_context else 'http'
    print("======== Running on {scheme}://{host}:{port}/ ========\n"
          "(Press CTRL+C to quit)".format(
              scheme=scheme, host=host, port=port))

    try:
        loop.run_forever()
    except KeyboardInterrupt:  # pragma: no cover
        pass
    finally:
        srv.close()
        loop.run_until_complete(srv.wait_closed())
        loop.run_until_complete(app.shutdown())
        loop.run_until_complete(handler.finish_connections(shutdown_timeout))
        loop.run_until_complete(app.cleanup())
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
    except ImportError:
        arg_parser.error("module %r not found" % mod_str)
    try:
        func = getattr(module, func_str)
    except AttributeError:
        arg_parser.error("module %r has no attribute %r" % (mod_str, func_str))

    app = func(extra_argv)
    run_app(app, host=args.hostname, port=args.port)
    arg_parser.exit(message="Stopped\n")

if __name__ == "__main__":  # pragma: no branch
    main(sys.argv[1:])  # pragma: no cover
