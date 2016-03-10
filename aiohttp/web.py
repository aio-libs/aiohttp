import asyncio
import warnings
import sys


from . import hdrs
from . import web_reqrep
from . import web_exceptions
from . import web_urldispatcher
from . import web_ws
from .abc import AbstractRouter, AbstractMatchInfo
from .log import web_logger
from .protocol import HttpVersion  # noqa
from .server import ServerHttpProtocol
from .signals import Signal, PreSignal, PostSignal
from .web_reqrep import *  # noqa
from .web_exceptions import *  # noqa
from .web_urldispatcher import *  # noqa
from .web_ws import *  # noqa
from argparse import ArgumentParser
from importlib import import_module


__all__ = (web_reqrep.__all__ +
           web_exceptions.__all__ +
           web_urldispatcher.__all__ +
           web_ws.__all__ +
           ('Application', 'RequestHandler',
            'RequestHandlerFactory', 'HttpVersion'))


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
        self.keep_alive(resp_msg.keep_alive())

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
        self.num_connections = 0

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
    def _connections_cleanup(self):
        sleep = 0.05
        while self._connections:
            yield from asyncio.sleep(sleep, loop=self._loop)
            if sleep < 5:
                sleep = sleep * 2

    @asyncio.coroutine
    def finish_connections(self, timeout=None):
        # try to close connections in 90% of graceful timeout
        timeout90 = None
        if timeout:
            timeout90 = timeout / 100 * 90

        for handler in self._connections.keys():
            handler.closing(timeout=timeout90)

        if timeout:
            try:
                yield from asyncio.wait_for(
                    self._connections_cleanup(), timeout, loop=self._loop)
            except asyncio.TimeoutError:
                self._app.logger.warning(
                    "Not all connections are closed (pending: %d)",
                    len(self._connections))

        for transport in self._connections.values():
            transport.close()

        self._connections.clear()

    def __call__(self):
        self.num_connections += 1
        try:
            return self._handler(
                self, self._app, self._router, loop=self._loop,
                secure_proxy_ssl_header=self._secure_proxy_ssl_header,
                **self._kwargs)
        except:
            web_logger.exception(
                'Can not create request handler: {!r}'.format(self._handler))


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

        for factory in middlewares:
            assert asyncio.iscoroutinefunction(factory), factory
        self._middlewares = list(middlewares)

        self._on_pre_signal = PreSignal()
        self._on_post_signal = PostSignal()
        self._on_response_prepare = Signal(self)
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
        return self._handler_factory(
            self, self.router, loop=self.loop, **kwargs)

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
            print=print):
    """Run an app locally"""
    if port is None:
        if not ssl_context:
            port = 8080
        else:
            port = 8443

    loop = app.loop

    handler = app.make_handler()
    srv = loop.run_until_complete(loop.create_server(handler, host, port,
                                                     ssl=ssl_context))

    scheme = 'https' if ssl_context else 'http'
    prompt = '127.0.0.1' if host == '0.0.0.0' else host
    print("======== Running on {scheme}://{prompt}:{port}/ ========\n"
          "(Press CTRL+C to quit)".format(
              scheme=scheme, prompt=prompt, port=port))

    try:
        loop.run_forever()
    except KeyboardInterrupt:  # pragma: no branch
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

if __name__ == "__main__":
    main(sys.argv[1:])
