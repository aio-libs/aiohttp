import asyncio
import sys
import warnings
from argparse import ArgumentParser
from collections import MutableMapping
from importlib import import_module

from yarl import URL

from . import hdrs, web_exceptions, web_reqrep, web_urldispatcher, web_ws
from .abc import AbstractMatchInfo, AbstractRouter
from .helpers import FrozenList, TimeService, sentinel
from .log import access_logger, web_logger
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

    _request = None

    def __init__(self, manager, app, router, time_service, *,
                 secure_proxy_ssl_header=None, **kwargs):
        super().__init__(**kwargs)

        self._manager = manager
        self._app = app
        self._router = router
        self._secure_proxy_ssl_header = secure_proxy_ssl_header
        self._time_service = time_service

    def __repr__(self):
        if self._request is None:
            meth = 'none'
            path = 'none'
        else:
            meth = self._request.method
            path = self._request.rel_url.raw_path
        return "<{} {}:{} {}>".format(
            self.__class__.__name__, meth, path,
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

        request = web_reqrep.Request(
            message, payload,
            self.transport, self.reader, self.writer,
            self._time_service,
            secure_proxy_ssl_header=self._secure_proxy_ssl_header)
        self._request = request
        try:
            match_info = yield from self._router.resolve(request)
            assert isinstance(match_info, AbstractMatchInfo), match_info
            match_info.add_app(self._app)
            match_info.freeze()

            resp = None
            request._match_info = match_info
            expect = request.headers.get(hdrs.EXPECT)
            if expect:
                resp = (
                    yield from match_info.expect_handler(request))

            if resp is None:
                handler = match_info.handler
                for app in match_info.apps:
                    for factory in reversed(app.middlewares):
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

        # Restore default state.
        # Should be no-op if server code didn't touch these attributes.
        self.writer.set_tcp_cork(False)
        self.writer.set_tcp_nodelay(True)

        # log access
        if self.access_log:
            self.log_access(message, None, resp_msg, self._loop.time() - now)

        # for repr
        self._request = None


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
        self._time_service = TimeService(self._loop)

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
        self._time_service.stop()

    def __call__(self):
        return self._handler(
            self, self._app, self._router, self._time_service, loop=self._loop,
            secure_proxy_ssl_header=self._secure_proxy_ssl_header,
            **self._kwargs)


class Application(MutableMapping):

    def __init__(self, *, logger=web_logger, loop=None,
                 router=None, handler_factory=RequestHandlerFactory,
                 middlewares=(), debug=False):
        if loop is None:
            loop = asyncio.get_event_loop()
        if router is None:
            router = web_urldispatcher.UrlDispatcher(self)
        assert isinstance(router, AbstractRouter), router

        self._debug = debug
        self._router = router
        self._handler_factory = handler_factory
        self._loop = loop
        self.logger = logger

        self._middlewares = FrozenList(middlewares)
        self._state = {}
        self._frozen = False

        self._on_pre_signal = PreSignal()
        self._on_post_signal = PostSignal()
        self._on_response_prepare = Signal(self)
        self._on_startup = Signal(self)
        self._on_shutdown = Signal(self)
        self._on_cleanup = Signal(self)

    # MutableMapping API

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
    def frozen(self):
        return self._frozen

    def freeze(self):
        if self._frozen:
            return
        self._frozen = True
        self._router.freeze()
        self._middlewares.freeze()
        self._on_pre_signal.freeze()
        self._on_post_signal.freeze()
        self._on_response_prepare.freeze()
        self._on_startup.freeze()
        self._on_shutdown.freeze()
        self._on_cleanup.freeze()

    @property
    def debug(self):
        return self._debug

    def _reg_subapp_signals(self, subapp):

        def reg_handler(signame):
            subsig = getattr(subapp, signame)

            @asyncio.coroutine
            def handler(app):
                yield from subsig.send(subapp)
            appsig = getattr(self, signame)
            appsig.append(handler)

        reg_handler('on_startup')
        reg_handler('on_shutdown')
        reg_handler('on_cleanup')

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
        self.freeze()
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
        return "<Application 0x{:x}>".format(id(self))


def run_app(app, *, host='0.0.0.0', port=None,
            shutdown_timeout=60.0, ssl_context=None,
            print=print, backlog=128, access_log_format=None,
            access_log=access_logger):
    """Run an app locally"""
    if port is None:
        if not ssl_context:
            port = 8080
        else:
            port = 8443

    loop = app.loop

    make_handler_kwargs = dict()
    if access_log_format is not None:
        make_handler_kwargs['access_log_format'] = access_log_format
    handler = app.make_handler(access_log=access_log,
                               **make_handler_kwargs)
    server = loop.create_server(handler, host, port, ssl=ssl_context,
                                backlog=backlog)
    srv, startup_res = loop.run_until_complete(asyncio.gather(server,
                                                              app.startup(),
                                                              loop=loop))

    scheme = 'https' if ssl_context else 'http'
    url = URL('{}://localhost'.format(scheme))
    url = url.with_host(host).with_port(port)
    print("======== Running on {} ========\n"
          "(Press CTRL+C to quit)".format(url))

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
    except ImportError as ex:
        arg_parser.error("unable to import %s: %s" % (mod_str, ex))
    try:
        func = getattr(module, func_str)
    except AttributeError:
        arg_parser.error("module %r has no attribute %r" % (mod_str, func_str))

    app = func(extra_argv)
    run_app(app, host=args.hostname, port=args.port)
    arg_parser.exit(message="Stopped\n")


if __name__ == "__main__":  # pragma: no branch
    main(sys.argv[1:])  # pragma: no cover
