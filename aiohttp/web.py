import asyncio
import os
import signal
import socket
import stat
import sys
import warnings
from argparse import ArgumentParser
from collections import Iterable, MutableMapping
from functools import partial
from importlib import import_module

from yarl import URL

from . import (hdrs, web_exceptions, web_fileresponse, web_middlewares,
               web_protocol, web_request, web_response, web_server,
               web_urldispatcher, web_ws)
from .abc import AbstractAccessLogger, AbstractMatchInfo, AbstractRouter
from .frozenlist import FrozenList
from .helpers import AccessLogger
from .http import HttpVersion  # noqa
from .log import access_logger, web_logger
from .signals import PostSignal, PreSignal, Signal
from .web_exceptions import *  # noqa
from .web_fileresponse import *  # noqa
from .web_middlewares import *  # noqa
from .web_protocol import *  # noqa
from .web_request import *  # noqa
from .web_response import *  # noqa
from .web_server import Server as WebServer
from .web_urldispatcher import *  # noqa
from .web_urldispatcher import PrefixedSubAppResource
from .web_ws import *  # noqa


__all__ = (web_protocol.__all__ +
           web_fileresponse.__all__ +
           web_request.__all__ +
           web_response.__all__ +
           web_exceptions.__all__ +
           web_urldispatcher.__all__ +
           web_ws.__all__ +
           web_server.__all__ +
           web_middlewares.__all__ +
           ('Application', 'HttpVersion', 'MsgType'))


class Application(MutableMapping):
    def __init__(self, *,
                 logger=web_logger,
                 router=None,
                 middlewares=(),
                 handler_args=None,
                 client_max_size=1024**2,
                 loop=None,
                 debug=...):
        if router is None:
            router = web_urldispatcher.UrlDispatcher()
        assert isinstance(router, AbstractRouter), router

        if loop is not None:
            warnings.warn("loop argument is deprecated", ResourceWarning)

        self._debug = debug
        self._router = router
        self._loop = loop
        self._handler_args = handler_args
        self.logger = logger

        self._middlewares = FrozenList(middlewares)
        self._state = {}
        self._frozen = False
        self._subapps = []

        self._on_pre_signal = PreSignal()
        self._on_post_signal = PostSignal()
        self._on_response_prepare = Signal(self)
        self._on_startup = Signal(self)
        self._on_shutdown = Signal(self)
        self._on_cleanup = Signal(self)
        self._client_max_size = client_max_size

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
    def frozen(self):
        return self._frozen

    def freeze(self):
        if self._frozen:
            return

        self._frozen = True
        self._middlewares = tuple(self._prepare_middleware())
        self._router.freeze()
        self._on_pre_signal.freeze()
        self._on_post_signal.freeze()
        self._on_response_prepare.freeze()
        self._on_startup.freeze()
        self._on_shutdown.freeze()
        self._on_cleanup.freeze()

        for subapp in self._subapps:
            subapp.freeze()

    @property
    def debug(self):
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

    def add_subapp(self, prefix, subapp):
        if self.frozen:
            raise RuntimeError(
                "Cannot add sub application to frozen application")
        if subapp.frozen:
            raise RuntimeError("Cannot add frozen application")
        if prefix.endswith('/'):
            prefix = prefix[:-1]
        if prefix in ('', '/'):
            raise ValueError("Prefix cannot be empty")

        resource = PrefixedSubAppResource(prefix, subapp)
        self.router.register_resource(resource)
        self._reg_subapp_signals(subapp)
        self._subapps.append(subapp)
        if self._loop is not None:
            subapp._set_loop(self._loop)
        return resource

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
    def middlewares(self):
        return self._middlewares

    def make_handler(self, *,
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

        return WebServer(self._handle, request_factory=self._make_request,
                         access_log_class=access_log_class,
                         loop=self.loop, **kwargs)

    async def startup(self):
        """Causes on_startup signal

        Should be called in the event loop along with the request handler.
        """
        await self.on_startup.send(self)

    async def shutdown(self):
        """Causes on_shutdown signal

        Should be called before cleanup()
        """
        await self.on_shutdown.send(self)

    async def cleanup(self):
        """Causes on_cleanup signal

        Should be called after shutdown()
        """
        await self.on_cleanup.send(self)

    def _make_request(self, message, payload, protocol, writer, task,
                      _cls=web_request.Request):
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

    async def _handle(self, request):
        match_info = await self._router.resolve(request)
        assert isinstance(match_info, AbstractMatchInfo), match_info
        match_info.add_app(self)

        if __debug__:
            match_info.freeze()

        resp = None
        request._match_info = match_info
        expect = request.headers.get(hdrs.EXPECT)
        if expect:
            resp = await match_info.expect_handler(request)
            await request.writer.drain()

        if resp is None:
            handler = match_info.handler
            for app in match_info.apps[::-1]:
                for m, new_style in app._middlewares:
                    if new_style:
                        handler = partial(m, handler=handler)
                    else:
                        handler = await m(app, handler)

            resp = await handler(request)

        assert isinstance(resp, web_response.StreamResponse), \
            ("Handler {!r} should return response instance, "
             "got {!r} [middlewares {!r}]").format(
                 match_info.handler, type(resp),
                 [middleware for middleware in app.middlewares
                  for app in match_info.apps])
        return resp

    def __call__(self):
        """gunicorn compatibility"""
        return self

    def __repr__(self):
        return "<Application 0x{:x}>".format(id(self))


class GracefulExit(SystemExit):
    code = 1


def raise_graceful_exit():
    raise GracefulExit()


class Server:
    def __init__(self, *, host=None, port=None, path=None, sock=None,
                 shutdown_timeout=60.0, ssl_context=None, backlog=128,
                 access_log_format=None, access_log=access_logger, loop=None):
        if loop is None:
            loop = asyncio.get_event_loop()
        self.loop = loop
        self._app = app = Application()
        make_handler_kwargs = dict()
        if access_log_format is not None:
            make_handler_kwargs['access_log_format'] = access_log_format
        self._handler = app.make_handler(loop=loop, access_log=access_log,
                                         **make_handler_kwargs)

        self.shutdown_timeout = shutdown_timeout
        self.scheme = scheme = 'https' if ssl_context else 'http'
        self.ssl_context = ssl_context
        self.backlog = backlog
        self.access_log_format = access_log_format
        self.access_log = access_log
        self.base_url = URL('{}://localhost'.format(scheme)).with_port(port)

        if path is None:
            self.paths = ()
        elif isinstance(path, (str, bytes, bytearray, memoryview))\
                or not isinstance(path, Iterable):
            self.paths = (path,)
        else:
            self.paths = path

        if sock is None:
            self.socks = ()
        elif not isinstance(sock, Iterable):
            self.socks = (sock,)
        else:
            self.socks = sock

        if host is None:
            if (self.paths or self.socks) and not port:
                self.hosts = ()
            else:
                self.hosts = ("0.0.0.0",)
        elif isinstance(host, (str, bytes, bytearray, memoryview))\
                or not isinstance(host, Iterable):
            self.hosts = (host,)
        else:
            self.hosts = host

        if self.hosts and port is None:
            self.port = 8443 if ssl_context else 8080

        self._apps = []
        self._servers = None

    def register(self, app, *, prefix="/"):
        self._apps.append(app)
        return self._app.add_subapp(prefix, app)

    def _create_servers(self, handler):
        server_creations = []

        uris = [str(self.base_url.with_host(host)) for host in self.hosts]
        if self.hosts:
            # Multiple hosts bound to same server is available in most loop
            # implementations, but only send multiple if we have multiple.
            host_binding = (
                self.hosts[0] if len(self.hosts) == 1 else self.hosts
            )
            server_creations.append(
                self.loop.create_server(
                    handler, host_binding, self.port, ssl=self.ssl_context,
                    backlog=self.backlog
                )
            )

        for path in self.paths:
            # Most loop implementations don't support multiple paths bound in
            # same server, so create a server for each.
            server_creations.append(
                self.loop.create_unix_server(
                    handler, path, ssl=self.ssl_context, backlog=self.backlog
                )
            )
            uris.append('{}://unix:{}:'.format(self.scheme, path))

            # Clean up prior socket path if stale and not abstract.
            # CPython 3.5.3+'s event loop already does this. See
            # https://github.com/python/asyncio/issues/425
            if path[0] not in (0, '\x00'):  # pragma: no branch
                try:
                    if stat.S_ISSOCK(os.stat(path).st_mode):
                        os.remove(path)
                except FileNotFoundError:
                    pass

        for sock in self.socks:
            server_creations.append(
                self.loop.create_server(
                    handler, sock=sock, ssl=self.ssl_context,
                    backlog=self.backlog
                )
            )

            if hasattr(socket, 'AF_UNIX') and sock.family == socket.AF_UNIX:
                uris.append('{}://unix:{}:'.format(self.scheme,
                                                   sock.getsockname()))
            else:
                host, port = sock.getsockname()
                uris.append(str(self.base_url.with_host(host).with_port(port)))

        self.uris = uris
        return asyncio.gather(*server_creations, loop=self.loop)

    @asyncio.coroutine
    def start(self):
        for app in self._apps:
            yield from app.startup()

        self._servers = yield from self._create_servers(self._handler)

        return self.uris

    @asyncio.coroutine
    def stop(self):
        server_closures = []
        for srv in self._servers:
            srv.close()
            server_closures.append(srv.wait_closed())
        yield from asyncio.gather(*server_closures,
                                  loop=self.loop)

        for app in self._apps:
            yield from app.shutdown()

        yield from self._handler.shutdown(self.shutdown_timeout)

        for app in self._apps:
            yield from app.cleanup()


def run_app(app, *, print=print, handle_signals=True, loop=None, **kwargs):
    """Run an app locally"""
    user_supplied_loop = loop is not None
    if loop is None:
        loop = asyncio.get_event_loop()

    server = Server(loop=loop, **kwargs)
    server.register(app)

    uris = loop.run_until_complete(server.start())

    if handle_signals:
        try:
            loop.add_signal_handler(signal.SIGINT, raise_graceful_exit)
            loop.add_signal_handler(signal.SIGTERM, raise_graceful_exit)
        except NotImplementedError:  # pragma: no cover
            # add_signal_handler is not implemented on Windows
            pass

    try:
        if print:
            print("======== Running on {} ========\n"
                  "(Press CTRL+C to quit)".format(', '.join(uris)))
        loop.run_forever()
    except (GracefulExit, KeyboardInterrupt):  # pragma: no cover
        pass
    finally:
        loop.run_until_complete(server.stop())

    if not user_supplied_loop:
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
