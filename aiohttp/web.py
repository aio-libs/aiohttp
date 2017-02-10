import asyncio
import os
import socket
import stat
import sys
import warnings
from argparse import ArgumentParser
from collections import Iterable, MutableMapping
from importlib import import_module

from yarl import URL

from . import (hdrs, web_exceptions, web_middlewares, web_reqrep, web_server,
               web_urldispatcher, web_ws)
from .abc import AbstractMatchInfo, AbstractRouter
from .helpers import FrozenList, sentinel
from .log import access_logger, web_logger
from .protocol import HttpVersion  # noqa
from .signals import PostSignal, PreSignal, Signal
from .web_exceptions import *  # noqa
from .web_middlewares import *  # noqa
from .web_reqrep import *  # noqa
from .web_server import Server
from .web_urldispatcher import *  # noqa
from .web_urldispatcher import PrefixedSubAppResource
from .web_ws import *  # noqa

__all__ = (web_reqrep.__all__ +
           web_exceptions.__all__ +
           web_urldispatcher.__all__ +
           web_ws.__all__ +
           web_server.__all__ +
           web_middlewares.__all__ +
           ('Application', 'HttpVersion', 'MsgType'))


class Application(MutableMapping):

    def __init__(self, *, logger=web_logger, loop=None,
                 router=None,
                 middlewares=(), debug=...,
                 client_max_size=None):
        if loop is None:
            loop = asyncio.get_event_loop()
        if router is None:
            router = web_urldispatcher.UrlDispatcher()
        assert isinstance(router, AbstractRouter), router

        # backward compatibility until full deprecation
        router.add_subapp = _wrap_add_subbapp(self)

        if debug is ...:
            debug = loop.get_debug()

        self._debug = debug
        self._router = router
        self._secure_proxy_ssl_header = None
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
        self._client_max_size = client_max_size

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
        subapp.freeze()
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
    def loop(self):
        return self._loop

    @property
    def middlewares(self):
        return self._middlewares

    def make_handler(self, *, secure_proxy_ssl_header=None, **kwargs):
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
        self._secure_proxy_ssl_header = secure_proxy_ssl_header
        return Server(self._handle, request_factory=self._make_request,
                      debug=self.debug, loop=self.loop, **kwargs)

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

    def _make_request(self, message, payload, protocol,
                      _cls=web_reqrep.Request):
        return _cls(
            message, payload,
            protocol.transport, protocol.reader, protocol.writer,
            protocol.time_service, protocol._request_handler,
            secure_proxy_ssl_header=self._secure_proxy_ssl_header,
            client_max_size=self._client_max_size)

    @asyncio.coroutine
    def _handle(self, request):
        match_info = yield from self._router.resolve(request)
        assert isinstance(match_info, AbstractMatchInfo), match_info
        match_info.add_app(self)
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
                 match_info.handler, type(resp),
                 [middleware for middleware in app.middlewares
                  for app in match_info.apps])
        return resp

    def __call__(self):
        """gunicorn compatibility"""
        return self

    def __repr__(self):
        return "<Application 0x{:x}>".format(id(self))


def _wrap_add_subbapp(app):
    # backward compatibility

    def add_subapp(prefix, subapp):
        warnings.warn("Use app.add_subapp() instead", DeprecationWarning)
        return app.add_subapp(prefix, subapp)

    return add_subapp


def run_app(app, *, host='0.0.0.0', port=None, path=None,
            shutdown_timeout=60.0, ssl_context=None,
            print=print, backlog=128, access_log_format=None,
            access_log=access_logger):
    """Run an app locally"""
    loop = app.loop

    make_handler_kwargs = dict()
    if access_log_format is not None:
        make_handler_kwargs['access_log_format'] = access_log_format
    handler = app.make_handler(access_log=access_log,
                               **make_handler_kwargs)

    loop.run_until_complete(app.startup())

    scheme = 'https' if ssl_context else 'http'
    base_url = URL('{}://localhost'.format(scheme)).with_port(port)

    if path is None:
        paths = ()
    elif isinstance(path, (str, bytes, bytearray, memoryview))\
            or not isinstance(path, Iterable):
        paths = (path,)
    else:
        paths = path

    if host is None:
        if paths and not port:
            hosts = ()
        else:
            hosts = ("0.0.0.0",)
    elif isinstance(host, (str, bytes, bytearray, memoryview))\
            or not isinstance(host, Iterable):
        hosts = (host,)
    else:
        hosts = host

    if hosts and port is None:
        port = 8443 if ssl_context else 8080

    server_creations = []
    uris = [str(base_url.with_host(host)) for host in hosts]
    if hosts:
        # Multiple hosts bound to same server is available in most loop
        # implementations, but only send multiple if we have multiple.
        host_binding = hosts[0] if len(hosts) == 1 else hosts
        server_creations.append(
            loop.create_server(
                handler, host_binding, port, ssl=ssl_context, backlog=backlog
            )
        )
    for path in paths:
        # Most loop implementations don't support multiple paths bound in same
        # server, so create a server for each.
        server_creations.append(
            loop.create_unix_server(
                handler, path, ssl=ssl_context, backlog=backlog
            )
        )
        uris.append('{}://unix:{}:'.format(scheme, path))

        # Clean up prior socket path if stale and not abstract.
        # CPython 3.5.3+'s event loop already does this. See
        # https://github.com/python/asyncio/issues/425
        if path[0] not in (0, '\x00'):  # pragma: no branch
            try:
                if stat.S_ISSOCK(os.stat(path).st_mode):
                    os.remove(path)
            except FileNotFoundError:
                pass

    servers = loop.run_until_complete(
        asyncio.gather(*server_creations, loop=loop)
    )

    print("======== Running on {} ========\n"
          "(Press CTRL+C to quit)".format(', '.join(uris)))

    try:
        loop.run_forever()
    except KeyboardInterrupt:  # pragma: no cover
        pass
    finally:
        server_closures = []
        for srv in servers:
            srv.close()
            server_closures.append(srv.wait_closed())
        loop.run_until_complete(asyncio.gather(*server_closures, loop=loop))
        loop.run_until_complete(app.shutdown())
        loop.run_until_complete(handler.shutdown(shutdown_timeout))
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
