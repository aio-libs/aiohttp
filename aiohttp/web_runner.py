import asyncio
import signal
import socket
from abc import ABC, abstractmethod

from yarl import URL

from .web_app import Application


__all__ = ('TCPSite', 'UnixSite', 'SockSite', 'BaseRunner',
           'AppRunner', 'ServerRunner', 'GracefulExit')


class GracefulExit(SystemExit):
    code = 1


def _raise_graceful_exit():
    raise GracefulExit()


class BaseSite(ABC):
    __slots__ = ('_runner', '_shutdown_timeout', '_ssl_context', '_backlog',
                 '_server')

    def __init__(self, runner, *,
                 shutdown_timeout=60.0, ssl_context=None,
                 backlog=128):
        if runner.server is None:
            raise RuntimeError("Call runner.setup() before making a site")
        self._runner = runner
        self._shutdown_timeout = shutdown_timeout
        self._ssl_context = ssl_context
        self._backlog = backlog
        self._server = None

    @property
    @abstractmethod
    def name(self):
        pass  # pragma: no cover

    @abstractmethod
    async def start(self):
        self._runner._reg_site(self)

    async def stop(self):
        self._runner._check_site(self)
        if self._server is None:
            self._runner._unreg_site(self)
            return  # not started yet
        self._server.close()
        await self._server.wait_closed()
        await self._runner.shutdown()
        await self._runner.server.shutdown(self._shutdown_timeout)
        self._runner._unreg_site(self)


class TCPSite(BaseSite):
    __slots__ = ('_host', '_port', '_reuse_address', '_reuse_port')

    def __init__(self, runner, host=None, port=None, *,
                 shutdown_timeout=60.0, ssl_context=None,
                 backlog=128, reuse_address=None,
                 reuse_port=None):
        super().__init__(runner, shutdown_timeout=shutdown_timeout,
                         ssl_context=ssl_context, backlog=backlog)
        if host is None:
            host = "0.0.0.0"
        self._host = host
        if port is None:
            port = 8443 if self._ssl_context else 8080
        self._port = port
        self._reuse_address = reuse_address
        self._reuse_port = reuse_port

    @property
    def name(self):
        scheme = 'https' if self._ssl_context else 'http'
        return str(URL.build(scheme=scheme, host=self._host, port=self._port))

    async def start(self):
        await super().start()
        loop = asyncio.get_event_loop()
        self._server = await loop.create_server(
            self._runner.server, self._host, self._port,
            ssl=self._ssl_context, backlog=self._backlog,
            reuse_address=self._reuse_address,
            reuse_port=self._reuse_port)


class UnixSite(BaseSite):
    __slots__ = ('_path', )

    def __init__(self, runner, path, *,
                 shutdown_timeout=60.0, ssl_context=None,
                 backlog=128):
        super().__init__(runner, shutdown_timeout=shutdown_timeout,
                         ssl_context=ssl_context, backlog=backlog)
        self._path = path

    @property
    def name(self):
        scheme = 'https' if self._ssl_context else 'http'
        return '{}://unix:{}:'.format(scheme, self._path)

    async def start(self):
        await super().start()
        loop = asyncio.get_event_loop()
        self._server = await loop.create_unix_server(
            self._runner.server, self._path,
            ssl=self._ssl_context, backlog=self._backlog)


class SockSite(BaseSite):
    __slots__ = ('_sock', '_name')

    def __init__(self, runner, sock, *,
                 shutdown_timeout=60.0, ssl_context=None,
                 backlog=128):
        super().__init__(runner, shutdown_timeout=shutdown_timeout,
                         ssl_context=ssl_context, backlog=backlog)
        self._sock = sock
        scheme = 'https' if self._ssl_context else 'http'
        if hasattr(socket, 'AF_UNIX') and sock.family == socket.AF_UNIX:
            name = '{}://unix:{}:'.format(scheme, sock.getsockname())
        else:
            host, port = sock.getsockname()[:2]
            name = str(URL.build(scheme=scheme, host=host, port=port))
        self._name = name

    @property
    def name(self):
        return self._name

    async def start(self):
        await super().start()
        loop = asyncio.get_event_loop()
        self._server = await loop.create_server(
            self._runner.server, sock=self._sock,
            ssl=self._ssl_context, backlog=self._backlog)


class BaseRunner(ABC):
    __slots__ = ('_handle_signals', '_kwargs', '_server', '_sites')

    def __init__(self, *, handle_signals=False, **kwargs):
        self._handle_signals = handle_signals
        self._kwargs = kwargs
        self._server = None
        self._sites = set()

    @property
    def server(self):
        return self._server

    @property
    def sites(self):
        return set(self._sites)

    async def setup(self):
        loop = asyncio.get_event_loop()

        if self._handle_signals:
            try:
                loop.add_signal_handler(signal.SIGINT, _raise_graceful_exit)
                loop.add_signal_handler(signal.SIGTERM, _raise_graceful_exit)
            except NotImplementedError:  # pragma: no cover
                # add_signal_handler is not implemented on Windows
                pass

        self._server = await self._make_server()

    @abstractmethod
    async def shutdown(self):
        pass  # pragma: no cover

    async def cleanup(self):
        loop = asyncio.get_event_loop()

        if self._server is None:
            # no started yet, do nothing
            return

        # The loop over sites is intentional, an exception on gather()
        # leaves self._sites in unpredictable state.
        # The loop guaranties that a site is either deleted on success or
        # still present on failure
        for site in list(self._sites):
            await site.stop()
        await self._cleanup_server()
        self._server = None
        if self._handle_signals:
            try:
                loop.remove_signal_handler(signal.SIGINT)
                loop.remove_signal_handler(signal.SIGTERM)
            except NotImplementedError:  # pragma: no cover
                # remove_signal_handler is not implemented on Windows
                pass

    @abstractmethod
    async def _make_server(self):
        pass  # pragma: no cover

    @abstractmethod
    async def _cleanup_server(self):
        pass  # pragma: no cover

    def _reg_site(self, site):
        if site in self._sites:
            raise RuntimeError("Site {} is already registered in runner {}"
                               .format(site, self))
        self._sites.add(site)

    def _check_site(self, site):
        if site not in self._sites:
            raise RuntimeError("Site {} is not registered in runner {}"
                               .format(site, self))

    def _unreg_site(self, site):
        if site not in self._sites:
            raise RuntimeError("Site {} is not registered in runner {}"
                               .format(site, self))
        self._sites.remove(site)


class ServerRunner(BaseRunner):
    """Low-level web server runner"""

    __slots__ = ('_web_server',)

    def __init__(self, web_server, *, handle_signals=False, **kwargs):
        super().__init__(handle_signals=handle_signals, **kwargs)
        self._web_server = web_server

    async def shutdown(self):
        pass

    async def _make_server(self):
        return self._web_server

    async def _cleanup_server(self):
        pass


class AppRunner(BaseRunner):
    """Web Application runner"""

    __slots__ = ('_app',)

    def __init__(self, app, *, handle_signals=False, **kwargs):
        super().__init__(handle_signals=handle_signals, **kwargs)
        if not isinstance(app, Application):
            raise TypeError("The first argument should be web.Application "
                            "instance, got {!r}".format(app))
        self._app = app

    @property
    def app(self):
        return self._app

    async def shutdown(self):
        await self._app.shutdown()

    async def _make_server(self):
        loop = asyncio.get_event_loop()
        self._app._set_loop(loop)
        self._app.on_startup.freeze()
        await self._app.startup()
        self._app.freeze()

        return self._app.make_handler(loop=loop, **self._kwargs)

    async def _cleanup_server(self):
        await self._app.cleanup()
