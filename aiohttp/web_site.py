import asyncio
import signal
import socket
from abc import ABC, abstractmethod

from yarl import URL

from .log import access_logger


__all__ = ('TCPSite', 'UnixSite', 'SockSite', 'AppRunner', 'GracefulExit')


class GracefulExit(SystemExit):
    code = 1


def _raise_graceful_exit():
    raise GracefulExit()


class BaseSite(ABC):
    def __init__(self, runner, *,
                 shutdown_timeout=60.0, ssl_context=None,
                 backlog=128):
        if not runner.app.frozen:
            raise RuntimeError("Freeze app before running a site")
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
        await self._runner.app.shutdown()
        await self._runner.handler.shutdown(self._shutdown_timeout)
        self._runner._unreg_site(self)


class TCPSite(BaseSite):
    def __init__(self, app, host=None, port=None, *,
                 shutdown_timeout=60.0, ssl_context=None,
                 backlog=128):
        super().__init__(app, shutdown_timeout=shutdown_timeout,
                         ssl_context=ssl_context, backlog=backlog)
        if host is None:
            host = "0.0.0.0"
        self._host = host
        if port is None:
            port = 8443 if self._ssl_context else 8080
        self._port = port

    @property
    def name(self):
        scheme = 'https' if self._ssl_context else 'http'
        return str(URL.build(scheme=scheme, host=self._host, port=self._port))

    async def start(self):
        await super().start()
        loop = asyncio.get_event_loop()
        self._server = await loop.create_server(
            self._runner.handler, self._host, self._port,
            ssl=self._ssl_context, backlog=self._backlog)


class UnixSite(BaseSite):
    def __init__(self, app, path, *,
                 shutdown_timeout=60.0, ssl_context=None,
                 backlog=128):
        super().__init__(app, shutdown_timeout=shutdown_timeout,
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
            self._runner.handler, self._path,
            ssl=self._ssl_context, backlog=self._backlog)


class SockSite(BaseSite):
    def __init__(self, app, sock, *,
                 shutdown_timeout=60.0, ssl_context=None,
                 backlog=128):
        super().__init__(app, shutdown_timeout=shutdown_timeout,
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
            self._runner.handler, sock=self._sock,
            ssl=self._ssl_context, backlog=self._backlog)


class AppRunner:
    def __init__(self, app, *, handle_signals=True,
                 access_log_format=None, access_log=access_logger):
        self._app = app
        self._handle_signals = handle_signals
        self._access_log_format = access_log_format
        self._access_log = access_log
        self._handler = None
        self._sites = set()

    @property
    def app(self):
        return self._app

    @property
    def handler(self):
        return self._handler

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

        self._app._set_loop(loop)
        self._app.on_startup.freeze()
        await self._app.startup()
        self._app.freeze()

        make_handler_kwargs = dict(access_log=self._access_log)
        if self._access_log_format is not None:
            make_handler_kwargs['access_log_format'] = self._access_log_format

        handler = self._app.make_handler(loop=loop, **make_handler_kwargs)
        self._handler = handler

    async def cleanup(self):
        loop = asyncio.get_event_loop()

        # The loop over sites is intentional, an exception on gather()
        # leaves self._sites in unpredictable state.
        # The loop guaranties than a site is eigher deleted on success or
        # still present on failure
        for site in list(self._sites):
            await site.stop()
        await self._app.cleanup()
        if self._handle_signals:
            try:
                loop.remove_signal_handler(signal.SIGINT)
                loop.remove_signal_handler(signal.SIGTERM)
            except NotImplementedError:  # pragma: no cover
                # remove_signal_handler is not implemented on Windows
                pass

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
