"""Async gunicorn worker."""
__all__ = ['AsyncGunicornWorker', 'PortMapperWorker']

import asyncio
import functools
import os
import gunicorn.workers.base as base

from aiohttp.wsgi import WSGIServerHttpProtocol


class AsyncGunicornWorker(base.Worker):

    def __init__(self, *args, **kw):  # pragma: no cover
        super().__init__(*args, **kw)
        self.servers = []
        self.connections = {}

    def init_process(self):
        # create new event_loop after fork
        asyncio.get_event_loop().close()

        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        super().init_process()

    def run(self):
        self._runner = asyncio.async(self._run(), loop=self.loop)

        try:
            self.loop.run_until_complete(self._runner)
        finally:
            self.loop.close()

    def wrap_protocol(self, proto):
        proto.connection_made = _wrp(
            proto, proto.connection_made, self.connections)
        proto.connection_lost = _wrp(
            proto, proto.connection_lost, self.connections, False)
        return proto

    def factory(self, wsgi, host, port):
        proto = WSGIServerHttpProtocol(
            wsgi, loop=self.loop,
            log=self.log,
            debug=self.cfg.debug,
            keep_alive=self.cfg.keepalive,
            access_log=self.log.access_log,
            access_log_format=self.cfg.access_log_format)
        return self.wrap_protocol(proto)

    def get_factory(self, sock, host, port):
        return functools.partial(self.factory, self.wsgi, host, port)

    @asyncio.coroutine
    def close(self):
        try:
            if hasattr(self.wsgi, 'close'):
                yield from self.wsgi.close()
        except:
            self.log.exception('Process shutdown exception')

    @asyncio.coroutine
    def _run(self):
        for sock in self.sockets:
            factory = self.get_factory(sock.sock, *sock.cfg_addr)
            self.servers.append(
                (yield from self.loop.create_server(factory, sock=sock.sock)))

        # If our parent changed then we shut down.
        pid = os.getpid()
        try:
            while self.alive or self.connections:
                self.notify()

                if (self.alive and
                        pid == os.getpid() and self.ppid != os.getppid()):
                    self.log.info("Parent changed, shutting down: %s", self)
                    self.alive = False

                # stop accepting requests
                if not self.alive:
                    if self.servers:
                        self.log.info(
                            "Stopping server: %s, connections: %s",
                            pid, len(self.connections))
                        for server in self.servers:
                            server.close()
                        self.servers.clear()

                    # prepare connections for closing
                    for conn in self.connections.values():
                        if hasattr(conn, 'closing'):
                            conn.closing()

                yield from asyncio.sleep(1.0, loop=self.loop)
        except KeyboardInterrupt:
            pass

        if self.servers:
            for server in self.servers:
                server.close()

        yield from self.close()


class PortMapperWorker(AsyncGunicornWorker):
    """Special worker that uses different wsgi application depends on port.

    Main wsgi application object has to be dictionary:
    """

    def get_factory(self, sock, host, port):
        return functools.partial(self.factory, self.wsgi[port], host, port)

    @asyncio.coroutine
    def close(self):
        for port, wsgi in self.wsgi.items():
            try:
                if hasattr(wsgi, 'close'):
                    yield from wsgi.close()
            except:
                self.log.exception('Process shutdown exception')


class _wrp:

    def __init__(self, proto, meth, tracking, add=True):
        self._proto = proto
        self._id = id(proto)
        self._meth = meth
        self._tracking = tracking
        self._add = add

    def __call__(self, *args):
        if self._add:
            self._tracking[self._id] = self._proto
        elif self._id in self._tracking:
            del self._tracking[self._id]

        conn = self._meth(*args)
        return conn
