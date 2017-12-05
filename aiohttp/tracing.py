from types import SimpleNamespace

from .signals import Signal


__all__ = ('TraceConfig',)


class TraceConfig:
    """First-class used to trace requests launched via ClientSession
    objects."""

    def __init__(self, trace_config_ctx_factory=SimpleNamespace):
        self._on_request_start = Signal(self)
        self._on_request_end = Signal(self)
        self._on_request_exception = Signal(self)
        self._on_request_redirect = Signal(self)
        self._on_connection_queued_start = Signal(self)
        self._on_connection_queued_end = Signal(self)
        self._on_connection_create_start = Signal(self)
        self._on_connection_create_end = Signal(self)
        self._on_connection_reuseconn = Signal(self)
        self._on_dns_resolvehost_start = Signal(self)
        self._on_dns_resolvehost_end = Signal(self)
        self._on_dns_cache_hit = Signal(self)
        self._on_dns_cache_miss = Signal(self)

        self._trace_config_ctx_factory = trace_config_ctx_factory

    def trace_config_ctx(self, trace_request_ctx=None):
        """ Return a new trace_config_ctx instance """
        return self._trace_config_ctx_factory(
            trace_request_ctx=trace_request_ctx)

    def freeze(self):
        self._on_request_start.freeze()
        self._on_request_end.freeze()
        self._on_request_exception.freeze()
        self._on_request_redirect.freeze()
        self._on_connection_queued_start.freeze()
        self._on_connection_queued_end.freeze()
        self._on_connection_create_start.freeze()
        self._on_connection_create_end.freeze()
        self._on_connection_reuseconn.freeze()
        self._on_dns_resolvehost_start.freeze()
        self._on_dns_resolvehost_end.freeze()
        self._on_dns_cache_hit.freeze()
        self._on_dns_cache_miss.freeze()

    @property
    def on_request_start(self):
        return self._on_request_start

    @property
    def on_request_end(self):
        return self._on_request_end

    @property
    def on_request_exception(self):
        return self._on_request_exception

    @property
    def on_request_redirect(self):
        return self._on_request_redirect

    @property
    def on_connection_queued_start(self):
        return self._on_connection_queued_start

    @property
    def on_connection_queued_end(self):
        return self._on_connection_queued_end

    @property
    def on_connection_create_start(self):
        return self._on_connection_create_start

    @property
    def on_connection_create_end(self):
        return self._on_connection_create_end

    @property
    def on_connection_reuseconn(self):
        return self._on_connection_reuseconn

    @property
    def on_dns_resolvehost_start(self):
        return self._on_dns_resolvehost_start

    @property
    def on_dns_resolvehost_end(self):
        return self._on_dns_resolvehost_end

    @property
    def on_dns_cache_hit(self):
        return self._on_dns_cache_hit

    @property
    def on_dns_cache_miss(self):
        return self._on_dns_cache_miss


class Trace:
    """ Internal class used to keep together the main dependencies used
    at the moment of send a signal."""

    def __init__(self, session, trace_config, trace_config_ctx):
        self._trace_config = trace_config
        self._trace_config_ctx = trace_config_ctx
        self._session = session

    async def send_request_start(self, *args, **kwargs):
        return await self._trace_config.on_request_start.send(
            self._session,
            self._trace_config_ctx,
            *args,
            **kwargs
        )

    async def send_request_end(self, *args, **kwargs):
        return await self._trace_config.on_request_end.send(
            self._session,
            self._trace_config_ctx,
            *args,
            **kwargs
        )

    async def send_request_exception(self, *args, **kwargs):
        return await self._trace_config.on_request_exception.send(
            self._session,
            self._trace_config_ctx,
            *args,
            **kwargs
        )

    async def send_request_redirect(self, *args, **kwargs):
        return await self._trace_config._on_request_redirect.send(
            self._session,
            self._trace_config_ctx,
            *args,
            **kwargs
        )

    async def send_connection_queued_start(self, *args, **kwargs):
        return await self._trace_config.on_connection_queued_start.send(
            self._session,
            self._trace_config_ctx,
            *args,
            **kwargs
        )

    async def send_connection_queued_end(self, *args, **kwargs):
        return await self._trace_config.on_connection_queued_end.send(
            self._session,
            self._trace_config_ctx,
            *args,
            **kwargs
        )

    async def send_connection_create_start(self, *args, **kwargs):
        return await self._trace_config.on_connection_create_start.send(
            self._session,
            self._trace_config_ctx,
            *args,
            **kwargs
        )

    async def send_connection_create_end(self, *args, **kwargs):
        return await self._trace_config.on_connection_create_end.send(
            self._session,
            self._trace_config_ctx,
            *args,
            **kwargs
        )

    async def send_connection_reuseconn(self, *args, **kwargs):
        return await self._trace_config.on_connection_reuseconn.send(
            self._session,
            self._trace_config_ctx,
            *args,
            **kwargs
        )

    async def send_dns_resolvehost_start(self, *args, **kwargs):
        return await self._trace_config.on_dns_resolvehost_start.send(
            self._session,
            self._trace_config_ctx,
            *args,
            **kwargs
        )

    async def send_dns_resolvehost_end(self, *args, **kwargs):
        return await self._trace_config.on_dns_resolvehost_end.send(
            self._session,
            self._trace_config_ctx,
            *args,
            **kwargs
        )

    async def send_dns_cache_hit(self, *args, **kwargs):
        return await self._trace_config.on_dns_cache_hit.send(
            self._session,
            self._trace_config_ctx,
            *args,
            **kwargs
        )

    async def send_dns_cache_miss(self, *args, **kwargs):
        return await self._trace_config.on_dns_cache_miss.send(
            self._session,
            self._trace_config_ctx,
            *args,
            **kwargs
        )
