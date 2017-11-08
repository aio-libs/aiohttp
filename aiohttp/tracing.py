from types import SimpleNamespace

from aiohttp.signals import Signal

__all__ = ('TraceConfig',)

REQUEST_SIGNALS = (
    'on_request_start',
    'on_request_end',
    'on_request_exception',
    'on_request_redirect',
    'on_connection_queued_start',
    'on_connection_queued_end',
    'on_connection_create_start',
    'on_connection_create_end',
    'on_connection_reuseconn',
    'on_dns_resolvehost_start',
    'on_dns_resolvehost_end',
    'on_dns_cache_hit',
    'on_dns_cache_miss'
)


class TraceConfig:
    """First-class used to trace requests launched via ClientSession
    objects."""

    def __init__(self, trace_context_class=SimpleNamespace):
        for signal in REQUEST_SIGNALS:
            setattr(self, signal, Signal(self))

        self._trace_context_class = trace_context_class

    def trace_context(self):
        """ Return a new trace_context instance """
        return self._trace_context_class()

    def freeze(self):
        for signal in REQUEST_SIGNALS:
            getattr(self, signal).freeze()


class Trace:
    """ Internal class used to have access to the TraceConfig, ClientSession
    and trace config at any point of a request execution."""

    def __init__(self, trace_config, session, trace_context):
        self._trace_config = trace_config
        self._session = session
        self._trace_context = trace_context

    async def send(self, signal, *args, **kwargs):
        return await getattr(self._trace_config, signal).send(
            self._session,
            self._trace_context,
            *args,
            **kwargs
        )
