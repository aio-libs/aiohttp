import asyncio
import time
import warnings
from collections import defaultdict
from math import ceil

import attr

from aiohttp.helpers import TimerContext, TimerNoop
from aiohttp.tracing import SIGNALS


def _tm(start, end):
    if start not in SIGNALS.keys():
        raise ValueError("Invalid timeout start signal %s" % start)
    if end not in SIGNALS.keys():
        raise ValueError("Invalid timeout end signal %s" % end)
    return {"start": start, "end": end}


@attr.s(frozen=True, slots=True)
class RequestTimeouts:
    # XXX what happens between "connection_create_start" and "connection_create_end" and whether we'll get callbacks is implementation dependent
    read_timeout = attr.ib(type=float, default=None)  # TODO
    connection_create_timeout = attr.ib(type=float, default=None, metadata=_tm("connection_create_start", "connection_create_end"))

    uber_timeout = attr.ib(type=float, default=None, metadata=_tm("request_start", "request_end"))
    pool_queue_timeout = attr.ib(type=float, default=None, metadata=_tm("connection_queued_start", "connection_queued_end"))
    dns_resolution_timeout = attr.ib(type=float, default=None, metadata=_tm("dns_resolvehost_start", "dns_resolvehost_end"))
    socket_connect_timeout = attr.ib(type=float, default=None)  # TODO
    connection_acquiring_timeout = attr.ib(type=float, default=None)  # TODO
    new_connection_timeout = attr.ib(type=float, default=None)  # TODO
    http_header_timeout = attr.ib(type=float, default=None)  # TODO metadata=_tm("request_sent", "response_headers_received"))
    response_body_timeout = attr.ib(type=float, default=None)  # TODO metadata=_tm("response_headers_received", "request_end"))

    # to create a timeout specific for a single request, either
    # - create a completely new one to overwrite the default
    # - or use http://www.attrs.org/en/stable/api.html#attr.evolve to overwrite the defaults
    # (maybe this should be done through either session.extend_timeout or session.replace_timeout without directly calling RequestTimeouts)


class RequestLifecycle:
    """ Internal class used to keep together the main dependencies used
    at the moment of send a signal."""

    def __init__(self, session, loop, trace_configs, trace_request_ctx, timeout_config):
        self._session = session
        self._loop = loop
        self._trace_configs = [
            (config, config.trace_config_ctx(trace_request_ctx=trace_request_ctx)) for config in trace_configs
        ]
        self._timeout_config = timeout_config

        self._signal_timestamps = {}
        self._set_timeouts = defaultdict(list)
        self._active_timeouts = defaultdict(list)

        # filter timeouts that were actually set by the user
        if timeout_config:
            for timeout_field in attr.fields(RequestTimeouts):
                if timeout_field.metadata and getattr(timeout_config, timeout_field.name):
                    self._active_timeouts[timeout_field.metadata["start"]].append(
                        (timeout_field.metadata["end"], getattr(timeout_config, timeout_field.name))
                    )

        # create a timeout context depending on wether any timeouts were actually set
        if self._set_timeouts:
            self.request_timer_context = TimerContext(self._loop)
        else:
            self.request_timer_context = TimerNoop()

        # generate send_signal methods, sending on_signal to all trace listeners and keeping track of timeouts, for all Signals
        for signal, params_class in SIGNALS:
            setattr(self, "send_" + signal, self._send(signal, params_class))

    def _send(self, signal, params_class):
        async def sender(*args, **kwargs):
            # record timestamp
            self._signal_timestamps[signal] = time.time()

            # cancel all running timeouts that end with this signal
            while self._set_timeouts[signal]:
                timeout_handle = self._set_timeouts[signal].pop()
                timeout_handle.cancel()

            # send on_signal to all trace listeners
            params = params_class(*args, **kwargs)
            await asyncio.gather(
                getattr(trace_config, "on_" + signal).send(self._session, trace_context, params)
                for trace_config, trace_context in self._trace_configs
            )

            # start all timeouts that begin with this signal and register their handles for the end signal
            for end, timeout in self._set_timeouts[signal]:
                assert isinstance(self.request_timer_context, TimerContext)
                at = ceil(self._loop.time() + timeout)
                handle = self._loop.call_at(at, self.request_timer_context.timeout)
                self._set_timeouts[end].append(handle)

        return sender

    def clear_timeouts(self):
        for signal, timeout_handles in self._set_timeouts.items():
            while timeout_handles[signal]:
                timeout_handle = timeout_handles[signal].pop()
                warnings.warn("Timeout handle %s wasn't cancelled by it's end signal %s. "
                              "There was something wrong with the lifecycle transitions."
                              % (timeout_handle, signal))
                timeout_handle.cancel()
