import asyncio
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from aiohttp.tracing import Trace, TraceConfig


class TestTraceConfig:

    def test_trace_config_ctx_default(self):
        trace_config = TraceConfig()
        assert isinstance(trace_config.trace_config_ctx(), SimpleNamespace)

    def test_trace_config_ctx_factory(self):
        trace_config = TraceConfig(trace_config_ctx_factory=dict)
        assert isinstance(trace_config.trace_config_ctx(), dict)

    def test_trace_config_ctx_request_ctx(self):
        trace_request_ctx = Mock()
        trace_config = TraceConfig()
        trace_config_ctx = trace_config.trace_config_ctx(
            trace_request_ctx=trace_request_ctx)
        assert trace_config_ctx.trace_request_ctx is trace_request_ctx

    def test_freeze(self):
        trace_config = TraceConfig()
        trace_config.freeze()

        assert trace_config.on_request_start.frozen
        assert trace_config.on_request_end.frozen
        assert trace_config.on_request_exception.frozen
        assert trace_config.on_request_redirect.frozen
        assert trace_config.on_connection_queued_start.frozen
        assert trace_config.on_connection_queued_end.frozen
        assert trace_config.on_connection_create_start.frozen
        assert trace_config.on_connection_create_end.frozen
        assert trace_config.on_connection_reuseconn.frozen
        assert trace_config.on_dns_resolvehost_start.frozen
        assert trace_config.on_dns_resolvehost_end.frozen
        assert trace_config.on_dns_cache_hit.frozen
        assert trace_config.on_dns_cache_miss.frozen


class TestTrace:

    @pytest.mark.parametrize('signal', [
        'request_start',
        'request_end',
        'request_exception',
        'request_redirect',
        'connection_queued_start',
        'connection_queued_end',
        'connection_create_start',
        'connection_create_end',
        'connection_reuseconn',
        'dns_resolvehost_start',
        'dns_resolvehost_end',
        'dns_cache_hit',
        'dns_cache_miss'
    ])
    async def test_send(self, loop, signal):
        param = Mock()
        session = Mock()
        trace_request_ctx = Mock()
        callback = Mock(side_effect=asyncio.coroutine(Mock()))

        trace_config = TraceConfig()
        getattr(trace_config, "on_%s" % signal).append(callback)
        trace_config.freeze()
        trace = Trace(
            session,
            trace_config,
            trace_config.trace_config_ctx(trace_request_ctx=trace_request_ctx)
        )
        await getattr(trace, "send_%s" % signal)(param)

        callback.assert_called_once_with(
            session,
            SimpleNamespace(trace_request_ctx=trace_request_ctx),
            param,
        )
