from types import SimpleNamespace
from typing import Any, Tuple
from unittest import mock
from unittest.mock import Mock

import pytest

from aiohttp.tracing import (
    Trace,
    TraceConfig,
    TraceConnectionCreateEndParams,
    TraceConnectionCreateStartParams,
    TraceConnectionQueuedEndParams,
    TraceConnectionQueuedStartParams,
    TraceConnectionReuseconnParams,
    TraceDnsCacheHitParams,
    TraceDnsCacheMissParams,
    TraceDnsResolveHostEndParams,
    TraceDnsResolveHostStartParams,
    TraceRequestChunkSentParams,
    TraceRequestEndParams,
    TraceRequestExceptionParams,
    TraceRequestRedirectParams,
    TraceRequestStartParams,
    TraceResponseChunkReceivedParams,
)


class TestTraceConfig:
    def test_trace_config_ctx_default(self) -> None:
        trace_config = TraceConfig()
        assert isinstance(trace_config.trace_config_ctx(), SimpleNamespace)

    def test_trace_config_ctx_factory(self) -> None:
        trace_config = TraceConfig(trace_config_ctx_factory=dict)
        assert isinstance(trace_config.trace_config_ctx(), dict)

    def test_trace_config_ctx_request_ctx(self) -> None:
        trace_request_ctx = Mock()
        trace_config = TraceConfig()
        trace_config_ctx = trace_config.trace_config_ctx(
            trace_request_ctx=trace_request_ctx
        )
        assert trace_config_ctx.trace_request_ctx is trace_request_ctx

    def test_freeze(self) -> None:
        trace_config = TraceConfig()
        trace_config.freeze()

        assert trace_config.on_request_start.frozen
        assert trace_config.on_request_chunk_sent.frozen
        assert trace_config.on_response_chunk_received.frozen
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
        assert trace_config.on_request_headers_sent.frozen


class TestTrace:
    @pytest.mark.parametrize(
        "signal,params,param_obj",
        [
            ("request_start", (Mock(), Mock(), Mock()), TraceRequestStartParams),
            (
                "request_chunk_sent",
                (Mock(), Mock(), Mock()),
                TraceRequestChunkSentParams,
            ),
            (
                "response_chunk_received",
                (Mock(), Mock(), Mock()),
                TraceResponseChunkReceivedParams,
            ),
            ("request_end", (Mock(), Mock(), Mock(), Mock()), TraceRequestEndParams),
            (
                "request_exception",
                (Mock(), Mock(), Mock(), Mock()),
                TraceRequestExceptionParams,
            ),
            (
                "request_redirect",
                (Mock(), Mock(), Mock(), Mock()),
                TraceRequestRedirectParams,
            ),
            ("connection_queued_start", (), TraceConnectionQueuedStartParams),
            ("connection_queued_end", (), TraceConnectionQueuedEndParams),
            ("connection_create_start", (), TraceConnectionCreateStartParams),
            ("connection_create_end", (), TraceConnectionCreateEndParams),
            ("connection_reuseconn", (), TraceConnectionReuseconnParams),
            ("dns_resolvehost_start", (Mock(),), TraceDnsResolveHostStartParams),
            ("dns_resolvehost_end", (Mock(),), TraceDnsResolveHostEndParams),
            ("dns_cache_hit", (Mock(),), TraceDnsCacheHitParams),
            ("dns_cache_miss", (Mock(),), TraceDnsCacheMissParams),
        ],
    )
    async def test_send(
        self, signal: str, params: Tuple[Mock, ...], param_obj: Any
    ) -> None:
        session = Mock()
        trace_request_ctx = Mock()
        callback = Mock(side_effect=mock.AsyncMock())

        trace_config = TraceConfig()
        getattr(trace_config, "on_%s" % signal).append(callback)
        trace_config.freeze()
        trace = Trace(
            session,
            trace_config,
            trace_config.trace_config_ctx(trace_request_ctx=trace_request_ctx),
        )
        await getattr(trace, "send_%s" % signal)(*params)

        callback.assert_called_once_with(
            session,
            SimpleNamespace(trace_request_ctx=trace_request_ctx),
            param_obj(*params),
        )
