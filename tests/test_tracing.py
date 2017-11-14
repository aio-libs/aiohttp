import asyncio
from types import SimpleNamespace
from unittest.mock import Mock

from aiohttp.signals import Signal
from aiohttp.tracing import REQUEST_SIGNALS, Trace, TraceConfig


class TestTraceConfig:

    def test_trace_conifg(self):
        trace_config = TraceConfig()
        for signal in REQUEST_SIGNALS:
            assert isinstance(getattr(trace_config, signal), Signal)

        assert isinstance(trace_config.trace_context(), SimpleNamespace)

    def test_trace_context_class(self):
        trace_config = TraceConfig(trace_context_class=dict)
        assert isinstance(trace_config.trace_context(), dict)

    def test_freeze(self):
        trace_config = TraceConfig()
        trace_config.freeze()

        for signal in REQUEST_SIGNALS:
            assert getattr(trace_config, signal).frozen


class TestTrace:

    async def test_send(self, loop):
        param = Mock()
        session = Mock()
        trace_context = Mock()
        on_request_start = Mock(side_effect=asyncio.coroutine(Mock()))

        trace_config = TraceConfig()
        trace_config.on_request_start.append(on_request_start)
        trace_config.freeze()
        trace = Trace(trace_config, session, trace_context)
        await trace.send('on_request_start', param)

        on_request_start.assert_called_once_with(
            session,
            trace_context,
            param
        )
