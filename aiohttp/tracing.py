import dataclasses
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, Awaitable, Generic, Protocol, TypeVar, overload

from aiosignal import Signal
from multidict import CIMultiDict
from yarl import URL

from .client_reqrep import ClientResponse

if TYPE_CHECKING:
    from .client import ClientSession

    _ParamT_contra = TypeVar("_ParamT_contra", contravariant=True)

    class _SignalCallback(Protocol[_ParamT_contra]):
        def __call__(
            self,
            __client_session: ClientSession,
            __trace_config_ctx: SimpleNamespace,
            __params: _ParamT_contra,
        ) -> Awaitable[None]: ...


__all__ = (
    "TraceConfig",
    "TraceRequestStartParams",
    "TraceRequestEndParams",
    "TraceRequestExceptionParams",
    "TraceConnectionQueuedStartParams",
    "TraceConnectionQueuedEndParams",
    "TraceConnectionCreateStartParams",
    "TraceConnectionCreateEndParams",
    "TraceConnectionReuseconnParams",
    "TraceDnsResolveHostStartParams",
    "TraceDnsResolveHostEndParams",
    "TraceDnsCacheHitParams",
    "TraceDnsCacheMissParams",
    "TraceRequestRedirectParams",
    "TraceRequestChunkSentParams",
    "TraceResponseChunkReceivedParams",
    "TraceRequestHeadersSentParams",
)

_T = TypeVar("_T", covariant=True)


class _Factory(Protocol[_T]):
    def __call__(self, **kwargs: Any) -> _T: ...


class TraceConfig(Generic[_T]):
    """First-class used to trace requests launched via ClientSession objects."""

    @overload
    def __init__(self: "TraceConfig[SimpleNamespace]") -> None: ...
    @overload
    def __init__(self, trace_config_ctx_factory: _Factory[_T]) -> None: ...
    def __init__(
        self, trace_config_ctx_factory: _Factory[Any] = SimpleNamespace
    ) -> None:
        self._on_request_start: Signal[_SignalCallback[TraceRequestStartParams]] = (
            Signal(self)
        )
        self._on_request_chunk_sent: Signal[
            _SignalCallback[TraceRequestChunkSentParams]
        ] = Signal(self)
        self._on_response_chunk_received: Signal[
            _SignalCallback[TraceResponseChunkReceivedParams]
        ] = Signal(self)
        self._on_request_end: Signal[_SignalCallback[TraceRequestEndParams]] = Signal(
            self
        )
        self._on_request_exception: Signal[
            _SignalCallback[TraceRequestExceptionParams]
        ] = Signal(self)
        self._on_request_redirect: Signal[
            _SignalCallback[TraceRequestRedirectParams]
        ] = Signal(self)
        self._on_connection_queued_start: Signal[
            _SignalCallback[TraceConnectionQueuedStartParams]
        ] = Signal(self)
        self._on_connection_queued_end: Signal[
            _SignalCallback[TraceConnectionQueuedEndParams]
        ] = Signal(self)
        self._on_connection_create_start: Signal[
            _SignalCallback[TraceConnectionCreateStartParams]
        ] = Signal(self)
        self._on_connection_create_end: Signal[
            _SignalCallback[TraceConnectionCreateEndParams]
        ] = Signal(self)
        self._on_connection_reuseconn: Signal[
            _SignalCallback[TraceConnectionReuseconnParams]
        ] = Signal(self)
        self._on_dns_resolvehost_start: Signal[
            _SignalCallback[TraceDnsResolveHostStartParams]
        ] = Signal(self)
        self._on_dns_resolvehost_end: Signal[
            _SignalCallback[TraceDnsResolveHostEndParams]
        ] = Signal(self)
        self._on_dns_cache_hit: Signal[_SignalCallback[TraceDnsCacheHitParams]] = (
            Signal(self)
        )
        self._on_dns_cache_miss: Signal[_SignalCallback[TraceDnsCacheMissParams]] = (
            Signal(self)
        )
        self._on_request_headers_sent: Signal[
            _SignalCallback[TraceRequestHeadersSentParams]
        ] = Signal(self)

        self._trace_config_ctx_factory: _Factory[_T] = trace_config_ctx_factory

    def trace_config_ctx(self, trace_request_ctx: Any = None) -> _T:
        """Return a new trace_config_ctx instance"""
        return self._trace_config_ctx_factory(trace_request_ctx=trace_request_ctx)

    def freeze(self) -> None:
        self._on_request_start.freeze()
        self._on_request_chunk_sent.freeze()
        self._on_response_chunk_received.freeze()
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
        self._on_request_headers_sent.freeze()

    @property
    def on_request_start(self) -> "Signal[_SignalCallback[TraceRequestStartParams]]":
        return self._on_request_start

    @property
    def on_request_chunk_sent(
        self,
    ) -> "Signal[_SignalCallback[TraceRequestChunkSentParams]]":
        return self._on_request_chunk_sent

    @property
    def on_response_chunk_received(
        self,
    ) -> "Signal[_SignalCallback[TraceResponseChunkReceivedParams]]":
        return self._on_response_chunk_received

    @property
    def on_request_end(self) -> "Signal[_SignalCallback[TraceRequestEndParams]]":
        return self._on_request_end

    @property
    def on_request_exception(
        self,
    ) -> "Signal[_SignalCallback[TraceRequestExceptionParams]]":
        return self._on_request_exception

    @property
    def on_request_redirect(
        self,
    ) -> "Signal[_SignalCallback[TraceRequestRedirectParams]]":
        return self._on_request_redirect

    @property
    def on_connection_queued_start(
        self,
    ) -> "Signal[_SignalCallback[TraceConnectionQueuedStartParams]]":
        return self._on_connection_queued_start

    @property
    def on_connection_queued_end(
        self,
    ) -> "Signal[_SignalCallback[TraceConnectionQueuedEndParams]]":
        return self._on_connection_queued_end

    @property
    def on_connection_create_start(
        self,
    ) -> "Signal[_SignalCallback[TraceConnectionCreateStartParams]]":
        return self._on_connection_create_start

    @property
    def on_connection_create_end(
        self,
    ) -> "Signal[_SignalCallback[TraceConnectionCreateEndParams]]":
        return self._on_connection_create_end

    @property
    def on_connection_reuseconn(
        self,
    ) -> "Signal[_SignalCallback[TraceConnectionReuseconnParams]]":
        return self._on_connection_reuseconn

    @property
    def on_dns_resolvehost_start(
        self,
    ) -> "Signal[_SignalCallback[TraceDnsResolveHostStartParams]]":
        return self._on_dns_resolvehost_start

    @property
    def on_dns_resolvehost_end(
        self,
    ) -> "Signal[_SignalCallback[TraceDnsResolveHostEndParams]]":
        return self._on_dns_resolvehost_end

    @property
    def on_dns_cache_hit(self) -> "Signal[_SignalCallback[TraceDnsCacheHitParams]]":
        return self._on_dns_cache_hit

    @property
    def on_dns_cache_miss(self) -> "Signal[_SignalCallback[TraceDnsCacheMissParams]]":
        return self._on_dns_cache_miss

    @property
    def on_request_headers_sent(
        self,
    ) -> "Signal[_SignalCallback[TraceRequestHeadersSentParams]]":
        return self._on_request_headers_sent


@dataclasses.dataclass(frozen=True)
class TraceRequestStartParams:
    """Parameters sent by the `on_request_start` signal"""

    method: str
    url: URL
    headers: "CIMultiDict[str]"


@dataclasses.dataclass(frozen=True)
class TraceRequestChunkSentParams:
    """Parameters sent by the `on_request_chunk_sent` signal"""

    method: str
    url: URL
    chunk: bytes


@dataclasses.dataclass(frozen=True)
class TraceResponseChunkReceivedParams:
    """Parameters sent by the `on_response_chunk_received` signal"""

    method: str
    url: URL
    chunk: bytes


@dataclasses.dataclass(frozen=True)
class TraceRequestEndParams:
    """Parameters sent by the `on_request_end` signal"""

    method: str
    url: URL
    headers: "CIMultiDict[str]"
    response: ClientResponse


@dataclasses.dataclass(frozen=True)
class TraceRequestExceptionParams:
    """Parameters sent by the `on_request_exception` signal"""

    method: str
    url: URL
    headers: "CIMultiDict[str]"
    exception: BaseException


@dataclasses.dataclass(frozen=True)
class TraceRequestRedirectParams:
    """Parameters sent by the `on_request_redirect` signal"""

    method: str
    url: URL
    headers: "CIMultiDict[str]"
    response: ClientResponse


@dataclasses.dataclass(frozen=True)
class TraceConnectionQueuedStartParams:
    """Parameters sent by the `on_connection_queued_start` signal"""


@dataclasses.dataclass(frozen=True)
class TraceConnectionQueuedEndParams:
    """Parameters sent by the `on_connection_queued_end` signal"""


@dataclasses.dataclass(frozen=True)
class TraceConnectionCreateStartParams:
    """Parameters sent by the `on_connection_create_start` signal"""


@dataclasses.dataclass(frozen=True)
class TraceConnectionCreateEndParams:
    """Parameters sent by the `on_connection_create_end` signal"""


@dataclasses.dataclass(frozen=True)
class TraceConnectionReuseconnParams:
    """Parameters sent by the `on_connection_reuseconn` signal"""


@dataclasses.dataclass(frozen=True)
class TraceDnsResolveHostStartParams:
    """Parameters sent by the `on_dns_resolvehost_start` signal"""

    host: str


@dataclasses.dataclass(frozen=True)
class TraceDnsResolveHostEndParams:
    """Parameters sent by the `on_dns_resolvehost_end` signal"""

    host: str


@dataclasses.dataclass(frozen=True)
class TraceDnsCacheHitParams:
    """Parameters sent by the `on_dns_cache_hit` signal"""

    host: str


@dataclasses.dataclass(frozen=True)
class TraceDnsCacheMissParams:
    """Parameters sent by the `on_dns_cache_miss` signal"""

    host: str


@dataclasses.dataclass(frozen=True)
class TraceRequestHeadersSentParams:
    """Parameters sent by the `on_request_headers_sent` signal"""

    method: str
    url: URL
    headers: "CIMultiDict[str]"


class Trace:
    """Internal dependency holder class.

    Used to keep together the main dependencies used
    at the moment of send a signal.
    """

    def __init__(
        self,
        session: "ClientSession",
        trace_config: TraceConfig[object],
        trace_config_ctx: Any,
    ) -> None:
        self._trace_config = trace_config
        self._trace_config_ctx = trace_config_ctx
        self._session = session

    async def send_request_start(
        self, method: str, url: URL, headers: "CIMultiDict[str]"
    ) -> None:
        return await self._trace_config.on_request_start.send(
            self._session,
            self._trace_config_ctx,
            TraceRequestStartParams(method, url, headers),
        )

    async def send_request_chunk_sent(
        self, method: str, url: URL, chunk: bytes
    ) -> None:
        return await self._trace_config.on_request_chunk_sent.send(
            self._session,
            self._trace_config_ctx,
            TraceRequestChunkSentParams(method, url, chunk),
        )

    async def send_response_chunk_received(
        self, method: str, url: URL, chunk: bytes
    ) -> None:
        return await self._trace_config.on_response_chunk_received.send(
            self._session,
            self._trace_config_ctx,
            TraceResponseChunkReceivedParams(method, url, chunk),
        )

    async def send_request_end(
        self,
        method: str,
        url: URL,
        headers: "CIMultiDict[str]",
        response: ClientResponse,
    ) -> None:
        return await self._trace_config.on_request_end.send(
            self._session,
            self._trace_config_ctx,
            TraceRequestEndParams(method, url, headers, response),
        )

    async def send_request_exception(
        self,
        method: str,
        url: URL,
        headers: "CIMultiDict[str]",
        exception: BaseException,
    ) -> None:
        return await self._trace_config.on_request_exception.send(
            self._session,
            self._trace_config_ctx,
            TraceRequestExceptionParams(method, url, headers, exception),
        )

    async def send_request_redirect(
        self,
        method: str,
        url: URL,
        headers: "CIMultiDict[str]",
        response: ClientResponse,
    ) -> None:
        return await self._trace_config._on_request_redirect.send(
            self._session,
            self._trace_config_ctx,
            TraceRequestRedirectParams(method, url, headers, response),
        )

    async def send_connection_queued_start(self) -> None:
        return await self._trace_config.on_connection_queued_start.send(
            self._session, self._trace_config_ctx, TraceConnectionQueuedStartParams()
        )

    async def send_connection_queued_end(self) -> None:
        return await self._trace_config.on_connection_queued_end.send(
            self._session, self._trace_config_ctx, TraceConnectionQueuedEndParams()
        )

    async def send_connection_create_start(self) -> None:
        return await self._trace_config.on_connection_create_start.send(
            self._session, self._trace_config_ctx, TraceConnectionCreateStartParams()
        )

    async def send_connection_create_end(self) -> None:
        return await self._trace_config.on_connection_create_end.send(
            self._session, self._trace_config_ctx, TraceConnectionCreateEndParams()
        )

    async def send_connection_reuseconn(self) -> None:
        return await self._trace_config.on_connection_reuseconn.send(
            self._session, self._trace_config_ctx, TraceConnectionReuseconnParams()
        )

    async def send_dns_resolvehost_start(self, host: str) -> None:
        return await self._trace_config.on_dns_resolvehost_start.send(
            self._session, self._trace_config_ctx, TraceDnsResolveHostStartParams(host)
        )

    async def send_dns_resolvehost_end(self, host: str) -> None:
        return await self._trace_config.on_dns_resolvehost_end.send(
            self._session, self._trace_config_ctx, TraceDnsResolveHostEndParams(host)
        )

    async def send_dns_cache_hit(self, host: str) -> None:
        return await self._trace_config.on_dns_cache_hit.send(
            self._session, self._trace_config_ctx, TraceDnsCacheHitParams(host)
        )

    async def send_dns_cache_miss(self, host: str) -> None:
        return await self._trace_config.on_dns_cache_miss.send(
            self._session, self._trace_config_ctx, TraceDnsCacheMissParams(host)
        )

    async def send_request_headers(
        self, method: str, url: URL, headers: "CIMultiDict[str]"
    ) -> None:
        return await self._trace_config._on_request_headers_sent.send(
            self._session,
            self._trace_config_ctx,
            TraceRequestHeadersSentParams(method, url, headers),
        )
