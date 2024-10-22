__version__ = "4.0.0a2.dev0"

from typing import TYPE_CHECKING, Tuple

from . import hdrs
from .client import (
    BaseConnector,
    ClientConnectionError,
    ClientConnectionResetError,
    ClientConnectorCertificateError,
    ClientConnectorDNSError,
    ClientConnectorError,
    ClientConnectorSSLError,
    ClientError,
    ClientHttpProxyError,
    ClientOSError,
    ClientPayloadError,
    ClientProxyConnectionError,
    ClientRequest,
    ClientResponse,
    ClientResponseError,
    ClientSession,
    ClientSSLError,
    ClientTimeout,
    ClientWebSocketResponse,
    ClientWSTimeout,
    ConnectionTimeoutError,
    ContentTypeError,
    Fingerprint,
    InvalidURL,
    InvalidUrlClientError,
    InvalidUrlRedirectClientError,
    NamedPipeConnector,
    NonHttpUrlClientError,
    NonHttpUrlRedirectClientError,
    RedirectClientError,
    RequestInfo,
    ServerConnectionError,
    ServerDisconnectedError,
    ServerFingerprintMismatch,
    ServerTimeoutError,
    SocketTimeoutError,
    TCPConnector,
    TooManyRedirects,
    UnixConnector,
    WSServerHandshakeError,
    request,
)
from .cookiejar import CookieJar, DummyCookieJar
from .formdata import FormData
from .helpers import BasicAuth, ChainMapProxy, ETag
from .http import (
    HttpVersion,
    HttpVersion10,
    HttpVersion11,
    WebSocketError,
    WSCloseCode,
    WSMessageType,
    WSMsgType,
)
from .multipart import (
    BadContentDispositionHeader,
    BadContentDispositionParam,
    BodyPartReader,
    MultipartReader,
    MultipartWriter,
    content_disposition_filename,
    parse_content_disposition,
)
from .payload import (
    PAYLOAD_REGISTRY,
    AsyncIterablePayload,
    BufferedReaderPayload,
    BytesIOPayload,
    BytesPayload,
    IOBasePayload,
    JsonPayload,
    Payload,
    StringIOPayload,
    StringPayload,
    TextIOPayload,
    get_payload,
    payload_type,
)
from .resolver import AsyncResolver, DefaultResolver, ThreadedResolver
from .streams import (
    EMPTY_PAYLOAD,
    DataQueue,
    EofStream,
    FlowControlDataQueue,
    StreamReader,
)
from .tracing import (
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
    TraceRequestHeadersSentParams,
    TraceRequestRedirectParams,
    TraceRequestStartParams,
    TraceResponseChunkReceivedParams,
)

if TYPE_CHECKING:
    # At runtime these are lazy-loaded at the bottom of the file.
    from .worker import GunicornUVLoopWebWorker, GunicornWebWorker

__all__: Tuple[str, ...] = (
    "hdrs",
    # client
    "BaseConnector",
    "ClientConnectionError",
    "ClientConnectionResetError",
    "ClientConnectorCertificateError",
    "ClientConnectorDNSError",
    "ClientConnectorError",
    "ClientConnectorSSLError",
    "ClientError",
    "ClientHttpProxyError",
    "ClientOSError",
    "ClientPayloadError",
    "ClientProxyConnectionError",
    "ClientResponse",
    "ClientRequest",
    "ClientResponseError",
    "ClientSSLError",
    "ClientSession",
    "ClientTimeout",
    "ClientWebSocketResponse",
    "ClientWSTimeout",
    "ConnectionTimeoutError",
    "ContentTypeError",
    "Fingerprint",
    "InvalidURL",
    "InvalidUrlClientError",
    "InvalidUrlRedirectClientError",
    "NonHttpUrlClientError",
    "NonHttpUrlRedirectClientError",
    "RedirectClientError",
    "RequestInfo",
    "ServerConnectionError",
    "ServerDisconnectedError",
    "ServerFingerprintMismatch",
    "ServerTimeoutError",
    "SocketTimeoutError",
    "TCPConnector",
    "TooManyRedirects",
    "UnixConnector",
    "NamedPipeConnector",
    "WSServerHandshakeError",
    "request",
    # cookiejar
    "CookieJar",
    "DummyCookieJar",
    # formdata
    "FormData",
    # helpers
    "BasicAuth",
    "ChainMapProxy",
    "ETag",
    # http
    "HttpVersion",
    "HttpVersion10",
    "HttpVersion11",
    "WSMsgType",
    "WSCloseCode",
    "WSMessageType",
    "WebSocketError",
    # multipart
    "BadContentDispositionHeader",
    "BadContentDispositionParam",
    "BodyPartReader",
    "MultipartReader",
    "MultipartWriter",
    "content_disposition_filename",
    "parse_content_disposition",
    # payload
    "AsyncIterablePayload",
    "BufferedReaderPayload",
    "BytesIOPayload",
    "BytesPayload",
    "IOBasePayload",
    "JsonPayload",
    "PAYLOAD_REGISTRY",
    "Payload",
    "StringIOPayload",
    "StringPayload",
    "TextIOPayload",
    "get_payload",
    "payload_type",
    # resolver
    "AsyncResolver",
    "DefaultResolver",
    "ThreadedResolver",
    # streams
    "DataQueue",
    "EMPTY_PAYLOAD",
    "EofStream",
    "FlowControlDataQueue",
    "StreamReader",
    # tracing
    "TraceConfig",
    "TraceConnectionCreateEndParams",
    "TraceConnectionCreateStartParams",
    "TraceConnectionQueuedEndParams",
    "TraceConnectionQueuedStartParams",
    "TraceConnectionReuseconnParams",
    "TraceDnsCacheHitParams",
    "TraceDnsCacheMissParams",
    "TraceDnsResolveHostEndParams",
    "TraceDnsResolveHostStartParams",
    "TraceRequestChunkSentParams",
    "TraceRequestEndParams",
    "TraceRequestExceptionParams",
    "TraceRequestHeadersSentParams",
    "TraceRequestRedirectParams",
    "TraceRequestStartParams",
    "TraceResponseChunkReceivedParams",
    # workers (imported lazily with __getattr__)
    "GunicornUVLoopWebWorker",
    "GunicornWebWorker",
)


def __dir__() -> Tuple[str, ...]:
    return __all__ + ("__author__", "__doc__")


def __getattr__(name: str) -> object:
    global GunicornUVLoopWebWorker, GunicornWebWorker

    # Importing gunicorn takes a long time (>100ms), so only import if actually needed.
    if name in ("GunicornUVLoopWebWorker", "GunicornWebWorker"):
        try:
            from .worker import GunicornUVLoopWebWorker as guv, GunicornWebWorker as gw
        except ImportError:
            return None

        GunicornUVLoopWebWorker = guv  # type: ignore[misc]
        GunicornWebWorker = gw  # type: ignore[misc]
        return guv if name == "GunicornUVLoopWebWorker" else gw

    raise AttributeError(f"module {__name__} has no attribute {name}")
