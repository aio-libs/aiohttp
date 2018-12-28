__version__ = '4.0.0a0'

# This relies on each of the submodules having an __all__ variable.

from . import hdrs  # noqa
from .client import BaseConnector  # noqa
from .client import ClientConnectionError  # noqa
from .client import ClientConnectorCertificateError  # noqa
from .client import ClientConnectorError  # noqa
from .client import ClientConnectorSSLError  # noqa
from .client import ClientError  # noqa
from .client import ClientHttpProxyError  # noqa
from .client import ClientOSError  # noqa
from .client import ClientPayloadError  # noqa
from .client import ClientProxyConnectionError  # noqa
from .client import ClientRequest  # noqa
from .client import ClientResponse  # noqa
from .client import ClientResponseError  # noqa
from .client import ClientSSLError  # noqa
from .client import ClientSession  # noqa
from .client import ClientTimeout  # noqa
from .client import ClientWebSocketResponse  # noqa
from .client import ContentTypeError  # noqa
from .client import Fingerprint  # noqa
from .client import InvalidURL  # noqa
from .client import RequestInfo  # noqa
from .client import ServerConnectionError  # noqa
from .client import ServerDisconnectedError  # noqa
from .client import ServerFingerprintMismatch  # noqa
from .client import ServerTimeoutError  # noqa
from .client import TCPConnector  # noqa
from .client import UnixConnector  # noqa
from .client import WSServerHandshakeError  # noqa
from .client import request  # noqa
from .cookiejar import CookieJar  # noqa
from .cookiejar import DummyCookieJar  # noqa
from .formdata import FormData  # noqa
from .helpers import BasicAuth  # noqa
from .helpers import ChainMapProxy  # noqa
from .http import (HttpVersion, HttpVersion10, HttpVersion11,  # noqa
                   WSMsgType, WSCloseCode, WSMessage, WebSocketError)  # noqa
from .multipart import BadContentDispositionHeader  # noqa
from .multipart import BadContentDispositionParam  # noqa
from .multipart import BodyPartReader  # noqa
from .multipart import MultipartReader  # noqa
from .multipart import MultipartWriter  # noqa
from .multipart import content_disposition_filename  # noqa
from .multipart import parse_content_disposition  # noqa
from .payload import AsyncIterablePayload  # noqa
from .payload import BufferedReaderPayload  # noqa
from .payload import BytesIOPayload  # noqa
from .payload import BytesPayload  # noqa
from .payload import IOBasePayload  # noqa
from .payload import JsonPayload  # noqa
from .payload import PAYLOAD_REGISTRY  # noqa
from .payload import Payload  # noqa
from .payload import StringIOPayload  # noqa
from .payload import StringPayload  # noqa
from .payload import TextIOPayload  # noqa
from .payload import get_payload  # noqa
from .payload import payload_type  # noqa
from .payload_streamer import streamer  # noqa
from .resolver import AsyncResolver  # noqa
from .resolver import DefaultResolver  # noqa
from .resolver import ThreadedResolver  # noqa
from .signals import Signal  # noqa
from .streams import DataQueue  # noqa
from .streams import EMPTY_PAYLOAD  # noqa
from .streams import EofStream  # noqa
from .streams import FlowControlDataQueue  # noqa
from .streams import StreamReader  # noqa
from .tracing import TraceConfig  # noqa
from .tracing import TraceConnectionCreateEndParams  # noqa
from .tracing import TraceConnectionCreateStartParams  # noqa
from .tracing import TraceConnectionQueuedEndParams  # noqa
from .tracing import TraceConnectionQueuedStartParams  # noqa
from .tracing import TraceConnectionReuseconnParams  # noqa
from .tracing import TraceDnsCacheHitParams  # noqa
from .tracing import TraceDnsCacheMissParams  # noqa
from .tracing import TraceDnsResolveHostEndParams  # noqa
from .tracing import TraceDnsResolveHostStartParams  # noqa
from .tracing import TraceRequestChunkSentParams  # noqa
from .tracing import TraceRequestEndParams  # noqa
from .tracing import TraceRequestExceptionParams  # noqa
from .tracing import TraceRequestRedirectParams  # noqa
from .tracing import TraceRequestStartParams  # noqa
from .tracing import TraceResponseChunkReceivedParams  # noqa

try:
    from .worker import GunicornWebWorker, GunicornUVLoopWebWorker  # noqa
    workers = ('GunicornWebWorker', 'GunicornUVLoopWebWorker')
except ImportError:  # pragma: no cover
    workers = ()  # type: ignore


__all__ = (client.__all__ +  # noqa
           cookiejar.__all__ +  # noqa
           formdata.__all__ +  # noqa
           helpers.__all__ +  # noqa
           multipart.__all__ +  # noqa
           payload.__all__ +  # noqa
           payload_streamer.__all__ +  # noqa
           streams.__all__ +  # noqa
           signals.__all__ +  # noqa
           tracing.__all__ + # noqa
           ('hdrs', 'HttpVersion', 'HttpVersion10', 'HttpVersion11',
            'WSMsgType', 'WSCloseCode',
            'WebSocketError', 'WSMessage',
           ) + workers)
