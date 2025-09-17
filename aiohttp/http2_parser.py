from typing import (
    Generic,
    List,
    NamedTuple,
    Optional,
    Tuple,
    TypeVar,
    Union,
    TYPE_CHECKING
)

from multidict import CIMultiDict, CIMultiDictProxy, istr
from yarl import URL

from .typedefs import RawHeaders
from .streams import EMPTY_PAYLOAD, StreamReader

from hpack.hpack import Decoder
from hyperframe.frame import HeadersFrame, ContinuationFrame, Frame, GoAwayFrame
from h2.frame_buffer import FrameBuffer

from .http_parser import RawRequestMessage, RawResponseMessage, _MsgT
import base64 # TODO: Pybase64 or libbase64 in Cython would be a good idea here...
from . import hdrs

from .compression_utils import (
    HAS_BROTLI,
    HAS_ZSTD,
    BrotliDecompressor,
    ZLibDecompressor,
    ZSTDDecompressor,
)

from abc import ABC, abstractmethod
from types import GenericAlias

from http_writer import HttpVersion, HttpVersion20

# TODO: Something simillar to llhttp would be effective. 
# A Parody of llparse for python also exists (Thanks to me, Vizonex) and making 
# A http2 frameparser in C would be pretty simple.
DEFAULT_MAX_HEADER_LIST_SIZE = 2 ** 16

class PartialResponseMessage(NamedTuple):
    """utilizes the Building blocks for a RawResponseMessage"""
    version: HttpVersion = HttpVersion20
    code: Optional[int] = None
    reason: Optional[str] = None
    headers: Optional[CIMultiDict[str]] = None
    # raw_headers should be extendable with partials since Continuation frames can happen...
    raw_headers: List[Tuple[bytes, bytes]] = list()
    should_close: bool = False
    compression: Optional[str] = None
    upgrade: Optional[bool] = None
    chunked: Optional[bool] = None



class PartialRequestMessage(NamedTuple):
    """utilizes the Building blocks for a RawRequestMessage"""
    method: Optional[str] = None
    path: Optional[str] = None
    version: HttpVersion = HttpVersion20
    headers: "Optional[CIMultiDict[str]]" = None
    raw_headers: List[Tuple[bytes, bytes]] = list()
    should_close: bool = False
    compression: Optional[str]
    upgrade: Optional[bool] = None
    chunked: Optional[bool] = None
    url: Optional[URL] = None

_PartialMsgT = TypeVar("_PartialMsgT", PartialResponseMessage, PartialRequestMessage)


class AbstractFrameParser(ABC, Generic[_MsgT, _PartialMsgT]):
    """inspired by the h2 this Parser parses http/2 frames 
    and other data until considered ready to send back a response"""
    __class_getitem__ = classmethod(GenericAlias)
    
    # NOTE: This is not in the AbstractFrameParser and must be initalized elsewhere.
    _buffer: FrameBuffer

    @property
    def should_disconnect(self):
        """Immutable property for dealing with go-away frames (Server Related, Serves no use on the ClientFrameParser)"""
        return self._go_away_issued
    
    @should_disconnect.setter
    def should_disconnect(self, value:bool):
        raise AttributeError("should_disconnect is immutable")

    def reset(self):
        self._partial = self.create_partial()
        self._response = None

    @abstractmethod
    def parse_message(self) -> _MsgT:...
    
    @abstractmethod
    def create_buffer(self) -> FrameBuffer:...

    @abstractmethod
    def create_partial(self) -> _PartialMsgT:...

    def __init__(
        self,
        max_line_size: int = 8190,
        max_headers: int = 32768,
        max_field_size: int = 8190
    ) -> None:
        self.max_line_size = max_line_size
        self.max_headers = max_headers
        self.max_field_size = max_field_size

        self._buffer = self.create_buffer()
        self._decoder = Decoder(max_headers)
        self._partial = self.create_partial()
        self._response: Optional[_MsgT] = None
        self._go_away_issued = False

    def feed_data(
        self,
        data: Union[bytes, bytearray, memoryview]
    ) -> tuple[list[Frame], Optional[_MsgT], bool]:
        """return a list of frames, response if it can be issued and parses 
        a given set of raw http/2 data"""
        data_frames: list[Frame] = []
        self._buffer.add_data(data)
        for frame in self._buffer:
            if isinstance(frame, (HeadersFrame, ContinuationFrame)):
                # Do not allow multiple HeadersFrames if already closed

                # As an aggressive measure against bad actors who wish to abuse the http/2 system, 
                # allow multiple header-frames and continuation-frames but don't reset parser until 
                # end developer says to.
                if self._response is not None:
                    # XXX: Still under concept but throwing an exception at this point would be acceptable as we already
                    # Got frames from this response and don't need more unless parser was reset.
                    raise RuntimeError("Header frames were already obtained")
                

                self._partial.raw_headers.extend(self._decoder.decode(frame.data, raw=True))
                # TODO: HPack Could use better typehint overloads and a pull request for that may suffice :)
                for k, v in self._decoder.decode(frame.data, raw=False):
                    if TYPE_CHECKING:
                        # headers types are truthy and are really strings and not bytes since 
                        # we set raw to False
                        assert isinstance(k, str)
                        assert isinstance(v, str)
                    self._partial.headers.add(k, v)

                if "END_HEADERS" in frame.flags:
                    # Headers are ready
                    self._response = self.parse_message()
            
            elif isinstance(frame, GoAwayFrame):
                # Do not accept anymore requests after this one 
                # since server/client wants to disconnect this stream
                self._partial.should_close = self._go_away_issued = True
            else:
                data_frames.append(frame)
            

        return data_frames, self._response, self._go_away_issued 


class ClientFrameParser(AbstractFrameParser[RawResponseMessage, PartialResponseMessage]):
    """Parses incoming http2 respones from a server"""
    def create_buffer(self):
        return FrameBuffer(server=False)
    
    def create_partial(self):
        return PartialResponseMessage()
    
    # TODO: Need to figure out how http2 headers work (will need to add custom hdrs things too)
    def parse_message(self):
        return super().parse_message()

class ServerFrameParser(AbstractFrameParser[RawRequestMessage, PartialRequestMessage]):
    """Parses incomming http2 requests from a client"""
    def create_buffer(self):
        return FrameBuffer(server=True)

    def create_partial(self):
        return PartialRequestMessage()
    
    # TODO: Need to figure out how http2 headers work (will need to add custom hdrs things too)
    def parse_message(self):
        return super().parse_message()
    
