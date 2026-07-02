# aiohttp/http_protocol.py (new file)
import asyncio
from typing import Optional

from .client_proto import ResponseHandler
from .http2.connection import Http2Protocol


class HttpDispatcherProtocol(asyncio.Protocol):
    """Protocol that switches between HTTP/1.1 and HTTP/2 based on ALPN."""

    __slots__ = ("_loop", "_transport", "_handler")

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self._transport: Optional[asyncio.Transport] = None
        self._handler: Optional[asyncio.Protocol] = None

    # ---- Transport callbacks forwarded to the real handler ----
    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        if self._handler:
            return self._handler.connection_made(transport)

        self._transport = transport  # type: ignore[assignment]

        # Determine ALPN after TLS is established
        ssl_object = transport.get_extra_info("ssl_object")
        alpn_protocol = (
            ssl_object.selected_alpn_protocol() if ssl_object else "http/1.1"
        )

        if alpn_protocol == "h2":
            self._handler = Http2Protocol(self._loop)
        else:
            self._handler = ResponseHandler(self._loop)

        # Hand the real transport to the handler. The handler will now own
        # all incoming data and callbacks.
        self._handler.connection_made(transport)

    def __getattribute__(self, name):
        if not name.startswith("__") and name not in {"connection_made", "__getattribute__", "_handler", "_transport", "_loop"}:
            return getattr(self._handler, name)
        return super().__getattribute__(name)
    
    def __setattr__(self, name, value):
        if name not in {"_handler", "_transport", "_loop"}:
            return self._handler.__setattr__(name, value)
        return super().__setattr__(name, value)
    
    def __delattr__(self, name):
        return self._handler.__delattr__(name)
