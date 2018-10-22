"""Low level HTTP server."""
import asyncio
from typing import Any, Awaitable, Callable, Dict, List, Optional  # noqa

from .abc import AbstractStreamWriter
from .http_parser import RawRequestMessage
from .streams import StreamReader
from .web_protocol import RequestHandler
from .web_request import BaseRequest
from .web_response import StreamResponse


__all__ = ('Server',)

_RequestFactory = Callable[[RawRequestMessage,
                            StreamReader,
                            RequestHandler,
                            AbstractStreamWriter,
                            'asyncio.Task[None]'],
                           BaseRequest]


class Server:

    def __init__(self,
                 handler: Callable[[BaseRequest], Awaitable[StreamResponse]],
                 *,
                 request_factory: Optional[_RequestFactory]=None,
                 loop: Optional[asyncio.AbstractEventLoop]=None,
                 **kwargs: Any) -> None:
        if loop is None:
            loop = asyncio.get_event_loop()
        self._loop = loop
        self._connections = {}  # type: Dict[RequestHandler, asyncio.Transport]
        self._kwargs = kwargs
        self.requests_count = 0
        self.request_handler = handler
        self.request_factory = request_factory or self._make_request

    @property
    def connections(self) -> List[RequestHandler]:
        return list(self._connections.keys())

    def connection_made(self, handler: RequestHandler,
                        transport: asyncio.Transport) -> None:
        self._connections[handler] = transport

    def connection_lost(self, handler: RequestHandler,
                        exc: Optional[BaseException]=None) -> None:
        if handler in self._connections:
            del self._connections[handler]

    def _make_request(self, message: RawRequestMessage,
                      payload: StreamReader,
                      protocol: RequestHandler,
                      writer: AbstractStreamWriter,
                      task: 'asyncio.Task[None]') -> BaseRequest:
        return BaseRequest(
            message, payload, protocol, writer, task, self._loop)

    async def shutdown(self, timeout: Optional[float]=None) -> None:
        coros = [conn.shutdown(timeout) for conn in self._connections]
        await asyncio.gather(*coros, loop=self._loop)
        self._connections.clear()

    def __call__(self) -> RequestHandler:
        return RequestHandler(self, loop=self._loop, **self._kwargs)
