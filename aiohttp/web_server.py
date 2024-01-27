"""Low level HTTP server."""
import asyncio
import warnings
from typing import Any, Dict, Generic, List, Optional

from .abc import AbstractStreamWriter
from .http_parser import RawRequestMessage
from .streams import StreamReader
from .web_protocol import RequestHandler, _RequestFactory, _RequestHandler, _RequestType
from .web_request import BaseRequest

__all__ = ("Server",)


class Server(Generic[_RequestType]):
    def __init__(
        self,
        handler: _RequestHandler[_RequestType],
        *,
        request_factory: Optional[_RequestFactory[_RequestType]] = None,
        debug: Optional[bool] = None,
        handler_cancellation: bool = False,
        **kwargs: Any,
    ) -> None:
        if debug is not None:
            warnings.warn(
                "debug argument is no-op since 4.0 " "and scheduled for removal in 5.0",
                DeprecationWarning,
                stacklevel=2,
            )
        self._loop = asyncio.get_running_loop()
        self._connections: Dict[RequestHandler[_RequestType], asyncio.Transport] = {}
        self._kwargs = kwargs
        self.requests_count = 0
        self.request_handler = handler
        # This line confuses the type check with RequestFactory is None, as it
        # can not infer that _RequestType is then always BaseRequest, and self._make_request
        # meet the request factory contract.
        self.request_factory: _RequestFactory[_RequestType] = request_factory or self._make_request  # type: ignore[assignment]
        self.handler_cancellation = handler_cancellation

    @property
    def connections(self) -> List[RequestHandler[_RequestType]]:
        return list(self._connections.keys())

    def connection_made(
        self, handler: RequestHandler[_RequestType], transport: asyncio.Transport
    ) -> None:
        self._connections[handler] = transport

    def connection_lost(
        self, handler: RequestHandler[_RequestType], exc: Optional[BaseException] = None
    ) -> None:
        if handler in self._connections:
            del self._connections[handler]

    def _make_request(
        self,
        message: RawRequestMessage,
        payload: StreamReader,
        protocol: RequestHandler[BaseRequest],
        writer: AbstractStreamWriter,
        task: "asyncio.Task[None]",
    ) -> BaseRequest:
        return BaseRequest(message, payload, protocol, writer, task, self._loop)

    def pre_shutdown(self) -> None:
        for conn in self._connections:
            conn.close()

    async def shutdown(self, timeout: Optional[float] = None) -> None:
        coros = (conn.shutdown(timeout) for conn in self._connections)
        await asyncio.gather(*coros)
        self._connections.clear()

    def __call__(self) -> RequestHandler[_RequestType]:
        try:
            return RequestHandler(self, loop=self._loop, **self._kwargs)
        except TypeError:
            # Failsafe creation: remove all custom handler_args
            kwargs = {
                k: v
                for k, v in self._kwargs.items()
                if k in ["debug", "access_log_class"]
            }
            return RequestHandler(self, loop=self._loop, **kwargs)
