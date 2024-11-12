import asyncio
import asyncio.streams
import dataclasses
import sys
import traceback
from collections import deque
from contextlib import suppress
from html import escape as html_escape
from http import HTTPStatus
from logging import Logger
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    Deque,
    Generic,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
)

import yarl

from .abc import AbstractAccessLogger, AbstractAsyncAccessLogger, AbstractStreamWriter
from .base_protocol import BaseProtocol
from .helpers import ceil_timeout
from .http import (
    HttpProcessingError,
    HttpRequestParser,
    HttpVersion10,
    RawRequestMessage,
    StreamWriter,
)
from .log import access_logger, server_logger
from .streams import EMPTY_PAYLOAD, StreamReader
from .tcp_helpers import tcp_keepalive
from .web_exceptions import HTTPException, HTTPInternalServerError
from .web_log import AccessLogger
from .web_request import BaseRequest
from .web_response import Response, StreamResponse

__all__ = ("RequestHandler", "RequestPayloadError", "PayloadAccessError")

if TYPE_CHECKING:
    from .web_server import Server


_Request = TypeVar("_Request", bound=BaseRequest)
_RequestFactory = Callable[
    [
        RawRequestMessage,
        StreamReader,
        "RequestHandler[_Request]",
        AbstractStreamWriter,
        "asyncio.Task[None]",
    ],
    _Request,
]

_RequestHandler = Callable[[_Request], Awaitable[StreamResponse]]
_AnyAbstractAccessLogger = Union[
    Type[AbstractAsyncAccessLogger],
    Type[AbstractAccessLogger],
]

ERROR = RawRequestMessage(
    "UNKNOWN",
    "/",
    HttpVersion10,
    {},  # type: ignore[arg-type]
    {},  # type: ignore[arg-type]
    True,
    None,
    False,
    False,
    yarl.URL("/"),
)


class RequestPayloadError(Exception):
    """Payload parsing error."""


class PayloadAccessError(Exception):
    """Payload was accessed after response was sent."""


_PAYLOAD_ACCESS_ERROR = PayloadAccessError()


class AccessLoggerWrapper(AbstractAsyncAccessLogger):
    """Wrap an AbstractAccessLogger so it behaves like an AbstractAsyncAccessLogger."""

    __slots__ = ("access_logger", "_loop")

    def __init__(
        self, access_logger: AbstractAccessLogger, loop: asyncio.AbstractEventLoop
    ) -> None:
        self.access_logger = access_logger
        self._loop = loop
        super().__init__()

    async def log(
        self, request: BaseRequest, response: StreamResponse, request_start: float
    ) -> None:
        self.access_logger.log(request, response, self._loop.time() - request_start)

    @property
    def enabled(self) -> bool:
        """Check if logger is enabled."""
        return self.access_logger.enabled


@dataclasses.dataclass(frozen=True)
class _ErrInfo:
    status: int
    exc: BaseException
    message: str


_MsgType = Tuple[Union[RawRequestMessage, _ErrInfo], StreamReader]


class RequestHandler(BaseProtocol, Generic[_Request]):
    """HTTP protocol implementation.

    RequestHandler handles incoming HTTP request. It reads request line,
    request headers and request payload and calls handle_request() method.
    By default it always returns with 404 response.

    RequestHandler handles errors in incoming request, like bad
    status line, bad headers or incomplete payload. If any error occurs,
    connection gets closed.

    keepalive_timeout -- number of seconds before closing
                         keep-alive connection

    tcp_keepalive -- TCP keep-alive is on, default is on

    logger -- custom logger object

    access_log_class -- custom class for access_logger

    access_log -- custom logging object

    access_log_format -- access log format string

    loop -- Optional event loop

    max_line_size -- Optional maximum header line size

    max_field_size -- Optional maximum header field size

    timeout_ceil_threshold -- Optional value to specify
                              threshold to ceil() timeout
                              values

    """

    __slots__ = (
        "_request_count",
        "_keepalive",
        "_manager",
        "_request_handler",
        "_request_factory",
        "_tcp_keepalive",
        "_next_keepalive_close_time",
        "_keepalive_handle",
        "_keepalive_timeout",
        "_lingering_time",
        "_messages",
        "_message_tail",
        "_handler_waiter",
        "_waiter",
        "_task_handler",
        "_upgrade",
        "_payload_parser",
        "_request_parser",
        "logger",
        "access_log",
        "access_logger",
        "_close",
        "_force_close",
        "_current_request",
        "_timeout_ceil_threshold",
        "_request_in_progress",
    )

    def __init__(
        self,
        manager: "Server[_Request]",
        *,
        loop: asyncio.AbstractEventLoop,
        # Default should be high enough that it's likely longer than a reverse proxy.
        keepalive_timeout: float = 3630,
        tcp_keepalive: bool = True,
        logger: Logger = server_logger,
        access_log_class: _AnyAbstractAccessLogger = AccessLogger,
        access_log: Optional[Logger] = access_logger,
        access_log_format: str = AccessLogger.LOG_FORMAT,
        max_line_size: int = 8190,
        max_field_size: int = 8190,
        lingering_time: float = 10.0,
        read_bufsize: int = 2**16,
        auto_decompress: bool = True,
        timeout_ceil_threshold: float = 5,
    ):
        super().__init__(loop)

        self._request_count = 0
        self._keepalive = False
        self._current_request: Optional[_Request] = None
        self._manager: Optional[Server[_Request]] = manager
        self._request_handler: Optional[_RequestHandler[_Request]] = (
            manager.request_handler
        )
        self._request_factory: Optional[_RequestFactory[_Request]] = (
            manager.request_factory
        )

        self._tcp_keepalive = tcp_keepalive
        # placeholder to be replaced on keepalive timeout setup
        self._next_keepalive_close_time = 0.0
        self._keepalive_handle: Optional[asyncio.Handle] = None
        self._keepalive_timeout = keepalive_timeout
        self._lingering_time = float(lingering_time)

        self._messages: Deque[_MsgType] = deque()
        self._message_tail = b""

        self._waiter: Optional[asyncio.Future[None]] = None
        self._handler_waiter: Optional[asyncio.Future[None]] = None
        self._task_handler: Optional[asyncio.Task[None]] = None

        self._upgrade = False
        self._payload_parser: Any = None
        self._request_parser: Optional[HttpRequestParser] = HttpRequestParser(
            self,
            loop,
            read_bufsize,
            max_line_size=max_line_size,
            max_field_size=max_field_size,
            payload_exception=RequestPayloadError,
            auto_decompress=auto_decompress,
        )

        self._timeout_ceil_threshold: float = 5
        try:
            self._timeout_ceil_threshold = float(timeout_ceil_threshold)
        except (TypeError, ValueError):
            pass

        self.logger = logger
        self.access_log = access_log
        if access_log:
            if issubclass(access_log_class, AbstractAsyncAccessLogger):
                self.access_logger: Optional[AbstractAsyncAccessLogger] = (
                    access_log_class()
                )
            else:
                access_logger = access_log_class(access_log, access_log_format)
                self.access_logger = AccessLoggerWrapper(
                    access_logger,
                    self._loop,
                )
        else:
            self.access_logger = None

        self._close = False
        self._force_close = False
        self._request_in_progress = False

    def __repr__(self) -> str:
        return "<{} {}>".format(
            self.__class__.__name__,
            "connected" if self.transport is not None else "disconnected",
        )

    @property
    def keepalive_timeout(self) -> float:
        return self._keepalive_timeout

    async def shutdown(self, timeout: Optional[float] = 15.0) -> None:
        """Do worker process exit preparations.

        We need to clean up everything and stop accepting requests.
        It is especially important for keep-alive connections.
        """
        self._force_close = True

        if self._keepalive_handle is not None:
            self._keepalive_handle.cancel()

        # Wait for graceful handler completion
        if self._request_in_progress:
            # The future is only created when we are shutting
            # down while the handler is still processing a request
            # to avoid creating a future for every request.
            self._handler_waiter = self._loop.create_future()
            try:
                async with ceil_timeout(timeout):
                    await self._handler_waiter
            except (asyncio.CancelledError, asyncio.TimeoutError):
                self._handler_waiter = None
                if (
                    sys.version_info >= (3, 11)
                    and (task := asyncio.current_task())
                    and task.cancelling()
                ):
                    raise
        # Then cancel handler and wait
        try:
            async with ceil_timeout(timeout):
                if self._current_request is not None:
                    self._current_request._cancel(asyncio.CancelledError())

                if self._task_handler is not None and not self._task_handler.done():
                    await asyncio.shield(self._task_handler)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            if (
                sys.version_info >= (3, 11)
                and (task := asyncio.current_task())
                and task.cancelling()
            ):
                raise

        # force-close non-idle handler
        if self._task_handler is not None:
            self._task_handler.cancel()

        self.force_close()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        super().connection_made(transport)

        real_transport = cast(asyncio.Transport, transport)
        if self._tcp_keepalive:
            tcp_keepalive(real_transport)

        assert self._manager is not None
        self._manager.connection_made(self, real_transport)

        loop = self._loop
        if sys.version_info >= (3, 12):
            task = asyncio.Task(self.start(), loop=loop, eager_start=True)
        else:
            task = loop.create_task(self.start())
        self._task_handler = task

    def connection_lost(self, exc: Optional[BaseException]) -> None:
        if self._manager is None:
            return
        self._manager.connection_lost(self, exc)

        # Grab value before setting _manager to None.
        handler_cancellation = self._manager.handler_cancellation

        self.force_close()
        super().connection_lost(exc)
        self._manager = None
        self._request_factory = None
        self._request_handler = None
        self._request_parser = None

        if self._keepalive_handle is not None:
            self._keepalive_handle.cancel()

        if self._current_request is not None:
            if exc is None:
                exc = ConnectionResetError("Connection lost")
            self._current_request._cancel(exc)

        if handler_cancellation and self._task_handler is not None:
            self._task_handler.cancel()

        self._task_handler = None

        if self._payload_parser is not None:
            self._payload_parser.feed_eof()
            self._payload_parser = None

    def set_parser(self, parser: Any) -> None:
        # Actual type is WebReader
        assert self._payload_parser is None

        self._payload_parser = parser

        if self._message_tail:
            self._payload_parser.feed_data(self._message_tail)
            self._message_tail = b""

    def eof_received(self) -> None:
        pass

    def data_received(self, data: bytes) -> None:
        if self._force_close or self._close:
            return
        # parse http messages
        messages: Sequence[_MsgType]
        if self._payload_parser is None and not self._upgrade:
            assert self._request_parser is not None
            try:
                messages, upgraded, tail = self._request_parser.feed_data(data)
            except HttpProcessingError as exc:
                messages = [
                    (_ErrInfo(status=400, exc=exc, message=exc.message), EMPTY_PAYLOAD)
                ]
                upgraded = False
                tail = b""

            for msg, payload in messages or ():
                self._request_count += 1
                self._messages.append((msg, payload))

            waiter = self._waiter
            if messages and waiter is not None and not waiter.done():
                # don't set result twice
                waiter.set_result(None)

            self._upgrade = upgraded
            if upgraded and tail:
                self._message_tail = tail

        # no parser, just store
        elif self._payload_parser is None and self._upgrade and data:
            self._message_tail += data

        # feed payload
        elif data:
            eof, tail = self._payload_parser.feed_data(data)
            if eof:
                self.close()

    def keep_alive(self, val: bool) -> None:
        """Set keep-alive connection mode.

        :param bool val: new state.
        """
        self._keepalive = val
        if self._keepalive_handle:
            self._keepalive_handle.cancel()
            self._keepalive_handle = None

    def close(self) -> None:
        """Close connection.

        Stop accepting new pipelining messages and close
        connection when handlers done processing messages.
        """
        self._close = True
        if self._waiter:
            self._waiter.cancel()

    def force_close(self) -> None:
        """Forcefully close connection."""
        self._force_close = True
        if self._waiter:
            self._waiter.cancel()
        if self.transport is not None:
            self.transport.close()
            self.transport = None

    async def log_access(
        self, request: BaseRequest, response: StreamResponse, request_start: float
    ) -> None:
        if self.access_logger is not None and self.access_logger.enabled:
            await self.access_logger.log(request, response, request_start)

    def log_debug(self, *args: Any, **kw: Any) -> None:
        if self._loop.get_debug():
            self.logger.debug(*args, **kw)

    def log_exception(self, *args: Any, **kw: Any) -> None:
        self.logger.exception(*args, **kw)

    def _process_keepalive(self) -> None:
        self._keepalive_handle = None
        if self._force_close or not self._keepalive:
            return

        loop = self._loop
        now = loop.time()
        close_time = self._next_keepalive_close_time
        if now <= close_time:
            # Keep alive close check fired too early, reschedule
            self._keepalive_handle = loop.call_at(close_time, self._process_keepalive)
            return

        # handler in idle state
        if self._waiter and not self._waiter.done():
            self.force_close()

    async def _handle_request(
        self,
        request: _Request,
        start_time: float,
        request_handler: Callable[[_Request], Awaitable[StreamResponse]],
    ) -> Tuple[StreamResponse, bool]:
        self._request_in_progress = True
        try:
            try:
                self._current_request = request
                resp = await request_handler(request)
            finally:
                self._current_request = None
        except HTTPException as exc:
            resp = Response(
                status=exc.status, reason=exc.reason, text=exc.text, headers=exc.headers
            )
            resp._cookies = exc._cookies
            resp, reset = await self.finish_response(request, resp, start_time)
        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError as exc:
            self.log_debug("Request handler timed out.", exc_info=exc)
            resp = self.handle_error(request, 504)
            resp, reset = await self.finish_response(request, resp, start_time)
        except Exception as exc:
            resp = self.handle_error(request, 500, exc)
            resp, reset = await self.finish_response(request, resp, start_time)
        else:
            resp, reset = await self.finish_response(request, resp, start_time)
        finally:
            self._request_in_progress = False
            if self._handler_waiter is not None:
                self._handler_waiter.set_result(None)

        return resp, reset

    async def start(self) -> None:
        """Process incoming request.

        It reads request line, request headers and request payload, then
        calls handle_request() method. Subclass has to override
        handle_request(). start() handles various exceptions in request
        or response handling. Connection is being closed always unless
        keep_alive(True) specified.
        """
        loop = self._loop
        handler = asyncio.current_task(loop)
        assert handler is not None
        manager = self._manager
        assert manager is not None
        keepalive_timeout = self._keepalive_timeout
        resp = None
        assert self._request_factory is not None
        assert self._request_handler is not None

        while not self._force_close:
            if not self._messages:
                try:
                    # wait for next request
                    self._waiter = loop.create_future()
                    await self._waiter
                finally:
                    self._waiter = None

            message, payload = self._messages.popleft()

            start = loop.time()

            manager.requests_count += 1
            writer = StreamWriter(self, loop)
            if not isinstance(message, _ErrInfo):
                request_handler = self._request_handler
            else:
                # make request_factory work
                request_handler = self._make_error_handler(message)
                message = ERROR

            request = self._request_factory(message, payload, self, writer, handler)
            try:
                # a new task is used for copy context vars (#3406)
                coro = self._handle_request(request, start, request_handler)
                if sys.version_info >= (3, 12):
                    task = asyncio.Task(coro, loop=loop, eager_start=True)
                else:
                    task = loop.create_task(coro)
                try:
                    resp, reset = await task  # type: ignore[possibly-undefined]
                except ConnectionError:
                    self.log_debug("Ignored premature client disconnection")
                    break

                # Drop the processed task from asyncio.Task.all_tasks() early
                del task  # type: ignore[possibly-undefined]
                # https://github.com/python/mypy/issues/14309
                if reset:  # type: ignore[possibly-undefined]
                    self.log_debug("Ignored premature client disconnection 2")
                    break

                # notify server about keep-alive
                self._keepalive = bool(resp.keep_alive)

                # check payload
                if not payload.is_eof():
                    lingering_time = self._lingering_time
                    # Could be force closed while awaiting above tasks.
                    if not self._force_close and lingering_time:  # type: ignore[redundant-expr]
                        self.log_debug(
                            "Start lingering close timer for %s sec.", lingering_time
                        )

                        now = loop.time()
                        end_t = now + lingering_time

                        try:
                            while not payload.is_eof() and now < end_t:
                                async with ceil_timeout(end_t - now):
                                    # read and ignore
                                    await payload.readany()
                                now = loop.time()
                        except (asyncio.CancelledError, asyncio.TimeoutError):
                            if (
                                sys.version_info >= (3, 11)
                                and (t := asyncio.current_task())
                                and t.cancelling()
                            ):
                                raise

                    # if payload still uncompleted
                    if not payload.is_eof() and not self._force_close:
                        self.log_debug("Uncompleted request.")
                        self.close()

                payload.set_exception(_PAYLOAD_ACCESS_ERROR)

            except asyncio.CancelledError:
                self.log_debug("Ignored premature client disconnection")
                raise
            except Exception as exc:
                self.log_exception("Unhandled exception", exc_info=exc)
                self.force_close()
            finally:
                if self.transport is None and resp is not None:
                    self.log_debug("Ignored premature client disconnection.")
                elif not self._force_close:
                    if self._keepalive and not self._close:
                        # start keep-alive timer
                        if keepalive_timeout is not None:
                            now = loop.time()
                            close_time = now + keepalive_timeout
                            self._next_keepalive_close_time = close_time
                            if self._keepalive_handle is None:
                                self._keepalive_handle = loop.call_at(
                                    close_time, self._process_keepalive
                                )
                    else:
                        break

        # remove handler, close transport if no handlers left
        if not self._force_close:
            self._task_handler = None
            if self.transport is not None:
                self.transport.close()

    async def finish_response(
        self, request: BaseRequest, resp: StreamResponse, start_time: float
    ) -> Tuple[StreamResponse, bool]:
        """Prepare the response and write_eof, then log access.

        This has to
        be called within the context of any exception so the access logger
        can get exception information. Returns True if the client disconnects
        prematurely.
        """
        request._finish()
        if self._request_parser is not None:
            self._request_parser.set_upgraded(False)
            self._upgrade = False
            if self._message_tail:
                self._request_parser.feed_data(self._message_tail)
                self._message_tail = b""
        try:
            prepare_meth = resp.prepare
        except AttributeError:
            if resp is None:
                self.log_exception("Missing return statement on request handler")  # type: ignore[unreachable]
            else:
                self.log_exception(
                    "Web-handler should return a response instance, "
                    "got {!r}".format(resp)
                )
            exc = HTTPInternalServerError()
            resp = Response(
                status=exc.status, reason=exc.reason, text=exc.text, headers=exc.headers
            )
            prepare_meth = resp.prepare
        try:
            await prepare_meth(request)
            await resp.write_eof()
        except ConnectionError:
            await self.log_access(request, resp, start_time)
            return resp, True

        await self.log_access(request, resp, start_time)
        return resp, False

    def handle_error(
        self,
        request: BaseRequest,
        status: int = 500,
        exc: Optional[BaseException] = None,
        message: Optional[str] = None,
    ) -> StreamResponse:
        """Handle errors.

        Returns HTTP response with specific status code. Logs additional
        information. It always closes current connection.
        """
        self.log_exception("Error handling request", exc_info=exc)

        # some data already got sent, connection is broken
        if request.writer.output_size > 0:
            raise ConnectionError(
                "Response is sent already, cannot send another response "
                "with the error message"
            )

        ct = "text/plain"
        if status == HTTPStatus.INTERNAL_SERVER_ERROR:
            title = "{0.value} {0.phrase}".format(HTTPStatus.INTERNAL_SERVER_ERROR)
            msg = HTTPStatus.INTERNAL_SERVER_ERROR.description
            tb = None
            if self._loop.get_debug():
                with suppress(Exception):
                    tb = traceback.format_exc()

            if "text/html" in request.headers.get("Accept", ""):
                if tb:
                    tb = html_escape(tb)
                    msg = f"<h2>Traceback:</h2>\n<pre>{tb}</pre>"
                message = (
                    "<html><head>"
                    "<title>{title}</title>"
                    "</head><body>\n<h1>{title}</h1>"
                    "\n{msg}\n</body></html>\n"
                ).format(title=title, msg=msg)
                ct = "text/html"
            else:
                if tb:
                    msg = tb
                message = title + "\n\n" + msg

        resp = Response(status=status, text=message, content_type=ct)
        resp.force_close()

        return resp

    def _make_error_handler(
        self, err_info: _ErrInfo
    ) -> Callable[[BaseRequest], Awaitable[StreamResponse]]:
        async def handler(request: BaseRequest) -> StreamResponse:
            return self.handle_error(
                request, err_info.status, err_info.exc, err_info.message
            )

        return handler
