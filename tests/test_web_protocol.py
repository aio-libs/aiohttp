import asyncio
import gc
from typing import Any
from unittest import mock

import pytest

from aiohttp.http import WebSocketReader
from aiohttp.web_protocol import RequestHandler
from aiohttp.web_request import BaseRequest
from aiohttp.web_response import Response
from aiohttp.web_server import Server


@pytest.fixture
def dummy_manager() -> Server[BaseRequest]:
    return mock.create_autospec(Server[BaseRequest], request_handler=mock.Mock(), request_factory=mock.Mock(), instance=True)  # type: ignore[no-any-return]


@pytest.fixture
def dummy_reader() -> tuple[WebSocketReader, mock.Mock]:
    m = mock.create_autospec(WebSocketReader, spec_set=True, instance=True)
    m.feed_data.return_value = False, b""
    return m, m


def test_set_parser_does_not_call_data_received_cb_for_tail(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
    dummy_reader: tuple[WebSocketReader, mock.Mock],
) -> None:
    handler = RequestHandler(dummy_manager, loop=event_loop)
    handler._message_tail = b"tail"
    cb = mock.Mock()

    handler.set_parser(dummy_reader[0], data_received_cb=cb)

    cb.assert_not_called()
    dummy_reader[1].feed_data.assert_called_once_with(b"tail")


def test_data_received_calls_data_received_cb(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
    dummy_reader: tuple[WebSocketReader, mock.Mock],
) -> None:
    handler = RequestHandler(dummy_manager, loop=event_loop)
    cb = mock.Mock()

    handler.set_parser(dummy_reader[0], data_received_cb=cb)
    handler.data_received(b"x")

    cb.assert_called_once()
    dummy_reader[1].feed_data.assert_called_once_with(b"x")


def test_pause_reading_for_buffer_without_transport(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """Pausing with no transport still records the paused state."""
    handler = RequestHandler(dummy_manager, loop=event_loop)
    handler.transport = None

    handler._pause_reading_for_buffer()

    assert handler._buffer_paused is True


def test_resume_reading_if_drained_after_upgrade_skips_reparse(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """Resume after an upgrade clears the pause and resumes without reparsing."""
    handler = RequestHandler(dummy_manager, loop=event_loop)
    transport = mock.Mock()
    handler.transport = transport
    handler._upgraded = True
    handler._buffer_paused = True
    handler._reading_paused = False

    with mock.patch.object(RequestHandler, "data_received") as data_received:
        handler._resume_reading_if_drained()

    data_received.assert_not_called()
    assert handler._buffer_paused is False
    transport.resume_reading.assert_called_once_with()


def test_resume_reading_if_drained_without_transport(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """Resume clears the pause but does not touch a missing transport."""
    handler = RequestHandler(dummy_manager, loop=event_loop)
    handler.transport = None
    handler._upgraded = True  # skip the reparse branch
    handler._buffer_paused = True

    handler._resume_reading_if_drained()

    assert handler._buffer_paused is False


def test_resume_reading_if_drained_stays_paused_for_full_tail(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """Resume is refused while an in-flight upgrade holds read_bufsize of tail.

    The tail is drained by set_parser()/finish_response(), so resuming before
    then would let the buffer grow past its ceiling one read at a time.
    """
    handler = RequestHandler(dummy_manager, loop=event_loop, read_bufsize=1024)
    transport = mock.create_autospec(asyncio.Transport, spec_set=True, instance=True)
    handler.transport = transport
    handler._upgraded = True
    handler._buffer_paused = True
    handler._message_tail = b"x" * 1024

    handler._resume_reading_if_drained()

    assert handler._buffer_paused is True
    transport.resume_reading.assert_not_called()


def test_resume_reading_if_drained_with_room_left_in_tail(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """A tail under read_bufsize does not hold the transport paused."""
    handler = RequestHandler(dummy_manager, loop=event_loop, read_bufsize=1024)
    transport = mock.create_autospec(asyncio.Transport, spec_set=True, instance=True)
    handler.transport = transport
    handler._upgraded = True
    handler._buffer_paused = True
    handler._message_tail = b"x" * 1023

    handler._resume_reading_if_drained()

    assert handler._buffer_paused is False
    transport.resume_reading.assert_called_once_with()


def test_resume_reading_if_drained_with_zero_read_bufsize(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """An empty tail resumes even when read_bufsize leaves it no room.

    Guards the degenerate ``read_bufsize=0`` case: comparing sizes alone would
    match an empty tail and wedge the connection paused for good.
    """
    handler = RequestHandler(dummy_manager, loop=event_loop, read_bufsize=0)
    transport = mock.create_autospec(asyncio.Transport, spec_set=True, instance=True)
    handler.transport = transport
    handler._upgraded = True
    handler._buffer_paused = True

    handler._resume_reading_if_drained()

    assert handler._buffer_paused is False
    transport.resume_reading.assert_called_once_with()


def test_set_parser_resumes_reading_paused_for_tail(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
    dummy_reader: tuple[WebSocketReader, mock.Mock],
) -> None:
    """Handing a full tail to the upgraded protocol resumes reading."""
    handler = RequestHandler(dummy_manager, loop=event_loop, read_bufsize=1024)
    transport = mock.create_autospec(asyncio.Transport, spec_set=True, instance=True)
    handler.transport = transport
    handler._upgraded = True
    handler._buffer_paused = True
    handler._message_tail = b"x" * 1024

    handler.set_parser(dummy_reader[0])

    dummy_reader[1].feed_data.assert_called_once_with(b"x" * 1024)
    assert handler._message_tail == b""
    assert handler._buffer_paused is False
    transport.resume_reading.assert_called_once_with()


def test_resume_reading_stays_paused_for_msg_queue(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """Base resume_reading must not un-pause the transport while queue-paused."""
    handler = RequestHandler(dummy_manager, loop=event_loop)
    transport = mock.Mock()
    handler.transport = transport
    handler._buffer_paused = True

    handler.resume_reading()

    transport.resume_reading.assert_not_called()


def test_pause_reading_for_buffer_ignores_unsupported_transport(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """A transport without flow control raising on pause is ignored."""
    handler = RequestHandler(dummy_manager, loop=event_loop)
    # Bare asyncio.Transport.pause_reading() raises NotImplementedError.
    handler.transport = asyncio.Transport()

    handler._pause_reading_for_buffer()

    assert handler._buffer_paused is True


def test_resume_reading_if_drained_ignores_unsupported_transport(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """A transport without flow control raising on resume is ignored."""
    handler = RequestHandler(dummy_manager, loop=event_loop)
    # Bare asyncio.Transport.resume_reading() raises NotImplementedError.
    handler.transport = asyncio.Transport()
    handler._upgraded = True  # skip the reparse branch
    handler._buffer_paused = True

    handler._resume_reading_if_drained()

    assert handler._buffer_paused is False


class _FatalError(BaseException):
    """Escapes RequestHandler.start() (not caught by ``except Exception``)."""


async def _ok_handler(request: BaseRequest) -> Response:
    return Response(text="ok")


def _make_protocol(
    loop: asyncio.AbstractEventLoop, request_factory: Any = None
) -> tuple[RequestHandler[BaseRequest], mock.Mock]:
    server = Server(_ok_handler, request_factory=request_factory)
    proto = RequestHandler(server, loop=loop)
    transport = mock.Mock()
    transport.is_closing.return_value = False
    proto.connection_made(transport)
    return proto, transport


async def _assert_no_unretrieved_task_exception(
    loop: asyncio.AbstractEventLoop, contexts: list[dict[str, Any]]
) -> None:
    """Force collection of dead tasks and check nothing was left unretrieved."""
    gc.collect()
    await asyncio.sleep(0.1)
    gc.collect()
    await asyncio.sleep(0.1)
    gc.collect()
    unretrieved = [
        ctx for ctx in contexts if "never retrieved" in str(ctx.get("message", ""))
    ]
    assert unretrieved == []


async def test_connection_lost_with_buffered_request_no_task_exception() -> None:
    """A request buffered just before connection_lost must not be processed.

    Regression test for #6978: when the connection was lost while the
    start() task was parked on the waiter and a message was already buffered,
    the task woke up and tried to build a request on the torn-down protocol.
    That raised (``TypeError``/``AssertionError``) inside the handler task
    and, since nobody awaited the finished task, the loop reported
    "Task exception was never retrieved".
    """
    loop = asyncio.get_running_loop()
    contexts: list[dict[str, Any]] = []
    loop.set_exception_handler(lambda _loop, ctx: contexts.append(ctx))

    request_factory = mock.Mock()
    proto, _transport = _make_protocol(loop, request_factory=request_factory)
    task = proto._task_handler
    assert task is not None

    # On Python 3.11 connection_made() schedules start() with
    # loop.create_task(), so give the task a chance to actually start before
    # the connection is lost below.
    await asyncio.sleep(0)

    # A full request is parsed and buffered, waking the waiter, but the
    # start() task has not had a chance to run yet.
    proto.data_received(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    assert len(proto._messages) == 1

    # The connection is lost before the task processes the buffered message.
    proto.connection_lost(None)

    await asyncio.sleep(0.1)
    assert task.done()
    assert not task.cancelled()
    # The task must finish cleanly instead of raising on the dead protocol.
    assert task.exception() is None
    request_factory.assert_not_called()

    del task, proto
    await _assert_no_unretrieved_task_exception(loop, contexts)


async def test_request_factory_exception_is_logged_and_connection_closed() -> None:
    """A request factory raising Exception is logged and closes the connection. (#6978)

    Covers the ``except Exception`` branch around request construction in
    start(): the error must be logged, the connection force-closed, and the
    handler task must finish without an unretrieved exception.
    """
    loop = asyncio.get_running_loop()
    contexts: list[dict[str, Any]] = []
    loop.set_exception_handler(lambda _loop, ctx: contexts.append(ctx))

    def bad_factory(*args: Any, **kwargs: Any) -> BaseRequest:
        raise RuntimeError("boom")

    proto, transport = _make_protocol(loop, request_factory=bad_factory)
    task = proto._task_handler
    assert task is not None

    with mock.patch.object(type(proto), "log_exception") as log_exception:
        proto.data_received(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        await asyncio.sleep(0.1)

        # The task finished cleanly (the factory error was handled, not raised).
        assert task.done()
        assert not task.cancelled()
        assert task.exception() is None
        # The error was logged and the connection was force-closed.
        log_exception.assert_called_once()
        assert log_exception.call_args.args[0] == "Unhandled exception"
        assert isinstance(log_exception.call_args.kwargs["exc_info"], RuntimeError)
        transport.close.assert_called_once_with()
        assert proto.transport is None

    del task, proto
    await _assert_no_unretrieved_task_exception(loop, contexts)


async def test_connection_lost_marks_failed_handler_task_exception_retrieved() -> None:
    """connection_lost() must consume the handler task exception. (#6978)

    If the start() task already finished with an exception when the
    connection is lost, dropping the _task_handler reference must not leave
    the exception unretrieved.
    """
    loop = asyncio.get_running_loop()
    contexts: list[dict[str, Any]] = []
    loop.set_exception_handler(lambda _loop, ctx: contexts.append(ctx))

    def bad_factory(*args: Any, **kwargs: Any) -> BaseRequest:
        raise _FatalError("boom")

    proto, _transport = _make_protocol(loop, request_factory=bad_factory)
    task = proto._task_handler
    assert task is not None

    proto.data_received(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    # Let the start() task run: request construction fails with a
    # BaseException, which escapes the task.
    await asyncio.sleep(0.1)
    assert task.done()
    assert not task.cancelled()
    # The task failed with an exception that is not retrieved yet.
    log_traceback = task._log_traceback
    assert log_traceback

    proto.connection_lost(None)
    assert proto._task_handler is None

    # The done callback registered by connection_lost() must mark the
    # exception as retrieved.
    await asyncio.sleep(0.1)
    assert not task._log_traceback

    del task, proto
    await _assert_no_unretrieved_task_exception(loop, contexts)


async def test_shutdown_marks_failed_handler_task_exception_retrieved() -> None:
    """shutdown() must consume the exception of an already failed task. (#6978)

    shutdown() only awaits _task_handler when it is not done yet; when the
    task already failed, its exception must still be marked as retrieved.
    """
    loop = asyncio.get_running_loop()
    contexts: list[dict[str, Any]] = []
    loop.set_exception_handler(lambda _loop, ctx: contexts.append(ctx))

    def bad_factory(*args: Any, **kwargs: Any) -> BaseRequest:
        raise _FatalError("boom")

    proto, _transport = _make_protocol(loop, request_factory=bad_factory)
    task = proto._task_handler
    assert task is not None

    proto.data_received(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    await asyncio.sleep(0.1)
    assert task.done()
    assert not task.cancelled()
    # The task failed with an exception that is not retrieved yet.
    log_traceback = task._log_traceback
    assert log_traceback

    await proto.shutdown(timeout=1.0)
    # shutdown() must mark the already-finished task's exception as retrieved.
    assert not task._log_traceback

    del task, proto
    await _assert_no_unretrieved_task_exception(loop, contexts)
