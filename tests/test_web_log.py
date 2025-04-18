import datetime
import logging
import platform
from typing import Any
from unittest import mock

import pytest

import aiohttp
from aiohttp import web
from aiohttp.abc import AbstractAccessLogger
from aiohttp.pytest_plugin import AiohttpClient, AiohttpServer
from aiohttp.typedefs import Handler
from aiohttp.web_log import AccessLogger

try:
    from contextvars import ContextVar
except ImportError:
    ContextVar = None


IS_PYPY = platform.python_implementation() == "PyPy"


def test_access_logger_format() -> None:
    log_format = '%T "%{ETag}o" %X {X} %%P'
    mock_logger = mock.Mock()
    access_logger = AccessLogger(mock_logger, log_format)
    expected = '%s "%s" %%X {X} %%%s'
    assert expected == access_logger._log_format


@pytest.mark.skipif(
    IS_PYPY,
    reason="""
    Because of patching :py:class:`datetime.datetime`, under PyPy it
    fails in :py:func:`isinstance` call in
    :py:meth:`datetime.datetime.__sub__` (called from
    :py:meth:`aiohttp.AccessLogger._format_t`):

    *** TypeError: isinstance() arg 2 must be a class, type, or tuple of classes and types

    (Pdb) from datetime import datetime
    (Pdb) isinstance(now, datetime)
    *** TypeError: isinstance() arg 2 must be a class, type, or tuple of classes and types
    (Pdb) datetime.__class__
    <class 'unittest.mock.MagicMock'>
    (Pdb) isinstance(now, datetime.__class__)
    False

    Ref: https://bitbucket.org/pypy/pypy/issues/1187/call-to-isinstance-in-__sub__-self-other
    Ref: https://github.com/celery/celery/issues/811
    Ref: https://stackoverflow.com/a/46102240/595220
    """,
)
@pytest.mark.parametrize(
    "log_format,expected,extra",
    [
        (
            "%t",
            "[01/Jan/1843:00:29:56 +0800]",
            {"request_start_time": "[01/Jan/1843:00:29:56 +0800]"},
        ),
        (
            '%a %t %P %r %s %b %T %Tf %D "%{H1}i" "%{H2}i"',
            (
                "127.0.0.2 [01/Jan/1843:00:29:56 +0800] <42> "
                'GET /path HTTP/1.1 200 42 3 3.141593 3141593 "a" "b"'
            ),
            {
                "first_request_line": "GET /path HTTP/1.1",
                "process_id": "<42>",
                "remote_address": "127.0.0.2",
                "request_start_time": "[01/Jan/1843:00:29:56 +0800]",
                "request_time": "3",
                "request_time_frac": "3.141593",
                "request_time_micro": "3141593",
                "response_size": 42,
                "response_status": 200,
                "request_header": {"H1": "a", "H2": "b"},
            },
        ),
    ],
)
def test_access_logger_atoms(
    monkeypatch: Any, log_format: Any, expected: Any, extra: Any
) -> None:
    class PatchedDatetime(datetime.datetime):
        @staticmethod
        def now(tz):
            return datetime.datetime(1843, 1, 1, 0, 30, tzinfo=tz)

    monkeypatch.setattr("datetime.datetime", PatchedDatetime)
    monkeypatch.setattr("time.timezone", -28800)
    monkeypatch.setattr("os.getpid", lambda: 42)
    mock_logger = mock.Mock()
    access_logger = AccessLogger(mock_logger, log_format)
    request = mock.Mock(
        headers={"H1": "a", "H2": "b"},
        method="GET",
        path_qs="/path",
        version=aiohttp.HttpVersion(1, 1),
        remote="127.0.0.2",
    )
    response = mock.Mock(headers={}, body_length=42, status=200)
    access_logger.log(request, response, 3.1415926)
    assert not mock_logger.exception.called, mock_logger.exception.call_args

    mock_logger.info.assert_called_with(expected, extra=extra)


def test_access_logger_dicts() -> None:
    log_format = "%{User-Agent}i %{Content-Length}o %{None}i"
    mock_logger = mock.Mock()
    access_logger = AccessLogger(mock_logger, log_format)
    request = mock.Mock(
        headers={"User-Agent": "Mock/1.0"}, version=(1, 1), remote="127.0.0.2"
    )
    response = mock.Mock(headers={"Content-Length": 123})
    access_logger.log(request, response, 0.0)
    assert not mock_logger.error.called
    expected = "Mock/1.0 123 -"
    extra = {
        "request_header": {"User-Agent": "Mock/1.0", "None": "-"},
        "response_header": {"Content-Length": 123},
    }

    mock_logger.info.assert_called_with(expected, extra=extra)


def test_access_logger_unix_socket() -> None:
    log_format = "|%a|"
    mock_logger = mock.Mock()
    access_logger = AccessLogger(mock_logger, log_format)
    request = mock.Mock(headers={"User-Agent": "Mock/1.0"}, version=(1, 1), remote="")
    response = mock.Mock()
    access_logger.log(request, response, 0.0)
    assert not mock_logger.error.called
    expected = "||"
    mock_logger.info.assert_called_with(expected, extra={"remote_address": ""})


def test_logger_no_message() -> None:
    mock_logger = mock.Mock()
    access_logger = AccessLogger(mock_logger, "%r %{content-type}i")
    extra_dict = {
        "first_request_line": "-",
        "request_header": {"content-type": "(no headers)"},
    }

    access_logger.log(None, None, 0.0)
    mock_logger.info.assert_called_with("- (no headers)", extra=extra_dict)


def test_logger_internal_error() -> None:
    mock_logger = mock.Mock()
    access_logger = AccessLogger(mock_logger, "%D")
    access_logger.log(None, None, "invalid")
    mock_logger.exception.assert_called_with("Error in logging")


def test_logger_no_transport() -> None:
    mock_logger = mock.Mock()
    access_logger = AccessLogger(mock_logger, "%a")
    access_logger.log(None, None, 0)
    mock_logger.info.assert_called_with("-", extra={"remote_address": "-"})


def test_logger_abc() -> None:
    class Logger(AbstractAccessLogger):
        def log(self, request, response, time):
            1 / 0

    mock_logger = mock.Mock()
    access_logger = Logger(mock_logger, None)

    with pytest.raises(ZeroDivisionError):
        access_logger.log(None, None, None)

    class Logger(AbstractAccessLogger):
        def log(self, request, response, time):
            self.logger.info(
                self.log_format.format(request=request, response=response, time=time)
            )

    mock_logger = mock.Mock()
    access_logger = Logger(mock_logger, "{request} {response} {time}")
    access_logger.log("request", "response", 1)
    mock_logger.info.assert_called_with("request response 1")


async def test_contextvars_logger(aiohttp_server, aiohttp_client):
    VAR = ContextVar("VAR")

    async def handler(request):
        return web.Response()

    @web.middleware
    async def middleware(request, handler: Handler):
        VAR.set("uuid")
        return await handler(request)

    msg = None

    class Logger(AbstractAccessLogger):
        def log(self, request, response, time):
            nonlocal msg
            msg = f"contextvars: {VAR.get()}"

    app = web.Application(middlewares=[middleware])
    app.router.add_get("/", handler)
    server = await aiohttp_server(app, access_log_class=Logger)
    client = await aiohttp_client(server)
    resp = await client.get("/")
    assert 200 == resp.status
    assert msg == "contextvars: uuid"


def test_access_logger_feeds_logger(caplog: pytest.LogCaptureFixture) -> None:
    """Test that the logger still works."""
    mock_logger = logging.getLogger("test.aiohttp.log")
    mock_logger.setLevel(logging.INFO)
    access_logger = AccessLogger(mock_logger, "%b")
    access_logger.log(
        mock.Mock(name="mock_request"), mock.Mock(name="mock_response"), 42
    )
    assert "mock_response" in caplog.text


async def test_logger_does_not_log_when_not_enabled(
    aiohttp_server: AiohttpServer,
    aiohttp_client: AiohttpClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test logger does nothing when not enabled."""

    async def handler(request: web.Request) -> web.Response:
        return web.Response()

    class Logger(AbstractAccessLogger):

        def log(
            self, request: web.BaseRequest, response: web.StreamResponse, time: float
        ) -> None:
            self.logger.critical("This should not be logged")  # pragma: no cover

        @property
        def enabled(self) -> bool:
            return False

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app, access_log_class=Logger)
    client = await aiohttp_client(server)
    resp = await client.get("/")
    assert 200 == resp.status
    assert "This should not be logged" not in caplog.text


async def test_logger_set_to_none(
    aiohttp_server: AiohttpServer,
    aiohttp_client: AiohttpClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test logger does nothing when access_log is set to None."""

    async def handler(request: web.Request) -> web.Response:
        return web.Response()

    class Logger(AbstractAccessLogger):

        def log(
            self, request: web.BaseRequest, response: web.StreamResponse, time: float
        ) -> None:
            self.logger.critical("This should not be logged")  # pragma: no cover

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app, access_log=None, access_log_class=Logger)
    client = await aiohttp_client(server)
    resp = await client.get("/")
    assert 200 == resp.status
    assert "This should not be logged" not in caplog.text
