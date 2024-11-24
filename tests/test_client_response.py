# Tests for aiohttp/client.py

import asyncio
import gc
import sys
from json import JSONDecodeError
from unittest import mock

import pytest
from multidict import CIMultiDict, CIMultiDictProxy
from pytest_mock import MockerFixture
from yarl import URL

import aiohttp
from aiohttp import ClientSession, http
from aiohttp.client_reqrep import ClientResponse, RequestInfo
from aiohttp.connector import Connection
from aiohttp.helpers import TimerNoop
from aiohttp.test_utils import make_mocked_coro


class WriterMock(mock.AsyncMock):
    def done(self) -> bool:
        return True


@pytest.fixture
def session() -> mock.Mock:
    return mock.Mock()


async def test_http_processing_error(session: ClientSession) -> None:
    loop = mock.Mock()
    request_info = mock.Mock()
    response = ClientResponse(
        "get",
        URL("http://del-cl-resp.org"),
        request_info=request_info,
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )
    loop.get_debug = mock.Mock()
    loop.get_debug.return_value = True

    connection = mock.Mock()
    connection.protocol = aiohttp.DataQueue(loop)
    connection.protocol.set_exception(http.HttpProcessingError())

    with pytest.raises(aiohttp.ClientResponseError) as info:
        await response.start(connection)

    assert info.value.request_info is request_info
    response.close()


def test_del(session: ClientSession) -> None:
    loop = mock.Mock()
    response = ClientResponse(
        "get",
        URL("http://del-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )
    loop.get_debug = mock.Mock()
    loop.get_debug.return_value = True

    connection = mock.Mock()
    response._closed = False
    response._connection = connection
    loop.set_exception_handler(lambda loop, ctx: None)

    with pytest.warns(ResourceWarning):
        del response
        gc.collect()

    connection.release.assert_called_with()


def test_close(loop: asyncio.AbstractEventLoop, session: ClientSession) -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )
    response._closed = False
    response._connection = mock.Mock()
    response.close()
    assert response.connection is None
    response.close()
    response.close()


def test_wait_for_100_1(
    loop: asyncio.AbstractEventLoop, session: ClientSession
) -> None:
    response = ClientResponse(
        "get",
        URL("http://python.org"),
        continue100=loop.create_future(),
        request_info=mock.Mock(),
        writer=WriterMock(),
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )
    assert response._continue is not None
    response.close()


def test_wait_for_100_2(
    loop: asyncio.AbstractEventLoop, session: ClientSession
) -> None:
    response = ClientResponse(
        "get",
        URL("http://python.org"),
        request_info=mock.Mock(),
        continue100=None,
        writer=WriterMock(),
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )
    assert response._continue is None
    response.close()


def test_repr(loop: asyncio.AbstractEventLoop, session: ClientSession) -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )
    response.status = 200
    response.reason = "Ok"
    assert "<ClientResponse(http://def-cl-resp.org) [200 Ok]>" in repr(response)


def test_repr_non_ascii_url() -> None:
    response = ClientResponse(
        "get",
        URL("http://fake-host.org/\u03bb"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=mock.Mock(),
        session=mock.Mock(),
    )
    assert "<ClientResponse(http://fake-host.org/%CE%BB) [None None]>" in repr(response)


def test_repr_non_ascii_reason() -> None:
    response = ClientResponse(
        "get",
        URL("http://fake-host.org/path"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=mock.Mock(),
        session=mock.Mock(),
    )
    response.reason = "\u03bb"
    assert "<ClientResponse(http://fake-host.org/path) [None \\u03bb]>" in repr(
        response
    )


async def test_read_and_release_connection(
    loop: asyncio.AbstractEventLoop, session: ClientSession
) -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )

    def side_effect(*args: object, **kwargs: object) -> "asyncio.Future[bytes]":
        fut = loop.create_future()
        fut.set_result(b"payload")
        return fut

    content = response.content = mock.Mock()
    content.read.side_effect = side_effect

    res = await response.read()
    assert res == b"payload"
    assert response._connection is None


async def test_read_and_release_connection_with_error(
    loop: asyncio.AbstractEventLoop, session: ClientSession
) -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )
    content = response.content = mock.Mock()
    content.read.return_value = loop.create_future()
    content.read.return_value.set_exception(ValueError)

    with pytest.raises(ValueError):
        await response.read()
    assert response._closed


async def test_release(loop: asyncio.AbstractEventLoop, session: ClientSession) -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )
    fut = loop.create_future()
    fut.set_result(b"")
    content = response.content = mock.Mock()
    content.readany.return_value = fut

    response.release()
    assert response._connection is None


@pytest.mark.skipif(
    sys.implementation.name != "cpython",
    reason="Other implementations has different GC strategies",
)
async def test_release_on_del(
    loop: asyncio.AbstractEventLoop, session: ClientSession
) -> None:
    connection = mock.Mock()
    connection.protocol.upgraded = False

    def run(conn: Connection) -> None:
        response = ClientResponse(
            "get",
            URL("http://def-cl-resp.org"),
            request_info=mock.Mock(),
            writer=WriterMock(),
            continue100=None,
            timer=TimerNoop(),
            traces=[],
            loop=loop,
            session=session,
        )
        response._closed = False
        response._connection = conn

    run(connection)

    assert connection.release.called


async def test_response_eof(
    loop: asyncio.AbstractEventLoop, session: ClientSession
) -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=None,
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )
    response._closed = False
    conn = response._connection = mock.Mock()
    conn.protocol.upgraded = False

    response._response_eof()
    assert conn.release.called
    assert response._connection is None


async def test_response_eof_upgraded(
    loop: asyncio.AbstractEventLoop, session: ClientSession
) -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )

    conn = response._connection = mock.Mock()
    conn.protocol.upgraded = True

    response._response_eof()
    assert not conn.release.called
    assert response._connection is conn


async def test_response_eof_after_connection_detach(
    loop: asyncio.AbstractEventLoop, session: ClientSession
) -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=None,
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )
    response._closed = False
    conn = response._connection = mock.Mock()
    conn.protocol = None

    response._response_eof()
    assert conn.release.called
    assert response._connection is None


async def test_text(loop: asyncio.AbstractEventLoop, session: ClientSession) -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )

    def side_effect(*args: object, **kwargs: object) -> "asyncio.Future[bytes]":
        fut = loop.create_future()
        fut.set_result('{"тест": "пройден"}'.encode("cp1251"))
        return fut

    h = {"Content-Type": "application/json;charset=cp1251"}
    response._headers = CIMultiDictProxy(CIMultiDict(h))
    content = response.content = mock.Mock()
    content.read.side_effect = side_effect

    res = await response.text()
    assert res == '{"тест": "пройден"}'
    assert response._connection is None


async def test_text_bad_encoding(
    loop: asyncio.AbstractEventLoop, session: ClientSession
) -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )

    def side_effect(*args: object, **kwargs: object) -> "asyncio.Future[bytes]":
        fut = loop.create_future()
        fut.set_result('{"тестkey": "пройденvalue"}'.encode("cp1251"))
        return fut

    # lie about the encoding
    h = {"Content-Type": "application/json;charset=utf-8"}
    response._headers = CIMultiDictProxy(CIMultiDict(h))
    content = response.content = mock.Mock()
    content.read.side_effect = side_effect
    with pytest.raises(UnicodeDecodeError):
        await response.text()
    # only the valid utf-8 characters will be returned
    res = await response.text(errors="ignore")
    assert res == '{"key": "value"}'
    assert response._connection is None


async def test_text_badly_encoded_encoding_header(
    loop: asyncio.AbstractEventLoop, session: ClientSession
) -> None:
    session._resolve_charset = lambda *_: "utf-8"
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )

    def side_effect(*args: object, **kwargs: object) -> "asyncio.Future[bytes]":
        fut = loop.create_future()
        fut.set_result(b"foo")
        return fut

    h = {"Content-Type": "text/html; charset=\udc81gutf-8\udc81\udc8d"}
    response._headers = CIMultiDictProxy(CIMultiDict(h))
    content = response.content = mock.Mock()
    content.read.side_effect = side_effect

    await response.read()
    encoding = response.get_encoding()

    assert encoding == "utf-8"


async def test_text_custom_encoding(
    loop: asyncio.AbstractEventLoop, session: ClientSession
) -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )

    def side_effect(*args: object, **kwargs: object) -> "asyncio.Future[bytes]":
        fut = loop.create_future()
        fut.set_result('{"тест": "пройден"}'.encode("cp1251"))
        return fut

    h = {"Content-Type": "application/json"}
    response._headers = CIMultiDictProxy(CIMultiDict(h))
    content = response.content = mock.Mock()
    content.read.side_effect = side_effect
    with mock.patch.object(response, "get_encoding") as m:
        res = await response.text(encoding="cp1251")
        assert res == '{"тест": "пройден"}'
        assert response._connection is None
        assert not m.called


@pytest.mark.parametrize("content_type", ("text/plain", "text/plain;charset=invalid"))
async def test_text_charset_resolver(
    content_type: str, loop: asyncio.AbstractEventLoop, session: ClientSession
) -> None:
    session._resolve_charset = lambda r, b: "cp1251"
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )

    def side_effect(*args: object, **kwargs: object) -> "asyncio.Future[bytes]":
        fut = loop.create_future()
        fut.set_result('{"тест": "пройден"}'.encode("cp1251"))
        return fut

    h = {"Content-Type": content_type}
    response._headers = CIMultiDictProxy(CIMultiDict(h))
    content = response.content = mock.Mock()
    content.read.side_effect = side_effect

    await response.read()
    res = await response.text()
    assert res == '{"тест": "пройден"}'
    assert response._connection is None
    assert response.get_encoding() == "cp1251"


async def test_get_encoding_body_none(
    loop: asyncio.AbstractEventLoop, session: ClientSession
) -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )

    h = {"Content-Type": "text/html"}
    response._headers = CIMultiDictProxy(CIMultiDict(h))
    content = response.content = mock.Mock()
    content.read.side_effect = AssertionError

    with pytest.raises(
        RuntimeError,
        match="^Cannot compute fallback encoding of a not yet read body$",
    ):
        response.get_encoding()
    assert response.closed


async def test_text_after_read(
    loop: asyncio.AbstractEventLoop, session: ClientSession
) -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )

    def side_effect(*args: object, **kwargs: object) -> "asyncio.Future[bytes]":
        fut = loop.create_future()
        fut.set_result('{"тест": "пройден"}'.encode("cp1251"))
        return fut

    h = {"Content-Type": "application/json;charset=cp1251"}
    response._headers = CIMultiDictProxy(CIMultiDict(h))
    content = response.content = mock.Mock()
    content.read.side_effect = side_effect

    res = await response.text()
    assert res == '{"тест": "пройден"}'
    assert response._connection is None


async def test_json(loop: asyncio.AbstractEventLoop, session: ClientSession) -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )

    def side_effect(*args: object, **kwargs: object) -> "asyncio.Future[bytes]":
        fut = loop.create_future()
        fut.set_result('{"тест": "пройден"}'.encode("cp1251"))
        return fut

    h = {"Content-Type": "application/json;charset=cp1251"}
    response._headers = CIMultiDictProxy(CIMultiDict(h))
    content = response.content = mock.Mock()
    content.read.side_effect = side_effect

    res = await response.json()
    assert res == {"тест": "пройден"}
    assert response._connection is None


async def test_json_extended_content_type(
    loop: asyncio.AbstractEventLoop, session: ClientSession
) -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )

    def side_effect(*args: object, **kwargs: object) -> "asyncio.Future[bytes]":
        fut = loop.create_future()
        fut.set_result('{"тест": "пройден"}'.encode("cp1251"))
        return fut

    h = {"Content-Type": "application/this.is-1_content+subtype+json;charset=cp1251"}
    response._headers = CIMultiDictProxy(CIMultiDict(h))
    content = response.content = mock.Mock()
    content.read.side_effect = side_effect

    res = await response.json()
    assert res == {"тест": "пройден"}
    assert response._connection is None


async def test_json_custom_content_type(
    loop: asyncio.AbstractEventLoop, session: ClientSession
) -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )

    def side_effect(*args: object, **kwargs: object) -> "asyncio.Future[bytes]":
        fut = loop.create_future()
        fut.set_result('{"тест": "пройден"}'.encode("cp1251"))
        return fut

    h = {"Content-Type": "custom/type;charset=cp1251"}
    response._headers = CIMultiDictProxy(CIMultiDict(h))
    content = response.content = mock.Mock()
    content.read.side_effect = side_effect

    res = await response.json(content_type="custom/type")
    assert res == {"тест": "пройден"}
    assert response._connection is None


async def test_json_custom_loader(
    loop: asyncio.AbstractEventLoop, session: ClientSession
) -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )
    h = {"Content-Type": "application/json;charset=cp1251"}
    response._headers = CIMultiDictProxy(CIMultiDict(h))
    response._body = b"data"

    def custom(content: str) -> str:
        return content + "-custom"

    res = await response.json(loads=custom)
    assert res == "data-custom"


async def test_json_invalid_content_type(
    loop: asyncio.AbstractEventLoop, session: ClientSession
) -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )
    h = {"Content-Type": "data/octet-stream"}
    response._headers = CIMultiDictProxy(CIMultiDict(h))
    response._body = b""
    response.status = 500

    with pytest.raises(aiohttp.ContentTypeError) as info:
        await response.json()

    assert info.value.request_info == response.request_info
    assert info.value.status == 500


async def test_json_no_content(
    loop: asyncio.AbstractEventLoop, session: ClientSession
) -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )
    h = {"Content-Type": "application/json"}
    response._headers = CIMultiDictProxy(CIMultiDict(h))
    response._body = b""

    with pytest.raises(JSONDecodeError):
        await response.json(content_type=None)


async def test_json_override_encoding(
    loop: asyncio.AbstractEventLoop, session: ClientSession
) -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )

    def side_effect(*args: object, **kwargs: object) -> "asyncio.Future[bytes]":
        fut = loop.create_future()
        fut.set_result('{"тест": "пройден"}'.encode("cp1251"))
        return fut

    h = {"Content-Type": "application/json;charset=utf8"}
    response._headers = CIMultiDictProxy(CIMultiDict(h))
    content = response.content = mock.Mock()
    content.read.side_effect = side_effect
    with mock.patch.object(response, "get_encoding") as m:
        res = await response.json(encoding="cp1251")
        assert res == {"тест": "пройден"}
        assert response._connection is None
        assert not m.called


def test_get_encoding_unknown(
    loop: asyncio.AbstractEventLoop, session: ClientSession
) -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )

    h = {"Content-Type": "application/json"}
    response._headers = CIMultiDictProxy(CIMultiDict(h))
    assert response.get_encoding() == "utf-8"


def test_raise_for_status_2xx() -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=mock.Mock(),
        session=mock.Mock(),
    )
    response.status = 200
    response.reason = "OK"
    response.raise_for_status()  # should not raise


def test_raise_for_status_4xx() -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=mock.Mock(),
        session=mock.Mock(),
    )
    response.status = 409
    response.reason = "CONFLICT"
    with pytest.raises(aiohttp.ClientResponseError) as cm:
        response.raise_for_status()
    assert str(cm.value.status) == "409"
    assert str(cm.value.message) == "CONFLICT"
    assert response.closed


def test_raise_for_status_4xx_without_reason() -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=mock.Mock(),
        session=mock.Mock(),
    )
    response.status = 404
    response.reason = ""
    with pytest.raises(aiohttp.ClientResponseError) as cm:
        response.raise_for_status()
    assert str(cm.value.status) == "404"
    assert str(cm.value.message) == ""
    assert response.closed


def test_resp_host() -> None:
    response = ClientResponse(
        "get",
        URL("http://del-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=mock.Mock(),
        session=mock.Mock(),
    )
    assert "del-cl-resp.org" == response.host


def test_content_type() -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=mock.Mock(),
        session=mock.Mock(),
    )
    h = {"Content-Type": "application/json;charset=cp1251"}
    response._headers = CIMultiDictProxy(CIMultiDict(h))

    assert "application/json" == response.content_type


def test_content_type_no_header() -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=mock.Mock(),
        session=mock.Mock(),
    )
    response._headers = CIMultiDictProxy(CIMultiDict({}))

    assert "application/octet-stream" == response.content_type


def test_charset() -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=mock.Mock(),
        session=mock.Mock(),
    )
    h = {"Content-Type": "application/json;charset=cp1251"}
    response._headers = CIMultiDictProxy(CIMultiDict(h))

    assert "cp1251" == response.charset


def test_charset_no_header() -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=mock.Mock(),
        session=mock.Mock(),
    )
    response._headers = CIMultiDictProxy(CIMultiDict({}))

    assert response.charset is None


def test_charset_no_charset() -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=mock.Mock(),
        session=mock.Mock(),
    )
    h = {"Content-Type": "application/json"}
    response._headers = CIMultiDictProxy(CIMultiDict(h))

    assert response.charset is None


def test_content_disposition_full() -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=mock.Mock(),
        session=mock.Mock(),
    )
    h = {"Content-Disposition": 'attachment; filename="archive.tar.gz"; foo=bar'}
    response._headers = CIMultiDictProxy(CIMultiDict(h))

    assert response.content_disposition is not None
    assert "attachment" == response.content_disposition.type
    assert "bar" == response.content_disposition.parameters["foo"]
    assert "archive.tar.gz" == response.content_disposition.filename
    with pytest.raises(TypeError):
        response.content_disposition.parameters["foo"] = "baz"  # type: ignore[index]


def test_content_disposition_no_parameters() -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=mock.Mock(),
        session=mock.Mock(),
    )
    h = {"Content-Disposition": "attachment"}
    response._headers = CIMultiDictProxy(CIMultiDict(h))

    assert response.content_disposition is not None
    assert "attachment" == response.content_disposition.type
    assert response.content_disposition.filename is None
    assert {} == response.content_disposition.parameters


def test_content_disposition_no_header() -> None:
    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=mock.Mock(),
        session=mock.Mock(),
    )
    response._headers = CIMultiDictProxy(CIMultiDict({}))

    assert response.content_disposition is None


def test_response_request_info() -> None:
    url = URL("http://def-cl-resp.org")
    h = {"Content-Type": "application/json;charset=cp1251"}
    headers = CIMultiDictProxy(CIMultiDict(h))
    response = ClientResponse(
        "get",
        url,
        request_info=RequestInfo(url, "get", headers, url),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=mock.Mock(),
        session=mock.Mock(),
    )
    assert url == response.request_info.url
    assert "get" == response.request_info.method
    assert headers == response.request_info.headers


def test_request_info_in_exception() -> None:
    url = URL("http://def-cl-resp.org")
    h = {"Content-Type": "application/json;charset=cp1251"}
    headers = CIMultiDictProxy(CIMultiDict(h))
    response = ClientResponse(
        "get",
        url,
        request_info=RequestInfo(url, "get", headers, url),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=mock.Mock(),
        session=mock.Mock(),
    )
    response.status = 409
    response.reason = "CONFLICT"
    with pytest.raises(aiohttp.ClientResponseError) as cm:
        response.raise_for_status()
    assert cm.value.request_info == response.request_info


def test_no_redirect_history_in_exception() -> None:
    url = URL("http://def-cl-resp.org")
    h = {"Content-Type": "application/json;charset=cp1251"}
    headers = CIMultiDictProxy(CIMultiDict(h))
    response = ClientResponse(
        "get",
        url,
        request_info=RequestInfo(url, "get", headers, url),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=mock.Mock(),
        session=mock.Mock(),
    )
    response.status = 409
    response.reason = "CONFLICT"
    with pytest.raises(aiohttp.ClientResponseError) as cm:
        response.raise_for_status()
    assert () == cm.value.history


def test_redirect_history_in_exception() -> None:
    hist_url = URL("http://def-cl-resp.org")
    u = "http://def-cl-resp.org/index.htm"
    url = URL(u)
    hist_headers = {"Content-Type": "application/json;charset=cp1251", "Location": u}
    h = {"Content-Type": "application/json;charset=cp1251"}
    headers = CIMultiDictProxy(CIMultiDict(h))
    response = ClientResponse(
        "get",
        url,
        request_info=RequestInfo(url, "get", headers, url),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=mock.Mock(),
        session=mock.Mock(),
    )
    response.status = 409
    response.reason = "CONFLICT"

    hist_response = ClientResponse(
        "get",
        hist_url,
        request_info=RequestInfo(url, "get", headers, url),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=mock.Mock(),
        session=mock.Mock(),
    )

    hist_response._headers = CIMultiDictProxy(CIMultiDict(hist_headers))
    hist_response.status = 301
    hist_response.reason = "REDIRECT"

    response._history = (hist_response,)
    with pytest.raises(aiohttp.ClientResponseError) as cm:
        response.raise_for_status()
    assert (hist_response,) == cm.value.history


async def test_response_read_triggers_callback(
    loop: asyncio.AbstractEventLoop, session: ClientSession
) -> None:
    trace = mock.Mock()
    trace.send_response_chunk_received = make_mocked_coro()
    response_method = "get"
    response_url = URL("http://def-cl-resp.org")
    response_body = b"This is response"

    response = ClientResponse(
        response_method,
        response_url,
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        loop=loop,
        session=session,
        traces=[trace],
    )

    def side_effect(*args: object, **kwargs: object) -> "asyncio.Future[bytes]":
        fut = loop.create_future()
        fut.set_result(response_body)
        return fut

    h = {"Content-Type": "application/json;charset=cp1251"}
    response._headers = CIMultiDictProxy(CIMultiDict(h))
    content = response.content = mock.Mock()
    content.read.side_effect = side_effect

    res = await response.read()
    assert res == response_body
    assert response._connection is None

    assert trace.send_response_chunk_received.called
    assert trace.send_response_chunk_received.call_args == mock.call(
        response_method, response_url, response_body
    )


def test_response_cookies(
    loop: asyncio.AbstractEventLoop, session: ClientSession
) -> None:
    response = ClientResponse(
        "get",
        URL("http://python.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )
    cookies = response.cookies
    # Ensure the same cookies object is returned each time
    assert response.cookies is cookies


def test_response_real_url(
    loop: asyncio.AbstractEventLoop, session: ClientSession
) -> None:
    url = URL("http://def-cl-resp.org/#urlfragment")
    response = ClientResponse(
        "get",
        url,
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )
    assert response.url == url.with_fragment(None)
    assert response.real_url == url


def test_response_links_comma_separated(
    loop: asyncio.AbstractEventLoop, session: ClientSession
) -> None:
    url = URL("http://def-cl-resp.org/")
    response = ClientResponse(
        "get",
        url,
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )
    h = (
        (
            "Link",
            (
                "<http://example.com/page/1.html>; rel=next, "
                "<http://example.com/>; rel=home"
            ),
        ),
    )
    response._headers = CIMultiDictProxy(CIMultiDict(h))
    assert response.links == {
        "next": {"url": URL("http://example.com/page/1.html"), "rel": "next"},
        "home": {"url": URL("http://example.com/"), "rel": "home"},
    }


def test_response_links_multiple_headers(
    loop: asyncio.AbstractEventLoop, session: ClientSession
) -> None:
    url = URL("http://def-cl-resp.org/")
    response = ClientResponse(
        "get",
        url,
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )
    h = (
        ("Link", "<http://example.com/page/1.html>; rel=next"),
        ("Link", "<http://example.com/>; rel=home"),
    )
    response._headers = CIMultiDictProxy(CIMultiDict(h))
    assert response.links == {
        "next": {"url": URL("http://example.com/page/1.html"), "rel": "next"},
        "home": {"url": URL("http://example.com/"), "rel": "home"},
    }


def test_response_links_no_rel(
    loop: asyncio.AbstractEventLoop, session: ClientSession
) -> None:
    url = URL("http://def-cl-resp.org/")
    response = ClientResponse(
        "get",
        url,
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )
    h = (("Link", "<http://example.com/>"),)
    response._headers = CIMultiDictProxy(CIMultiDict(h))
    assert response.links == {
        "http://example.com/": {"url": URL("http://example.com/")}
    }


def test_response_links_quoted(
    loop: asyncio.AbstractEventLoop, session: ClientSession
) -> None:
    url = URL("http://def-cl-resp.org/")
    response = ClientResponse(
        "get",
        url,
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )
    h = (("Link", '<http://example.com/>; rel="home-page"'),)
    response._headers = CIMultiDictProxy(CIMultiDict(h))
    assert response.links == {
        "home-page": {"url": URL("http://example.com/"), "rel": "home-page"}
    }


def test_response_links_relative(
    loop: asyncio.AbstractEventLoop, session: ClientSession
) -> None:
    url = URL("http://def-cl-resp.org/")
    response = ClientResponse(
        "get",
        url,
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )
    h = (("Link", "</relative/path>; rel=rel"),)
    response._headers = CIMultiDictProxy(CIMultiDict(h))
    assert response.links == {
        "rel": {"url": URL("http://def-cl-resp.org/relative/path"), "rel": "rel"}
    }


def test_response_links_empty(
    loop: asyncio.AbstractEventLoop, session: ClientSession
) -> None:
    url = URL("http://def-cl-resp.org/")
    response = ClientResponse(
        "get",
        url,
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=session,
    )
    response._headers = CIMultiDictProxy(CIMultiDict())
    assert response.links == {}


def test_response_not_closed_after_get_ok(mocker: MockerFixture) -> None:
    response = ClientResponse(
        "get",
        URL("http://del-cl-resp.org"),
        request_info=mock.Mock(),
        writer=WriterMock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=mock.Mock(),
        session=mock.Mock(),
    )
    response.status = 400
    response.reason = "Bad Request"
    response._closed = False
    spy = mocker.spy(response, "raise_for_status")
    assert not response.ok
    assert not response.closed
    assert spy.call_count == 0
