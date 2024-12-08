import collections.abc
import datetime
import gzip
import io
import json
import re
import weakref
import zlib
from concurrent.futures import ThreadPoolExecutor
from typing import AsyncIterator, Optional, Union
from unittest import mock

import aiosignal
import pytest
from multidict import CIMultiDict, CIMultiDictProxy

from aiohttp import HttpVersion, HttpVersion10, HttpVersion11, hdrs, web
from aiohttp.abc import AbstractStreamWriter
from aiohttp.helpers import ETag
from aiohttp.http_writer import StreamWriter, _serialize_headers
from aiohttp.multipart import BodyPartReader, MultipartWriter
from aiohttp.payload import BytesPayload, StringPayload
from aiohttp.test_utils import make_mocked_coro, make_mocked_request
from aiohttp.typedefs import LooseHeaders


def make_request(
    method: str,
    path: str,
    headers: LooseHeaders = CIMultiDict(),
    version: HttpVersion = HttpVersion11,
    *,
    app: Optional[web.Application] = None,
    writer: Optional[AbstractStreamWriter] = None,
) -> web.Request:
    if app is None:
        app = mock.create_autospec(
            web.Application, spec_set=True, on_response_prepare=aiosignal.Signal(app)
        )
    app.on_response_prepare.freeze()
    return make_mocked_request(
        method, path, headers, version=version, app=app, writer=writer
    )


@pytest.fixture
def buf() -> bytearray:
    return bytearray()


@pytest.fixture
def writer(buf: bytearray) -> AbstractStreamWriter:
    writer = mock.create_autospec(AbstractStreamWriter, spec_set=True)

    async def write_headers(status_line: str, headers: CIMultiDict[str]) -> None:
        b_headers = _serialize_headers(status_line, headers)
        buf.extend(b_headers)

    async def write_eof(chunk: bytes = b"") -> None:
        buf.extend(chunk)

    writer.write_eof.side_effect = write_eof
    writer.write_headers.side_effect = write_headers

    return writer  # type: ignore[no-any-return]


def test_stream_response_ctor() -> None:
    resp = web.StreamResponse()
    assert 200 == resp.status
    assert resp.keep_alive is None

    assert resp.task is None

    req = mock.Mock()
    resp._req = req
    assert resp.task is req.task


def test_stream_response_hashable() -> None:
    # should not raise exception
    hash(web.StreamResponse())


def test_stream_response_eq() -> None:
    resp1 = web.StreamResponse()
    resp2 = web.StreamResponse()

    assert resp1 == resp1
    assert not resp1 == resp2


def test_stream_response_is_mutable_mapping() -> None:
    resp = web.StreamResponse()
    assert isinstance(resp, collections.abc.MutableMapping)
    resp["key"] = "value"
    assert "value" == resp["key"]


def test_stream_response_delitem() -> None:
    resp = web.StreamResponse()
    resp["key"] = "value"
    del resp["key"]
    assert "key" not in resp


def test_stream_response_len() -> None:
    resp = web.StreamResponse()
    assert len(resp) == 0
    resp["key"] = "value"
    assert len(resp) == 1


def test_request_iter() -> None:
    resp = web.StreamResponse()
    resp["key"] = "value"
    resp["key2"] = "value2"
    assert set(resp) == {"key", "key2"}


def test_content_length() -> None:
    resp = web.StreamResponse()
    assert resp.content_length is None


def test_content_length_setter() -> None:
    resp = web.StreamResponse()

    resp.content_length = 234
    assert 234 == resp.content_length


def test_content_length_setter_with_enable_chunked_encoding() -> None:
    resp = web.StreamResponse()

    resp.enable_chunked_encoding()
    with pytest.raises(RuntimeError):
        resp.content_length = 234


def test_drop_content_length_header_on_setting_len_to_None() -> None:
    resp = web.StreamResponse()

    resp.content_length = 1
    assert "1" == resp.headers["Content-Length"]
    resp.content_length = None
    assert "Content-Length" not in resp.headers


def test_set_content_length_to_None_on_non_set() -> None:
    resp = web.StreamResponse()

    resp.content_length = None
    assert "Content-Length" not in resp.headers
    resp.content_length = None
    assert "Content-Length" not in resp.headers


def test_setting_content_type() -> None:
    resp = web.StreamResponse()

    resp.content_type = "text/html"
    assert "text/html" == resp.headers["content-type"]


def test_setting_charset() -> None:
    resp = web.StreamResponse()

    resp.content_type = "text/html"
    resp.charset = "koi8-r"
    assert "text/html; charset=koi8-r" == resp.headers["content-type"]


def test_default_charset() -> None:
    resp = web.StreamResponse()

    assert resp.charset is None


def test_reset_charset() -> None:
    resp = web.StreamResponse()

    resp.content_type = "text/html"
    resp.charset = None
    assert resp.charset is None


def test_reset_charset_after_setting() -> None:
    resp = web.StreamResponse()

    resp.content_type = "text/html"
    resp.charset = "koi8-r"
    resp.charset = None
    assert resp.charset is None


def test_charset_without_content_type() -> None:
    resp = web.StreamResponse()

    with pytest.raises(RuntimeError):
        resp.charset = "koi8-r"


def test_last_modified_initial() -> None:
    resp = web.StreamResponse()
    assert resp.last_modified is None


def test_last_modified_string() -> None:
    resp = web.StreamResponse()

    dt = datetime.datetime(1990, 1, 2, 3, 4, 5, 0, datetime.timezone.utc)
    resp.last_modified = "Mon, 2 Jan 1990 03:04:05 GMT"  # type: ignore[assignment]
    assert resp.last_modified == dt


def test_last_modified_timestamp() -> None:
    resp = web.StreamResponse()

    dt = datetime.datetime(1970, 1, 1, 0, 0, 0, 0, datetime.timezone.utc)

    resp.last_modified = 0  # type: ignore[assignment]
    assert resp.last_modified == dt

    resp.last_modified = 0.0  # type: ignore[assignment]
    assert resp.last_modified == dt


def test_last_modified_datetime() -> None:
    resp = web.StreamResponse()

    dt = datetime.datetime(2001, 2, 3, 4, 5, 6, 0, datetime.timezone.utc)
    resp.last_modified = dt
    assert resp.last_modified == dt


def test_last_modified_reset() -> None:
    resp = web.StreamResponse()

    resp.last_modified = 0  # type: ignore[assignment]
    resp.last_modified = None
    assert resp.last_modified is None


def test_last_modified_invalid_type() -> None:
    resp = web.StreamResponse()

    with pytest.raises(ValueError, match="Unsupported type for last_modified: object"):
        resp.last_modified = object()  # type: ignore[assignment]


@pytest.mark.parametrize(
    "header_val",
    (
        "xxyyzz",
        "Tue, 08 Oct 4446413 00:56:40 GMT",
        "Tue, 08 Oct 2000 00:56:80 GMT",
    ),
)
def test_last_modified_string_invalid(header_val: str) -> None:
    resp = web.StreamResponse(headers={"Last-Modified": header_val})
    assert resp.last_modified is None


def test_etag_initial() -> None:
    resp = web.StreamResponse()
    assert resp.etag is None


def test_etag_string() -> None:
    resp = web.StreamResponse()
    value = "0123-kotik"
    resp.etag = value  # type: ignore[assignment]
    assert resp.etag == ETag(value=value)
    assert resp.headers[hdrs.ETAG] == f'"{value}"'


@pytest.mark.parametrize(
    ("etag", "expected_header"),
    (
        (ETag(value="0123-weak-kotik", is_weak=True), 'W/"0123-weak-kotik"'),
        (ETag(value="0123-strong-kotik", is_weak=False), '"0123-strong-kotik"'),
    ),
)
def test_etag_class(etag: ETag, expected_header: str) -> None:
    resp = web.StreamResponse()
    resp.etag = etag
    assert resp.etag == etag
    assert resp.headers[hdrs.ETAG] == expected_header


def test_etag_any() -> None:
    resp = web.StreamResponse()
    resp.etag = "*"  # type: ignore[assignment]
    assert resp.etag == ETag(value="*")
    assert resp.headers[hdrs.ETAG] == "*"


@pytest.mark.parametrize(
    "invalid_value",
    (
        '"invalid"',
        "повинен бути ascii",
        ETag(value='"invalid"', is_weak=True),
        ETag(value="bad ©®"),
    ),
)
def test_etag_invalid_value_set(invalid_value: Union[str, ETag]) -> None:
    resp = web.StreamResponse()
    with pytest.raises(ValueError, match="is not a valid etag"):
        resp.etag = invalid_value  # type: ignore[assignment]


@pytest.mark.parametrize(
    "header",
    (
        "forgotten quotes",
        '"∀ x ∉ ascii"',
    ),
)
def test_etag_invalid_value_get(header: str) -> None:
    resp = web.StreamResponse()
    resp.headers["ETag"] = header
    assert resp.etag is None


@pytest.mark.parametrize("invalid", (123, ETag(value=123, is_weak=True)))  # type: ignore[arg-type]
def test_etag_invalid_value_class(invalid: Union[int, ETag]) -> None:
    resp = web.StreamResponse()
    with pytest.raises(ValueError, match="Unsupported etag type"):
        resp.etag = invalid  # type: ignore[assignment]


def test_etag_reset() -> None:
    resp = web.StreamResponse()
    resp.etag = "*"  # type: ignore[assignment]
    resp.etag = None
    assert resp.etag is None


async def test_start() -> None:
    req = make_request("GET", "/")
    resp = web.StreamResponse()
    assert resp.keep_alive is None

    msg = await resp.prepare(req)

    assert msg is not None
    assert msg.write_headers.called  # type: ignore[attr-defined]
    msg2 = await resp.prepare(req)
    assert msg is msg2

    assert resp.keep_alive

    req2 = make_request("GET", "/")  # type: ignore[unreachable]
    # with pytest.raises(RuntimeError):
    msg3 = await resp.prepare(req2)
    assert msg is msg3


async def test_chunked_encoding() -> None:
    req = make_request("GET", "/")
    resp = web.StreamResponse()
    assert not resp.chunked

    resp.enable_chunked_encoding()
    assert resp.chunked

    msg = await resp.prepare(req)  # type: ignore[unreachable]
    assert msg.chunked


def test_enable_chunked_encoding_with_content_length() -> None:
    resp = web.StreamResponse()

    resp.content_length = 234
    with pytest.raises(RuntimeError):
        resp.enable_chunked_encoding()


async def test_chunked_encoding_forbidden_for_http_10() -> None:
    req = make_request("GET", "/", version=HttpVersion10)
    resp = web.StreamResponse()
    resp.enable_chunked_encoding()

    with pytest.raises(RuntimeError) as ctx:
        await resp.prepare(req)
    assert str(ctx.value) == "Using chunked encoding is forbidden for HTTP/1.0"


async def test_compression_no_accept() -> None:
    req = make_request("GET", "/")
    resp = web.StreamResponse()
    assert not resp.chunked

    assert not resp.compression
    resp.enable_compression()
    assert resp.compression

    msg = await resp.prepare(req)  # type: ignore[unreachable]
    assert not msg.enable_compression.called


async def test_compression_default_coding() -> None:
    req = make_request(
        "GET", "/", headers=CIMultiDict({hdrs.ACCEPT_ENCODING: "gzip, deflate"})
    )
    resp = web.StreamResponse()
    assert not resp.chunked

    assert not resp.compression
    resp.enable_compression()
    assert resp.compression

    msg = await resp.prepare(req)  # type: ignore[unreachable]

    msg.enable_compression.assert_called_with("deflate", zlib.Z_DEFAULT_STRATEGY)
    assert "deflate" == resp.headers.get(hdrs.CONTENT_ENCODING)
    assert msg.filter is not None


async def test_force_compression_deflate() -> None:
    req = make_request(
        "GET", "/", headers=CIMultiDict({hdrs.ACCEPT_ENCODING: "gzip, deflate"})
    )
    resp = web.StreamResponse()

    resp.enable_compression(web.ContentCoding.deflate)
    assert resp.compression

    msg = await resp.prepare(req)
    assert msg is not None
    msg.enable_compression.assert_called_with("deflate", zlib.Z_DEFAULT_STRATEGY)  # type: ignore[attr-defined]
    assert "deflate" == resp.headers.get(hdrs.CONTENT_ENCODING)


async def test_force_compression_deflate_large_payload() -> None:
    """Make sure a warning is thrown for large payloads compressed in the event loop."""
    req = make_request(
        "GET", "/", headers=CIMultiDict({hdrs.ACCEPT_ENCODING: "gzip, deflate"})
    )
    resp = web.Response(body=b"large")

    resp.enable_compression(web.ContentCoding.deflate)
    assert resp.compression

    with (
        pytest.warns(Warning, match="Synchronous compression of large response bodies"),
        mock.patch("aiohttp.web_response.LARGE_BODY_SIZE", 2),
    ):
        msg = await resp.prepare(req)
        assert msg is not None
    assert "deflate" == resp.headers.get(hdrs.CONTENT_ENCODING)


async def test_force_compression_no_accept_deflate() -> None:
    req = make_request("GET", "/")
    resp = web.StreamResponse()

    resp.enable_compression(web.ContentCoding.deflate)
    assert resp.compression

    msg = await resp.prepare(req)
    assert msg is not None
    msg.enable_compression.assert_called_with("deflate", zlib.Z_DEFAULT_STRATEGY)  # type: ignore[attr-defined]
    assert "deflate" == resp.headers.get(hdrs.CONTENT_ENCODING)


async def test_force_compression_gzip() -> None:
    req = make_request(
        "GET", "/", headers=CIMultiDict({hdrs.ACCEPT_ENCODING: "gzip, deflate"})
    )
    resp = web.StreamResponse()

    resp.enable_compression(web.ContentCoding.gzip)
    assert resp.compression

    msg = await resp.prepare(req)
    assert msg is not None
    msg.enable_compression.assert_called_with("gzip", zlib.Z_DEFAULT_STRATEGY)  # type: ignore[attr-defined]
    assert "gzip" == resp.headers.get(hdrs.CONTENT_ENCODING)


async def test_force_compression_no_accept_gzip() -> None:
    req = make_request("GET", "/")
    resp = web.StreamResponse()

    resp.enable_compression(web.ContentCoding.gzip)
    assert resp.compression

    msg = await resp.prepare(req)
    assert msg is not None
    msg.enable_compression.assert_called_with("gzip", zlib.Z_DEFAULT_STRATEGY)  # type: ignore[attr-defined]
    assert "gzip" == resp.headers.get(hdrs.CONTENT_ENCODING)


async def test_change_content_threaded_compression_enabled() -> None:
    req = make_request("GET", "/")
    body_thread_size = 1024
    body = b"answer" * body_thread_size
    resp = web.Response(body=body, zlib_executor_size=body_thread_size)
    resp.enable_compression(web.ContentCoding.gzip)

    await resp.prepare(req)
    assert resp._compressed_body is not None
    assert gzip.decompress(resp._compressed_body) == body


async def test_change_content_threaded_compression_enabled_explicit() -> None:
    req = make_request("GET", "/")
    body_thread_size = 1024
    body = b"answer" * body_thread_size
    with ThreadPoolExecutor(1) as executor:
        resp = web.Response(
            body=body, zlib_executor_size=body_thread_size, zlib_executor=executor
        )
        resp.enable_compression(web.ContentCoding.gzip)

        await resp.prepare(req)
        assert resp._compressed_body is not None
        assert gzip.decompress(resp._compressed_body) == body


async def test_change_content_length_if_compression_enabled() -> None:
    req = make_request("GET", "/")
    resp = web.Response(body=b"answer")
    resp.enable_compression(web.ContentCoding.gzip)

    await resp.prepare(req)
    assert resp.content_length is not None and resp.content_length != len(b"answer")


async def test_set_content_length_if_compression_enabled() -> None:
    writer = mock.Mock()

    async def write_headers(status_line: str, headers: CIMultiDict[str]) -> None:
        assert hdrs.CONTENT_LENGTH in headers
        assert headers[hdrs.CONTENT_LENGTH] == "26"
        assert hdrs.TRANSFER_ENCODING not in headers

    writer.write_headers.side_effect = write_headers
    req = make_request("GET", "/", writer=writer)
    resp = web.Response(body=b"answer")
    resp.enable_compression(web.ContentCoding.gzip)

    await resp.prepare(req)
    assert resp.content_length == 26
    del resp.headers[hdrs.CONTENT_LENGTH]
    assert resp.content_length == 26


async def test_remove_content_length_if_compression_enabled_http11() -> None:
    writer = mock.Mock()

    async def write_headers(status_line: str, headers: CIMultiDict[str]) -> None:
        assert hdrs.CONTENT_LENGTH not in headers
        assert headers.get(hdrs.TRANSFER_ENCODING, "") == "chunked"

    writer.write_headers.side_effect = write_headers
    req = make_request("GET", "/", writer=writer)
    resp = web.StreamResponse()
    resp.content_length = 123
    resp.enable_compression(web.ContentCoding.gzip)
    await resp.prepare(req)
    assert resp.content_length is None


async def test_remove_content_length_if_compression_enabled_http10() -> None:
    writer = mock.Mock()

    async def write_headers(status_line: str, headers: CIMultiDict[str]) -> None:
        assert hdrs.CONTENT_LENGTH not in headers
        assert hdrs.TRANSFER_ENCODING not in headers

    writer.write_headers.side_effect = write_headers
    req = make_request("GET", "/", version=HttpVersion10, writer=writer)
    resp = web.StreamResponse()
    resp.content_length = 123
    resp.enable_compression(web.ContentCoding.gzip)
    await resp.prepare(req)
    assert resp.content_length is None


async def test_force_compression_identity() -> None:
    writer = mock.Mock()

    async def write_headers(status_line: str, headers: CIMultiDict[str]) -> None:
        assert hdrs.CONTENT_LENGTH in headers
        assert hdrs.TRANSFER_ENCODING not in headers

    writer.write_headers.side_effect = write_headers
    req = make_request("GET", "/", writer=writer)
    resp = web.StreamResponse()
    resp.content_length = 123
    resp.enable_compression(web.ContentCoding.identity)
    await resp.prepare(req)
    assert resp.content_length == 123


async def test_force_compression_identity_response() -> None:
    writer = mock.Mock()

    async def write_headers(status_line: str, headers: CIMultiDict[str]) -> None:
        assert headers[hdrs.CONTENT_LENGTH] == "6"
        assert hdrs.TRANSFER_ENCODING not in headers

    writer.write_headers.side_effect = write_headers
    req = make_request("GET", "/", writer=writer)
    resp = web.Response(body=b"answer")
    resp.enable_compression(web.ContentCoding.identity)
    await resp.prepare(req)
    assert resp.content_length == 6


async def test_rm_content_length_if_compression_http11() -> None:
    writer = mock.Mock()

    async def write_headers(status_line: str, headers: CIMultiDict[str]) -> None:
        assert hdrs.CONTENT_LENGTH not in headers
        assert headers.get(hdrs.TRANSFER_ENCODING, "") == "chunked"

    writer.write_headers.side_effect = write_headers
    req = make_request("GET", "/", writer=writer)
    payload = BytesPayload(b"answer", headers={"X-Test-Header": "test"})
    resp = web.Response(body=payload)
    resp.body = payload
    resp.enable_compression(web.ContentCoding.gzip)
    await resp.prepare(req)
    assert resp.content_length is None


async def test_rm_content_length_if_compression_http10() -> None:
    writer = mock.Mock()

    async def write_headers(status_line: str, headers: CIMultiDict[str]) -> None:
        assert hdrs.CONTENT_LENGTH not in headers
        assert hdrs.TRANSFER_ENCODING not in headers

    writer.write_headers.side_effect = write_headers
    req = make_request("GET", "/", version=HttpVersion10, writer=writer)
    resp = web.Response(body=BytesPayload(b"answer"))
    resp.enable_compression(web.ContentCoding.gzip)
    await resp.prepare(req)
    assert resp.content_length is None


async def test_rm_content_length_if_204() -> None:
    """Ensure content-length is removed for 204 responses."""
    writer = mock.create_autospec(StreamWriter, spec_set=True, instance=True)

    async def write_headers(status_line: str, headers: CIMultiDict[str]) -> None:
        assert hdrs.CONTENT_LENGTH not in headers

    writer.write_headers.side_effect = write_headers
    req = make_request("GET", "/", writer=writer)
    payload = BytesPayload(b"answer", headers={"Content-Length": "6"})
    resp = web.Response(body=payload, status=204)
    resp.body = payload
    await resp.prepare(req)
    assert resp.content_length is None


@pytest.mark.parametrize("status", (100, 101, 204, 304))
async def test_rm_transfer_encoding_rfc_9112_6_3_http_11(status: int) -> None:
    """Remove transfer encoding for RFC 9112 sec 6.3 with HTTP/1.1."""
    writer = mock.create_autospec(StreamWriter, spec_set=True, instance=True)
    req = make_request("GET", "/", version=HttpVersion11, writer=writer)
    resp = web.Response(status=status, headers={hdrs.TRANSFER_ENCODING: "chunked"})
    await resp.prepare(req)
    assert resp.content_length == 0
    assert not resp.chunked
    assert hdrs.CONTENT_LENGTH not in resp.headers
    assert hdrs.TRANSFER_ENCODING not in resp.headers


@pytest.mark.parametrize("status", (100, 101, 102, 204, 304))
async def test_rm_content_length_1xx_204_304_responses(status: int) -> None:
    """Remove content length for 1xx, 204, and 304 responses.

    Content-Length is forbidden for 1xx and 204
    https://datatracker.ietf.org/doc/html/rfc7230#section-3.3.2

    Content-Length is discouraged for 304.
    https://datatracker.ietf.org/doc/html/rfc7232#section-4.1
    """
    writer = mock.create_autospec(StreamWriter, spec_set=True, instance=True)
    req = make_request("GET", "/", version=HttpVersion11, writer=writer)
    resp = web.Response(status=status, body="answer")
    await resp.prepare(req)
    assert not resp.chunked
    assert hdrs.CONTENT_LENGTH not in resp.headers
    assert hdrs.TRANSFER_ENCODING not in resp.headers


async def test_head_response_keeps_content_length_of_original_body() -> None:
    """Verify HEAD response keeps the content length of the original body HTTP/1.1."""
    writer = mock.create_autospec(StreamWriter, spec_set=True, instance=True)
    req = make_request("HEAD", "/", version=HttpVersion11, writer=writer)
    resp = web.Response(status=200, body=b"answer")
    await resp.prepare(req)
    assert resp.content_length == 6
    assert not resp.chunked
    assert resp.headers[hdrs.CONTENT_LENGTH] == "6"
    assert hdrs.TRANSFER_ENCODING not in resp.headers


async def test_head_response_omits_content_length_when_body_unset() -> None:
    """Verify HEAD response omits content-length body when its unset."""
    writer = mock.create_autospec(StreamWriter, spec_set=True, instance=True)
    req = make_request("HEAD", "/", version=HttpVersion11, writer=writer)
    resp = web.Response(status=200)
    await resp.prepare(req)
    assert resp.content_length == 0
    assert not resp.chunked
    assert hdrs.CONTENT_LENGTH not in resp.headers
    assert hdrs.TRANSFER_ENCODING not in resp.headers


async def test_304_response_omits_content_length_when_body_unset() -> None:
    """Verify 304 response omits content-length body when its unset."""
    writer = mock.create_autospec(StreamWriter, spec_set=True, instance=True)
    req = make_request("GET", "/", version=HttpVersion11, writer=writer)
    resp = web.Response(status=304)
    await resp.prepare(req)
    assert resp.content_length == 0
    assert not resp.chunked
    assert hdrs.CONTENT_LENGTH not in resp.headers
    assert hdrs.TRANSFER_ENCODING not in resp.headers


async def test_content_length_on_chunked() -> None:
    req = make_request("GET", "/")
    resp = web.Response(body=b"answer")
    assert resp.content_length == 6
    resp.enable_chunked_encoding()
    assert resp.content_length is None
    await resp.prepare(req)  # type: ignore[unreachable]


async def test_write_non_byteish() -> None:
    resp = web.StreamResponse()
    await resp.prepare(make_request("GET", "/"))

    with pytest.raises(AssertionError):
        await resp.write(123)  # type: ignore[arg-type]


async def test_write_before_start() -> None:
    resp = web.StreamResponse()

    with pytest.raises(RuntimeError):
        await resp.write(b"data")


async def test_cannot_write_after_eof() -> None:
    resp = web.StreamResponse()
    req = make_request("GET", "/")
    await resp.prepare(req)

    await resp.write(b"data")
    await resp.write_eof()
    req.writer.write.reset_mock()  # type: ignore[attr-defined]

    with pytest.raises(RuntimeError):
        await resp.write(b"next data")
    assert not req.writer.write.called  # type: ignore[attr-defined]


async def test___repr___after_eof() -> None:
    resp = web.StreamResponse()
    await resp.prepare(make_request("GET", "/"))

    await resp.write(b"data")
    await resp.write_eof()
    resp_repr = repr(resp)
    assert resp_repr == "<StreamResponse OK eof>"


async def test_cannot_write_eof_before_headers() -> None:
    resp = web.StreamResponse()

    with pytest.raises(AssertionError):
        await resp.write_eof()


async def test_cannot_write_eof_twice() -> None:
    resp = web.StreamResponse()
    writer = mock.create_autospec(AbstractStreamWriter, spec_set=True)
    writer.write.return_value = None
    writer.write_eof.return_value = None
    resp_impl = await resp.prepare(make_request("GET", "/", writer=writer))

    await resp.write(b"data")
    assert resp_impl is not None
    assert resp_impl.write.called  # type: ignore[attr-defined]

    await resp.write_eof()

    resp_impl.write.reset_mock()  # type: ignore[attr-defined]
    await resp.write_eof()
    assert not writer.write.called


def test_force_close() -> None:
    resp = web.StreamResponse()

    assert resp.keep_alive is None
    resp.force_close()
    assert resp.keep_alive is False


def test_set_status_with_reason() -> None:
    resp = web.StreamResponse()

    resp.set_status(200, "Everything is fine!")
    assert 200 == resp.status
    assert "Everything is fine!" == resp.reason


def test_set_status_with_empty_reason() -> None:
    resp = web.StreamResponse()

    resp.set_status(200, "")
    assert resp.status == 200
    assert resp.reason == ""


async def test_start_force_close() -> None:
    req = make_request("GET", "/")
    resp = web.StreamResponse()
    resp.force_close()
    assert not resp.keep_alive

    await resp.prepare(req)
    assert not resp.keep_alive


async def test___repr__() -> None:
    req = make_request("GET", "/path/to")
    resp = web.StreamResponse(reason="foo")
    await resp.prepare(req)
    assert "<StreamResponse foo GET /path/to >" == repr(resp)


def test___repr___not_prepared() -> None:
    resp = web.StreamResponse(reason="foo")
    assert "<StreamResponse foo not prepared>" == repr(resp)


async def test_keep_alive_http10_default() -> None:
    req = make_request("GET", "/", version=HttpVersion10)
    resp = web.StreamResponse()
    await resp.prepare(req)
    assert not resp.keep_alive


async def test_keep_alive_http10_switched_on() -> None:
    headers = CIMultiDict(Connection="keep-alive")
    req = make_request("GET", "/", version=HttpVersion10, headers=headers)
    req._message = req._message._replace(should_close=False)
    resp = web.StreamResponse()
    await resp.prepare(req)
    assert resp.keep_alive


async def test_keep_alive_http09() -> None:
    headers = CIMultiDict(Connection="keep-alive")
    req = make_request("GET", "/", version=HttpVersion(0, 9), headers=headers)
    resp = web.StreamResponse()
    await resp.prepare(req)
    assert not resp.keep_alive


async def test_prepare_twice() -> None:
    req = make_request("GET", "/")
    resp = web.StreamResponse()

    impl1 = await resp.prepare(req)
    impl2 = await resp.prepare(req)
    assert impl1 is impl2


async def test_prepare_calls_signal() -> None:
    app = mock.create_autospec(web.Application, spec_set=True)
    sig = make_mocked_coro()
    app.on_response_prepare = aiosignal.Signal(app)
    app.on_response_prepare.append(sig)
    req = make_request("GET", "/", app=app)
    resp = web.StreamResponse()

    await resp.prepare(req)

    sig.assert_called_with(req, resp)


# Response class


def test_response_ctor() -> None:
    resp = web.Response()

    assert 200 == resp.status
    assert "OK" == resp.reason
    assert resp.body is None
    assert resp.content_length == 0
    assert "CONTENT-LENGTH" not in resp.headers


async def test_ctor_with_headers_and_status() -> None:
    resp = web.Response(body=b"body", status=201, headers={"Age": "12", "DATE": "date"})

    assert 201 == resp.status
    assert b"body" == resp.body
    assert resp.headers["AGE"] == "12"

    req = make_mocked_request("GET", "/")
    await resp._start(req)
    assert 4 == resp.content_length
    assert resp.headers["CONTENT-LENGTH"] == "4"


def test_ctor_content_type() -> None:
    resp = web.Response(content_type="application/json")

    assert 200 == resp.status
    assert "OK" == resp.reason
    assert 0 == resp.content_length
    assert CIMultiDict([("CONTENT-TYPE", "application/json")]) == resp.headers


def test_ctor_text_body_combined() -> None:
    with pytest.raises(ValueError):
        web.Response(body=b"123", text="test text")


async def test_ctor_text() -> None:
    resp = web.Response(text="test text")

    assert 200 == resp.status
    assert "OK" == resp.reason
    assert 9 == resp.content_length
    assert CIMultiDict([("CONTENT-TYPE", "text/plain; charset=utf-8")]) == resp.headers

    assert resp.body == b"test text"
    assert resp.text == "test text"

    resp.headers["DATE"] = "date"
    req = make_mocked_request("GET", "/", version=HttpVersion11)
    await resp._start(req)
    assert resp.headers["CONTENT-LENGTH"] == "9"


def test_ctor_charset() -> None:
    resp = web.Response(text="текст", charset="koi8-r")

    assert "текст".encode("koi8-r") == resp.body
    assert "koi8-r" == resp.charset


def test_ctor_charset_default_utf8() -> None:
    resp = web.Response(text="test test", charset=None)

    assert "utf-8" == resp.charset


def test_ctor_charset_in_content_type() -> None:
    with pytest.raises(ValueError):
        web.Response(text="test test", content_type="text/plain; charset=utf-8")


def test_ctor_charset_without_text() -> None:
    resp = web.Response(content_type="text/plain", charset="koi8-r")

    assert "koi8-r" == resp.charset


def test_ctor_content_type_with_extra() -> None:
    resp = web.Response(text="test test", content_type="text/plain; version=0.0.4")

    assert resp.content_type == "text/plain"
    assert resp.headers["content-type"] == "text/plain; version=0.0.4; charset=utf-8"


def test_ctor_both_content_type_param_and_header_with_text() -> None:
    with pytest.raises(ValueError):
        web.Response(
            headers={"Content-Type": "application/json"},
            content_type="text/html",
            text="text",
        )


def test_ctor_both_charset_param_and_header_with_text() -> None:
    with pytest.raises(ValueError):
        web.Response(
            headers={"Content-Type": "application/json"}, charset="koi8-r", text="text"
        )


def test_ctor_both_content_type_param_and_header() -> None:
    with pytest.raises(ValueError):
        web.Response(
            headers={"Content-Type": "application/json"}, content_type="text/html"
        )


def test_ctor_both_charset_param_and_header() -> None:
    with pytest.raises(ValueError):
        web.Response(headers={"Content-Type": "application/json"}, charset="koi8-r")


async def test_assign_nonbyteish_body() -> None:
    resp = web.Response(body=b"data")

    with pytest.raises(ValueError):
        resp.body = 123  # type: ignore[assignment]
    assert b"data" == resp.body
    assert 4 == resp.content_length

    resp.headers["DATE"] = "date"
    req = make_mocked_request("GET", "/", version=HttpVersion11)
    await resp._start(req)
    assert resp.headers["CONTENT-LENGTH"] == "4"
    assert 4 == resp.content_length


def test_assign_nonstr_text() -> None:
    resp = web.Response(text="test")

    with pytest.raises(AssertionError):
        resp.text = b"123"  # type: ignore[assignment]
    assert b"test" == resp.body
    assert 4 == resp.content_length


mpwriter = MultipartWriter(boundary="x")
mpwriter.append_payload(StringPayload("test"))


async def async_iter() -> AsyncIterator[str]:
    yield "foo"  # pragma: no cover


class CustomIO(io.IOBase):
    def __init__(self) -> None:
        self._lines = [b"", b"", b"test"]

    def read(self, size: int = -1) -> bytes:
        return self._lines.pop()


@pytest.mark.parametrize(
    "payload,expected",
    (
        ("test", "test"),
        (CustomIO(), "test"),
        (io.StringIO("test"), "test"),
        (io.TextIOWrapper(io.BytesIO(b"test")), "test"),
        (io.BytesIO(b"test"), "test"),
        (io.BufferedReader(io.BytesIO(b"test")), "test"),  # type: ignore[arg-type]
        (async_iter(), None),
        (BodyPartReader(b"x", CIMultiDictProxy(CIMultiDict()), mock.Mock()), None),
        (
            mpwriter,
            "--x\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 4\r\n\r\ntest",
        ),
    ),
)
def test_payload_body_get_text(payload: object, expected: Optional[str]) -> None:
    resp = web.Response(body=payload)
    if expected is None:
        with pytest.raises(TypeError):
            resp.text
    else:
        assert resp.text == expected


def test_response_set_content_length() -> None:
    resp = web.Response()
    with pytest.raises(RuntimeError):
        resp.content_length = 1


async def test_send_headers_for_empty_body(
    buf: bytearray, writer: AbstractStreamWriter
) -> None:
    req = make_request("GET", "/", writer=writer)
    resp = web.Response()

    await resp.prepare(req)
    await resp.write_eof()
    txt = buf.decode("utf8")

    lines = txt.split("\r\n")
    assert len(lines) == 6
    assert lines[0] == "HTTP/1.1 200 OK"
    assert lines[1] == "Content-Length: 0"
    assert lines[2].startswith("Date: ")
    assert lines[3].startswith("Server: ")
    assert lines[4] == lines[5] == ""


async def test_render_with_body(buf: bytearray, writer: AbstractStreamWriter) -> None:
    req = make_request("GET", "/", writer=writer)
    resp = web.Response(body=b"data")

    await resp.prepare(req)
    await resp.write_eof()
    txt = buf.decode("utf8")

    lines = txt.split("\r\n")
    assert len(lines) == 7
    assert lines[0] == "HTTP/1.1 200 OK"
    assert lines[1] == "Content-Length: 4"
    assert lines[2] == "Content-Type: application/octet-stream"
    assert lines[3].startswith("Date: ")
    assert lines[4].startswith("Server: ")
    assert lines[5] == ""
    assert lines[6] == "data"


async def test_multiline_reason(buf: bytearray, writer: AbstractStreamWriter) -> None:
    with pytest.raises(ValueError, match=r"Reason cannot contain \\n"):
        web.Response(reason="Bad\r\nInjected-header: foo")


async def test_send_set_cookie_header(
    buf: bytearray, writer: AbstractStreamWriter
) -> None:
    resp = web.Response()
    resp.cookies["name"] = "value"
    req = make_request("GET", "/", writer=writer)

    await resp.prepare(req)
    await resp.write_eof()
    txt = buf.decode("utf8")

    lines = txt.split("\r\n")
    assert len(lines) == 7
    assert lines[0] == "HTTP/1.1 200 OK"
    assert lines[1] == "Content-Length: 0"
    assert lines[2] == "Set-Cookie: name=value"
    assert lines[3].startswith("Date: ")
    assert lines[4].startswith("Server: ")
    assert lines[5] == lines[6] == ""


async def test_consecutive_write_eof() -> None:
    writer = mock.Mock()
    writer.write_eof = make_mocked_coro()
    writer.write_headers = make_mocked_coro()
    req = make_request("GET", "/", writer=writer)
    data = b"data"
    resp = web.Response(body=data)

    await resp.prepare(req)
    await resp.write_eof()
    await resp.write_eof()
    writer.write_eof.assert_called_once_with(data)


def test_set_text_with_content_type() -> None:
    resp = web.Response()
    resp.content_type = "text/html"
    resp.text = "text"

    assert "text" == resp.text
    assert b"text" == resp.body
    assert "text/html" == resp.content_type


def test_set_text_with_charset() -> None:
    resp = web.Response()
    resp.content_type = "text/plain"
    resp.charset = "KOI8-R"
    resp.text = "текст"

    assert "текст" == resp.text
    assert "текст".encode("koi8-r") == resp.body
    assert "koi8-r" == resp.charset


def test_default_content_type_in_stream_response() -> None:
    resp = web.StreamResponse()
    assert resp.content_type == "application/octet-stream"


def test_default_content_type_in_response() -> None:
    resp = web.Response()
    assert resp.content_type == "application/octet-stream"


def test_content_type_with_set_text() -> None:
    resp = web.Response(text="text")
    assert resp.content_type == "text/plain"


def test_content_type_with_set_body() -> None:
    resp = web.Response(body=b"body")
    assert resp.content_type == "application/octet-stream"


def test_prepared_when_not_started() -> None:
    resp = web.StreamResponse()
    assert not resp.prepared


async def test_prepared_when_started() -> None:
    resp = web.StreamResponse()
    await resp.prepare(make_request("GET", "/"))
    assert resp.prepared


async def test_prepared_after_eof() -> None:
    resp = web.StreamResponse()
    await resp.prepare(make_request("GET", "/"))
    await resp.write(b"data")
    await resp.write_eof()
    assert resp.prepared


async def test_drain_before_start() -> None:
    resp = web.StreamResponse()
    with pytest.raises(AssertionError):
        await resp.drain()


async def test_changing_status_after_prepare_raises() -> None:
    resp = web.StreamResponse()
    await resp.prepare(make_request("GET", "/"))
    with pytest.raises(AssertionError):
        resp.set_status(400)


def test_nonstr_text_in_ctor() -> None:
    with pytest.raises(TypeError):
        web.Response(text=b"data")  # type: ignore[arg-type]


def test_text_in_ctor_with_content_type() -> None:
    resp = web.Response(text="data", content_type="text/html")
    assert "data" == resp.text
    assert "text/html" == resp.content_type


def test_text_in_ctor_with_content_type_header() -> None:
    resp = web.Response(
        text="текст", headers={"Content-Type": "text/html; charset=koi8-r"}
    )
    assert "текст".encode("koi8-r") == resp.body
    assert "text/html" == resp.content_type
    assert "koi8-r" == resp.charset


def test_text_in_ctor_with_content_type_header_multidict() -> None:
    headers = CIMultiDict({"Content-Type": "text/html; charset=koi8-r"})
    resp = web.Response(text="текст", headers=headers)
    assert "текст".encode("koi8-r") == resp.body
    assert "text/html" == resp.content_type
    assert "koi8-r" == resp.charset


def test_body_in_ctor_with_content_type_header_multidict() -> None:
    headers = CIMultiDict({"Content-Type": "text/html; charset=koi8-r"})
    resp = web.Response(body="текст".encode("koi8-r"), headers=headers)
    assert "текст".encode("koi8-r") == resp.body
    assert "text/html" == resp.content_type
    assert "koi8-r" == resp.charset


def test_text_with_empty_payload() -> None:
    resp = web.Response(status=200)
    assert resp.body is None
    assert resp.text is None


def test_response_with_content_length_header_without_body() -> None:
    resp = web.Response(headers={"Content-Length": "123"})
    assert resp.content_length == 123


def test_response_with_immutable_headers() -> None:
    resp = web.Response(
        text="text", headers=CIMultiDictProxy(CIMultiDict({"Header": "Value"}))
    )
    assert resp.headers == {
        "Header": "Value",
        "Content-Type": "text/plain; charset=utf-8",
    }


async def test_response_prepared_after_header_preparation() -> None:
    req = make_request("GET", "/")
    resp = web.StreamResponse()
    await resp.prepare(req)

    assert type(resp.headers["Server"]) is str

    async def _strip_server(req: web.Request, res: web.Response) -> None:
        assert "Server" in res.headers

        if "Server" in res.headers:
            del res.headers["Server"]

    app = mock.create_autospec(web.Application, spec_set=True)
    app.on_response_prepare = aiosignal.Signal(app)
    app.on_response_prepare.append(_strip_server)

    req = make_request("GET", "/", app=app)
    resp = web.StreamResponse()
    await resp.prepare(req)

    assert "Server" not in resp.headers


def test_weakref_creation() -> None:
    resp = web.Response()
    weakref.ref(resp)


class TestJSONResponse:
    def test_content_type_is_application_json_by_default(self) -> None:
        resp = web.json_response("")
        assert "application/json" == resp.content_type

    def test_passing_text_only(self) -> None:
        resp = web.json_response(text=json.dumps("jaysawn"))
        assert resp.text == json.dumps("jaysawn")

    def test_data_and_text_raises_value_error(self) -> None:
        with pytest.raises(ValueError) as excinfo:
            web.json_response(data="foo", text="bar")
        expected_message = "only one of data, text, or body should be specified"
        assert expected_message == excinfo.value.args[0]

    def test_data_and_body_raises_value_error(self) -> None:
        with pytest.raises(ValueError) as excinfo:
            web.json_response(data="foo", body=b"bar")
        expected_message = "only one of data, text, or body should be specified"
        assert expected_message == excinfo.value.args[0]

    def test_text_is_json_encoded(self) -> None:
        resp = web.json_response({"foo": 42})
        assert json.dumps({"foo": 42}) == resp.text

    def test_content_type_is_overrideable(self) -> None:
        resp = web.json_response({"foo": 42}, content_type="application/vnd.json+api")
        assert "application/vnd.json+api" == resp.content_type


@pytest.mark.dev_mode
async def test_no_warn_small_cookie(
    buf: bytearray, writer: AbstractStreamWriter
) -> None:
    resp = web.Response()
    resp.set_cookie("foo", "ÿ" + "8" * 4064, max_age=2600)  # No warning
    req = make_request("GET", "/", writer=writer)

    await resp.prepare(req)
    await resp.write_eof()

    match = re.search(b"Set-Cookie: (.*?)\r\n", buf)
    assert match is not None
    cookie = match.group(1)
    assert len(cookie) == 4096


@pytest.mark.dev_mode
async def test_warn_large_cookie(buf: bytearray, writer: AbstractStreamWriter) -> None:
    resp = web.Response()

    with pytest.warns(
        UserWarning,
        match="The size of is too large, it might get ignored by the client.",
    ):
        resp.set_cookie("foo", "ÿ" + "8" * 4065, max_age=2600)
    req = make_request("GET", "/", writer=writer)

    await resp.prepare(req)
    await resp.write_eof()

    match = re.search(b"Set-Cookie: (.*?)\r\n", buf)
    assert match is not None
    cookie = match.group(1)
    assert len(cookie) == 4097
