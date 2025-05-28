import io
from unittest import mock

import pytest

from aiohttp import FormData, web
from aiohttp.http_writer import StreamWriter
from aiohttp.pytest_plugin import AiohttpClient


@pytest.fixture
def buf() -> bytearray:
    return bytearray()


@pytest.fixture
def writer(buf: bytearray) -> StreamWriter:
    writer = mock.create_autospec(StreamWriter, spec_set=True)

    async def write(chunk: bytes) -> None:
        buf.extend(chunk)

    writer.write.side_effect = write
    return writer  # type: ignore[no-any-return]


def test_formdata_multipart(buf: bytearray) -> None:
    form = FormData(default_to_multipart=False)
    assert not form.is_multipart

    form.add_field("test", b"test", filename="test.txt")
    assert form.is_multipart


def test_form_data_is_multipart_param(buf: bytearray) -> None:
    form = FormData(default_to_multipart=True)
    assert form.is_multipart

    form.add_field("test", "test")
    assert form.is_multipart


@pytest.mark.parametrize("obj", (object(), None))
def test_invalid_formdata_payload_multipart(obj: object) -> None:
    form = FormData()
    form.add_field("test", obj, filename="test.txt")
    with pytest.raises(TypeError, match="Can not serialize value"):
        form()


@pytest.mark.parametrize("obj", (object(), None))
def test_invalid_formdata_payload_urlencoded(obj: object) -> None:
    form = FormData({"test": obj})
    with pytest.raises(TypeError, match="expected str"):
        form()


def test_invalid_formdata_params() -> None:
    with pytest.raises(TypeError):
        FormData("asdasf")


def test_invalid_formdata_params2() -> None:
    with pytest.raises(TypeError):
        FormData("as")  # 2-char str is not allowed


async def test_formdata_textio_charset(buf: bytearray, writer: StreamWriter) -> None:
    form = FormData()
    body = io.TextIOWrapper(io.BytesIO(b"\xe6\x97\xa5\xe6\x9c\xac"), encoding="utf-8")
    form.add_field("foo", body, content_type="text/plain; charset=shift-jis")
    payload = form()
    await payload.write(writer)
    assert b"charset=shift-jis" in buf
    assert b"\x93\xfa\x96{" in buf


def test_invalid_formdata_content_type() -> None:
    form = FormData()
    invalid_vals = [0, 0.1, {}, [], b"foo"]
    for invalid_val in invalid_vals:
        with pytest.raises(TypeError):
            form.add_field("foo", "bar", content_type=invalid_val)  # type: ignore[arg-type]


def test_invalid_formdata_filename() -> None:
    form = FormData()
    invalid_vals = [0, 0.1, {}, [], b"foo"]
    for invalid_val in invalid_vals:
        with pytest.raises(TypeError):
            form.add_field("foo", "bar", filename=invalid_val)  # type: ignore[arg-type]


async def test_formdata_field_name_is_quoted(
    buf: bytearray, writer: StreamWriter
) -> None:
    form = FormData(charset="ascii")
    form.add_field("email 1", "xxx@x.co", content_type="multipart/form-data")
    payload = form()
    await payload.write(writer)
    assert b'name="email\\ 1"' in buf


async def test_formdata_field_name_is_not_quoted(
    buf: bytearray, writer: StreamWriter
) -> None:
    form = FormData(quote_fields=False, charset="ascii")
    form.add_field("email 1", "xxx@x.co", content_type="multipart/form-data")
    payload = form()
    await payload.write(writer)
    assert b'name="email 1"' in buf


async def test_formdata_is_reusable(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response()

    app = web.Application()
    app.add_routes([web.post("/", handler)])

    client = await aiohttp_client(app)

    data = FormData()
    data.add_field("test", "test_value", content_type="application/json")

    # First request
    resp1 = await client.post("/", data=data)
    assert resp1.status == 200
    resp1.release()

    # Second request - should work without RuntimeError
    resp2 = await client.post("/", data=data)
    assert resp2.status == 200
    resp2.release()

    # Third request to ensure continued reusability
    resp3 = await client.post("/", data=data)
    assert resp3.status == 200
    resp3.release()


async def test_formdata_boundary_param() -> None:
    boundary = "some_boundary"
    form = FormData(boundary=boundary)
    assert form._writer.boundary == boundary


async def test_formdata_reusability_multipart(
    writer: StreamWriter, buf: bytearray
) -> None:
    form = FormData()
    form.add_field("name", "value")
    form.add_field("file", b"content", filename="test.txt", content_type="text/plain")

    # First call - should generate multipart payload
    payload1 = form()
    assert form.is_multipart
    buf.clear()
    await payload1.write(writer)
    result1 = bytes(buf)

    # Verify first result contains expected content
    assert b"name" in result1
    assert b"value" in result1
    assert b"test.txt" in result1
    assert b"content" in result1
    assert b"text/plain" in result1

    # Second call - should generate identical multipart payload
    payload2 = form()
    buf.clear()
    await payload2.write(writer)
    result2 = bytes(buf)

    # Results should be identical (same boundary and content)
    assert result1 == result2

    # Third call to ensure continued reusability
    payload3 = form()
    buf.clear()
    await payload3.write(writer)
    result3 = bytes(buf)

    assert result1 == result3


async def test_formdata_reusability_urlencoded(
    writer: StreamWriter, buf: bytearray
) -> None:
    form = FormData()
    form.add_field("key1", "value1")
    form.add_field("key2", "value2")

    # First call - should generate urlencoded payload
    payload1 = form()
    assert not form.is_multipart
    buf.clear()
    await payload1.write(writer)
    result1 = bytes(buf)

    # Verify first result contains expected content
    assert b"key1=value1" in result1
    assert b"key2=value2" in result1

    # Second call - should generate identical urlencoded payload
    payload2 = form()
    buf.clear()
    await payload2.write(writer)
    result2 = bytes(buf)

    # Results should be identical
    assert result1 == result2

    # Third call to ensure continued reusability
    payload3 = form()
    buf.clear()
    await payload3.write(writer)
    result3 = bytes(buf)

    assert result1 == result3


async def test_formdata_reusability_after_adding_fields(
    writer: StreamWriter, buf: bytearray
) -> None:
    form = FormData()
    form.add_field("field1", "value1")

    # First call
    payload1 = form()
    buf.clear()
    await payload1.write(writer)
    result1 = bytes(buf)

    # Add more fields after first call
    form.add_field("field2", "value2")

    # Second call should include new field
    payload2 = form()
    buf.clear()
    await payload2.write(writer)
    result2 = bytes(buf)

    # Results should be different
    assert result1 != result2
    assert b"field1=value1" in result2
    assert b"field2=value2" in result2
    assert b"field2=value2" not in result1

    # Third call should be same as second
    payload3 = form()
    buf.clear()
    await payload3.write(writer)
    result3 = bytes(buf)

    assert result2 == result3


async def test_formdata_reusability_with_io_fields(
    writer: StreamWriter, buf: bytearray
) -> None:
    form = FormData()

    # Create BytesIO and StringIO objects
    bytes_io = io.BytesIO(b"bytes content")
    string_io = io.StringIO("string content")

    form.add_field(
        "bytes_field",
        bytes_io,
        filename="bytes.bin",
        content_type="application/octet-stream",
    )
    form.add_field(
        "string_field", string_io, filename="text.txt", content_type="text/plain"
    )

    # First call
    payload1 = form()
    buf.clear()
    await payload1.write(writer)
    result1 = bytes(buf)

    assert b"bytes content" in result1
    assert b"string content" in result1

    # Reset IO objects for reuse
    bytes_io.seek(0)
    string_io.seek(0)

    # Second call - should work with reset IO objects
    payload2 = form()
    buf.clear()
    await payload2.write(writer)
    result2 = bytes(buf)

    # Should produce identical results
    assert result1 == result2
