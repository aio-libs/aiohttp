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
    form = FormData()
    assert not form.is_multipart

    form.add_field("test", b"test", filename="test.txt")
    assert form.is_multipart


def test_invalid_formdata_payload() -> None:
    form = FormData()
    form.add_field("test", object(), filename="test.txt")
    with pytest.raises(TypeError):
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


async def test_mark_formdata_as_processed(aiohttp_client: AiohttpClient) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response()

    app = web.Application()
    app.add_routes([web.post("/", handler)])

    client = await aiohttp_client(app)

    data = FormData()
    data.add_field("test", "test_value", content_type="application/json")

    resp = await client.post("/", data=data)
    assert len(data._writer._parts) == 1

    with pytest.raises(RuntimeError):
        await client.post("/", data=data)

    resp.release()


async def test_formdata_boundary_param() -> None:
    boundary = "some_boundary"
    form = FormData(boundary=boundary)
    assert form._writer.boundary == boundary
