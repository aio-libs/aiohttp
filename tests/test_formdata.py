import io
from unittest import mock

import pytest

from aiohttp import FormData, web


@pytest.fixture
def buf():
    return bytearray()


@pytest.fixture
def writer(buf):
    writer = mock.Mock()

    async def write(chunk):
        buf.extend(chunk)

    writer.write.side_effect = write
    return writer


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


async def test_formdata_textio_charset(buf: bytearray, writer) -> None:
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
            form.add_field("foo", "bar", content_type=invalid_val)


def test_invalid_formdata_filename() -> None:
    form = FormData()
    invalid_vals = [0, 0.1, {}, [], b"foo"]
    for invalid_val in invalid_vals:
        with pytest.raises(TypeError):
            form.add_field("foo", "bar", filename=invalid_val)


def test_invalid_formdata_content_transfer_encoding() -> None:
    form = FormData()
    invalid_vals = [0, 0.1, {}, [], b"foo"]
    for invalid_val in invalid_vals:
        with pytest.raises(TypeError):
            form.add_field("foo", "bar", content_transfer_encoding=invalid_val)


async def test_formdata_field_name_is_quoted(buf, writer) -> None:
    form = FormData(charset="ascii")
    form.add_field("email 1", "xxx@x.co", content_type="multipart/form-data")
    payload = form()
    await payload.write(writer)
    assert b'name="email\\ 1"' in buf


async def test_formdata_field_name_is_not_quoted(buf, writer) -> None:
    form = FormData(quote_fields=False, charset="ascii")
    form.add_field("email 1", "xxx@x.co", content_type="multipart/form-data")
    payload = form()
    await payload.write(writer)
    assert b'name="email 1"' in buf


async def test_mark_formdata_as_processed(aiohttp_client) -> None:
    async def handler(request):
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
