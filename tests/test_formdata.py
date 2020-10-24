from unittest import mock

import pytest

from aiohttp import ClientSession, FormData


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


def test_formdata_multipart(buf, writer) -> None:
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
    form.add_field("emails[]", "xxx@x.co", content_type="multipart/form-data")
    payload = form()
    await payload.write(writer)
    assert b'name="emails%5B%5D"' in buf


async def test_formdata_field_name_is_not_quoted(buf, writer) -> None:
    form = FormData(quote_fields=False, charset="ascii")
    form.add_field("emails[]", "xxx@x.co", content_type="multipart/form-data")
    payload = form()
    await payload.write(writer)
    assert b'name="emails[]"' in buf


async def test_mark_formdata_as_processed() -> None:
    async with ClientSession() as session:
        url = "http://httpbin.org/anything"
        data = FormData()
        data.add_field("test", "test_value", content_type="application/json")

        await session.post(url, data=data)
        assert len(data._writer._parts) == 1

        with pytest.raises(RuntimeError):
            await session.post(url, data=data)
