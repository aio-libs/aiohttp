import asyncio
from unittest import mock

import pytest

from aiohttp.formdata import FormData


@pytest.fixture
def buf():
    return bytearray()


@pytest.fixture
def writer(buf):
    writer = mock.Mock()

    def write(chunk):
        buf.extend(chunk)
        return ()

    writer.write.side_effect = write
    return writer


def test_formdata_multipart(buf, writer):
    form = FormData()
    assert not form.is_multipart

    form.add_field('test', b'test', filename='test.txt')
    assert form.is_multipart


def test_invalid_formdata_payload():
    form = FormData()
    form.add_field('test', object(), filename='test.txt')
    with pytest.raises(TypeError):
        form()


def test_invalid_formdata_params():
    with pytest.raises(TypeError):
        FormData('asdasf')


def test_invalid_formdata_params2():
    with pytest.raises(TypeError):
        FormData('as')  # 2-char str is not allowed


def test_invalid_formdata_content_type():
    form = FormData()
    invalid_vals = [0, 0.1, {}, [], b'foo']
    for invalid_val in invalid_vals:
        with pytest.raises(TypeError):
            form.add_field('foo', 'bar', content_type=invalid_val)


def test_invalid_formdata_filename():
    form = FormData()
    invalid_vals = [0, 0.1, {}, [], b'foo']
    for invalid_val in invalid_vals:
        with pytest.raises(TypeError):
            form.add_field('foo', 'bar', filename=invalid_val)


def test_invalid_formdata_content_transfer_encoding():
    form = FormData()
    invalid_vals = [0, 0.1, {}, [], b'foo']
    for invalid_val in invalid_vals:
        with pytest.raises(TypeError):
            form.add_field('foo',
                           'bar',
                           content_transfer_encoding=invalid_val)


@asyncio.coroutine
def test_formdata_field_name_is_quoted(buf, writer):
    form = FormData(charset="ascii")
    form.add_field("emails[]", "xxx@x.co", content_type="multipart/form-data")
    payload = form()
    yield from payload.write(writer)
    assert b'name="emails%5B%5D"' in buf


@asyncio.coroutine
def test_formdata_field_name_is_not_quoted(buf, writer):
    form = FormData(quote_fields=False, charset="ascii")
    form.add_field("emails[]", "xxx@x.co", content_type="multipart/form-data")
    payload = form()
    yield from payload.write(writer)
    assert b'name="emails[]"' in buf
