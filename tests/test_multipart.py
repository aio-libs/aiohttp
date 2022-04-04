# type: ignore
import asyncio
import io
import json
import pathlib
import sys
import zlib
from typing import Any, Optional
from unittest import mock

import pytest

import aiohttp
from aiohttp import payload
from aiohttp.hdrs import (
    CONTENT_DISPOSITION,
    CONTENT_ENCODING,
    CONTENT_TRANSFER_ENCODING,
    CONTENT_TYPE,
)
from aiohttp.helpers import parse_mimetype
from aiohttp.multipart import MultipartResponseWrapper
from aiohttp.streams import StreamReader
from aiohttp.test_utils import make_mocked_coro

BOUNDARY: bytes = b"--:"


def pytest_generate_tests(metafunc: Any) -> None:  # pragma: no cover
    if "newline" in metafunc.fixturenames:
        metafunc.parametrize("newline", [b"\r\n", b"\n"], ids=str)


@pytest.fixture
def buf():
    return bytearray()


@pytest.fixture
def stream(buf: Any):
    writer = mock.Mock()

    async def write(chunk):
        buf.extend(chunk)

    writer.write.side_effect = write
    return writer


@pytest.fixture
def writer():
    return aiohttp.MultipartWriter(boundary=":")


class Response:
    headers: Any
    content: Any

    def __init__(self, headers: Any, content: Any) -> None:
        self.headers = headers
        self.content = content


class Stream:
    content: Any

    def __init__(self, content: Any) -> None:
        self.content = io.BytesIO(content)

    async def read(self, size: Optional[Any] = None):
        return self.content.read(size)

    def at_eof(self):
        return self.content.tell() == len(self.content.getbuffer())

    async def readline(self):
        return self.content.readline()

    def unread_data(self, data: Any) -> None:
        self.content = io.BytesIO(data + self.content.read())


class StreamWithShortenRead(Stream):
    def __init__(self, content: Any) -> None:
        self._first = True
        super().__init__(content)

    async def read(self, size: Optional[Any] = None):
        if size is not None and self._first:
            self._first = False
            size = size // 2
        return await super().read(size)


class TestMultipartResponseWrapper:
    def test_at_eof(self) -> None:
        wrapper = MultipartResponseWrapper(mock.Mock(), mock.Mock())
        wrapper.at_eof()
        assert wrapper.resp.content.at_eof.called

    async def test_next(self) -> None:
        wrapper = MultipartResponseWrapper(mock.Mock(), mock.Mock())
        wrapper.stream.next = make_mocked_coro(b"")
        wrapper.stream.at_eof.return_value = False
        await wrapper.next()
        assert wrapper.stream.next.called

    async def test_release(self) -> None:
        wrapper = MultipartResponseWrapper(mock.Mock(), mock.Mock())
        wrapper.resp.release = make_mocked_coro(None)
        await wrapper.release()
        assert wrapper.resp.release.called

    async def test_release_when_stream_at_eof(self) -> None:
        wrapper = MultipartResponseWrapper(mock.Mock(), mock.Mock())
        wrapper.resp.release = make_mocked_coro(None)
        wrapper.stream.next = make_mocked_coro(b"")
        wrapper.stream.at_eof.return_value = True
        await wrapper.next()
        assert wrapper.stream.next.called
        assert wrapper.resp.release.called


class TestPartReader:
    async def test_next(self, newline: Any) -> None:
        data = b"Hello, world!%s--:" % newline
        obj = aiohttp.BodyPartReader(BOUNDARY, {}, Stream(data), _newline=newline)
        result = await obj.next()
        assert b"Hello, world!" == result
        assert obj.at_eof()

    async def test_next_next(self, newline: Any) -> None:
        data = b"Hello, world!%s--:" % newline
        obj = aiohttp.BodyPartReader(BOUNDARY, {}, Stream(data), _newline=newline)
        result = await obj.next()
        assert b"Hello, world!" == result
        assert obj.at_eof()
        result = await obj.next()
        assert result is None

    async def test_read(self, newline: Any) -> None:
        data = b"Hello, world!%s--:" % newline
        obj = aiohttp.BodyPartReader(BOUNDARY, {}, Stream(data), _newline=newline)
        result = await obj.read()
        assert b"Hello, world!" == result
        assert obj.at_eof()

    async def test_read_chunk_at_eof(self) -> None:
        obj = aiohttp.BodyPartReader(BOUNDARY, {}, Stream(b"--:"))
        obj._at_eof = True
        result = await obj.read_chunk()
        assert b"" == result

    async def test_read_chunk_without_content_length(self, newline: Any) -> None:
        data = b"Hello, world!%s--:" % newline
        obj = aiohttp.BodyPartReader(BOUNDARY, {}, Stream(data), _newline=newline)
        c1 = await obj.read_chunk(8)
        c2 = await obj.read_chunk(8)
        c3 = await obj.read_chunk(8)
        assert c1 + c2 == b"Hello, world!"
        assert c3 == b""

    async def test_read_incomplete_chunk(self, newline: Any) -> None:
        stream = Stream(b"")

        if sys.version_info >= (3, 8, 1):
            # Workaround for a weird behavior of patch.object
            def prepare(data):
                return data

        else:

            async def prepare(data):
                return data

        with mock.patch.object(
            stream,
            "read",
            side_effect=[
                prepare(b"Hello, "),
                prepare(b"World"),
                prepare(b"!%s--:" % newline),
                prepare(b""),
            ],
        ):
            obj = aiohttp.BodyPartReader(BOUNDARY, {}, stream, _newline=newline)
            c1 = await obj.read_chunk(8)
            assert c1 == b"Hello, "
            c2 = await obj.read_chunk(8)
            assert c2 == b"World"
            c3 = await obj.read_chunk(8)
            assert c3 == b"!"

    async def test_read_all_at_once(self, newline: Any) -> None:
        data = b"Hello, World!%s--:--%s" % (newline, newline)
        obj = aiohttp.BodyPartReader(BOUNDARY, {}, Stream(data), _newline=newline)
        result = await obj.read_chunk()
        assert b"Hello, World!" == result
        result = await obj.read_chunk()
        assert b"" == result
        assert obj.at_eof()

    async def test_read_incomplete_body_chunked(self, newline: Any) -> None:
        data = b"Hello, World!%s--" % newline
        obj = aiohttp.BodyPartReader(BOUNDARY, {}, Stream(data), _newline=newline)
        result = b""
        with pytest.raises(AssertionError):
            for _ in range(4):
                result += await obj.read_chunk(7)
        assert data == result

    async def test_read_boundary_with_incomplete_chunk(self, newline: Any) -> None:
        stream = Stream(b"")

        if sys.version_info >= (3, 8, 1):
            # Workaround for weird 3.8.1 patch.object() behavior
            def prepare(data):
                return data

        else:

            async def prepare(data):
                return data

        with mock.patch.object(
            stream,
            "read",
            side_effect=[
                prepare(b"Hello, World"),
                prepare(b"!%s" % newline),
                prepare(b"--:"),
                prepare(b""),
            ],
        ):
            obj = aiohttp.BodyPartReader(BOUNDARY, {}, stream, _newline=newline)
            c1 = await obj.read_chunk(12)
            assert c1 == b"Hello, World"
            c2 = await obj.read_chunk(8)
            assert c2 == b"!"
            c3 = await obj.read_chunk(8)
            assert c3 == b""

    async def test_multi_read_chunk(self, newline: Any) -> None:
        data = b"Hello,%s--:%s%sworld!%s--:--" % ((newline,) * 4)
        obj = aiohttp.BodyPartReader(BOUNDARY, {}, Stream(data), _newline=newline)
        result = await obj.read_chunk(8)
        assert b"Hello," == result
        result = await obj.read_chunk(8)
        assert b"" == result
        assert obj.at_eof()

    async def test_read_chunk_properly_counts_read_bytes(self, newline: Any) -> None:
        expected = b"." * 10
        tail = b"%s--:--" % newline
        size = len(expected)
        obj = aiohttp.BodyPartReader(
            BOUNDARY,
            {"CONTENT-LENGTH": size},
            StreamWithShortenRead(expected + tail),
            _newline=newline,
        )
        result = bytearray()
        while True:
            chunk = await obj.read_chunk()
            if not chunk:
                break
            result.extend(chunk)
        assert size == len(result)
        assert b"." * size == result
        assert obj.at_eof()

    async def test_read_does_not_read_boundary(self, newline: Any) -> None:
        data = b"Hello, world!%s--:" % newline
        stream = Stream(data)
        obj = aiohttp.BodyPartReader(BOUNDARY, {}, stream, _newline=newline)
        result = await obj.read()
        assert b"Hello, world!" == result
        assert b"--:" == (await stream.read())

    async def test_multiread(self, newline: Any) -> None:
        data = b"Hello,%s--:%s%sworld!%s--:--" % ((newline,) * 4)
        obj = aiohttp.BodyPartReader(BOUNDARY, {}, Stream(data), _newline=newline)
        result = await obj.read()
        assert b"Hello," == result
        result = await obj.read()
        assert b"" == result
        assert obj.at_eof()

    async def test_read_multiline(self, newline: Any) -> None:
        data = b"Hello\n,\r\nworld!%s--:--" % newline
        obj = aiohttp.BodyPartReader(BOUNDARY, {}, Stream(data), _newline=newline)
        result = await obj.read()
        assert b"Hello\n,\r\nworld!" == result
        result = await obj.read()
        assert b"" == result
        assert obj.at_eof()

    async def test_read_respects_content_length(self, newline: Any) -> None:
        data = b"." * 100500
        tail = b"%s--:--" % newline
        obj = aiohttp.BodyPartReader(
            BOUNDARY,
            {"CONTENT-LENGTH": 100500},
            Stream(data + tail),
            _newline=newline,
        )
        result = await obj.read()
        assert data == result
        assert obj.at_eof()

    async def test_read_with_content_encoding_gzip(self, newline: Any) -> None:
        obj = aiohttp.BodyPartReader(
            BOUNDARY,
            {CONTENT_ENCODING: "gzip"},
            Stream(
                b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x0b\xc9\xccMU"
                b"(\xc9W\x08J\xcdI\xacP\x04\x00$\xfb\x9eV\x0e\x00\x00\x00"
                b"%s--:--" % newline
            ),
            _newline=newline,
        )
        result = await obj.read(decode=True)
        assert b"Time to Relax!" == result

    async def test_read_with_content_encoding_deflate(self, newline: Any) -> None:
        data = b"\x0b\xc9\xccMU(\xc9W\x08J\xcdI\xacP\x04\x00"
        tail = b"%s--:--" % newline
        obj = aiohttp.BodyPartReader(
            BOUNDARY,
            {CONTENT_ENCODING: "deflate"},
            Stream(data + tail),
            _newline=newline,
        )
        result = await obj.read(decode=True)
        assert b"Time to Relax!" == result

    async def test_read_with_content_encoding_identity(self, newline: Any) -> None:
        thing = (
            b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x0b\xc9\xccMU"
            b"(\xc9W\x08J\xcdI\xacP\x04\x00$\xfb\x9eV\x0e\x00\x00\x00"
        )
        obj = aiohttp.BodyPartReader(
            BOUNDARY,
            {CONTENT_ENCODING: "identity"},
            Stream(thing + b"%s--:--" % newline),
            _newline=newline,
        )
        result = await obj.read(decode=True)
        assert thing == result

    async def test_read_with_content_encoding_unknown(self, newline: Any) -> None:
        obj = aiohttp.BodyPartReader(
            BOUNDARY,
            {CONTENT_ENCODING: "snappy"},
            Stream(b"\x0e4Time to Relax!%s--:--" % newline),
            _newline=newline,
        )
        with pytest.raises(RuntimeError):
            await obj.read(decode=True)

    async def test_read_with_content_transfer_encoding_base64(
        self, newline: Any
    ) -> None:
        obj = aiohttp.BodyPartReader(
            BOUNDARY,
            {CONTENT_TRANSFER_ENCODING: "base64"},
            Stream(b"VGltZSB0byBSZWxheCE=%s--:--" % newline),
            _newline=newline,
        )
        result = await obj.read(decode=True)
        assert b"Time to Relax!" == result

    async def test_decode_with_content_transfer_encoding_base64(
        self, newline: Any
    ) -> None:

        obj = aiohttp.BodyPartReader(
            BOUNDARY,
            {CONTENT_TRANSFER_ENCODING: "base64"},
            Stream(b"VG\r\r\nltZSB0byBSZ\r\nWxheCE=%s--:--" % newline),
            _newline=newline,
        )
        result = b""
        while not obj.at_eof():
            chunk = await obj.read_chunk(size=6)
            result += obj.decode(chunk)
        assert b"Time to Relax!" == result

    async def test_read_with_content_transfer_encoding_quoted_printable(
        self, newline: Any
    ) -> None:
        obj = aiohttp.BodyPartReader(
            BOUNDARY,
            {CONTENT_TRANSFER_ENCODING: "quoted-printable"},
            Stream(
                b"=D0=9F=D1=80=D0=B8=D0=B2=D0=B5=D1=82,"
                b" =D0=BC=D0=B8=D1=80!%s--:--" % newline
            ),
            _newline=newline,
        )
        result = await obj.read(decode=True)
        expected = (
            b"\xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82,"
            b" \xd0\xbc\xd0\xb8\xd1\x80!"
        )
        assert result == expected

    @pytest.mark.parametrize("encoding", ("binary", "8bit", "7bit"))
    async def test_read_with_content_transfer_encoding_binary(
        self, encoding: Any, newline: Any
    ) -> None:
        data = (
            b"\xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82,"
            b" \xd0\xbc\xd0\xb8\xd1\x80!"
        )
        obj = aiohttp.BodyPartReader(
            BOUNDARY,
            {CONTENT_TRANSFER_ENCODING: encoding},
            Stream(data + b"%s--:--" % newline),
            _newline=newline,
        )
        result = await obj.read(decode=True)
        assert data == result

    async def test_read_with_content_transfer_encoding_unknown(
        self, newline: Any
    ) -> None:
        obj = aiohttp.BodyPartReader(
            BOUNDARY,
            {CONTENT_TRANSFER_ENCODING: "unknown"},
            Stream(b"\x0e4Time to Relax!%s--:--" % newline),
            _newline=newline,
        )
        with pytest.raises(RuntimeError):
            await obj.read(decode=True)

    async def test_read_text(self, newline: Any) -> None:
        obj = aiohttp.BodyPartReader(
            BOUNDARY,
            {},
            Stream(b"Hello, world!%s--:--" % newline),
            _newline=newline,
        )
        result = await obj.text()
        assert "Hello, world!" == result

    async def test_read_text_default_encoding(self, newline: Any) -> None:
        data = "Привет, Мир!"
        tail = b"%s--:--" % newline
        obj = aiohttp.BodyPartReader(
            BOUNDARY,
            {},
            Stream(data.encode("utf-8") + tail),
            _newline=newline,
        )
        result = await obj.text()
        assert data == result

    async def test_read_text_encoding(self, newline: Any) -> None:
        data = "Привет, Мир!"
        tail = b"%s--:--" % newline
        obj = aiohttp.BodyPartReader(
            BOUNDARY,
            {},
            Stream(data.encode("cp1251") + tail),
            _newline=newline,
        )
        result = await obj.text(encoding="cp1251")
        assert data == result

    async def test_read_text_guess_encoding(self, newline: Any) -> None:
        data = "Привет, Мир!"
        tail = b"%s--:--" % newline
        obj = aiohttp.BodyPartReader(
            BOUNDARY,
            {CONTENT_TYPE: "text/plain;charset=cp1251"},
            Stream(data.encode("cp1251") + tail),
            _newline=newline,
        )
        result = await obj.text()
        assert data == result

    async def test_read_text_compressed(self, newline: Any) -> None:
        data = b"\x0b\xc9\xccMU(\xc9W\x08J\xcdI\xacP\x04\x00" b"%s--:--" % newline
        obj = aiohttp.BodyPartReader(
            BOUNDARY,
            {CONTENT_ENCODING: "deflate", CONTENT_TYPE: "text/plain"},
            Stream(data),
            _newline=newline,
        )
        result = await obj.text()
        assert "Time to Relax!" == result

    async def test_read_text_while_closed(self) -> None:
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {CONTENT_TYPE: "text/plain"}, Stream(b"")
        )
        obj._at_eof = True
        result = await obj.text()
        assert "" == result

    async def test_read_json(self, newline: Any) -> None:
        obj = aiohttp.BodyPartReader(
            BOUNDARY,
            {CONTENT_TYPE: "application/json"},
            Stream(b'{"test": "passed"}%s--:--' % newline),
            _newline=newline,
        )
        result = await obj.json()
        assert {"test": "passed"} == result

    async def test_read_json_encoding(self, newline: Any) -> None:
        data = '{"тест": "пассед"}'.encode("cp1251")
        tail = b"%s--:--" % newline
        obj = aiohttp.BodyPartReader(
            BOUNDARY,
            {CONTENT_TYPE: "application/json"},
            Stream(data + tail),
            _newline=newline,
        )
        result = await obj.json(encoding="cp1251")
        assert {"тест": "пассед"} == result

    async def test_read_json_guess_encoding(self, newline: Any) -> None:
        data = '{"тест": "пассед"}'.encode("cp1251")
        tail = b"%s--:--" % newline
        obj = aiohttp.BodyPartReader(
            BOUNDARY,
            {CONTENT_TYPE: "application/json; charset=cp1251"},
            Stream(data + tail),
            _newline=newline,
        )
        result = await obj.json()
        assert {"тест": "пассед"} == result

    async def test_read_json_compressed(self, newline: Any) -> None:
        obj = aiohttp.BodyPartReader(
            BOUNDARY,
            {CONTENT_ENCODING: "deflate", CONTENT_TYPE: "application/json"},
            Stream(b"\xabV*I-.Q\xb2RP*H,.NMQ\xaa\x05\x00" b"%s--:--" % newline),
            _newline=newline,
        )
        result = await obj.json()
        assert {"test": "passed"} == result

    async def test_read_json_while_closed(self) -> None:
        stream = Stream(b"")
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {CONTENT_TYPE: "application/json"}, stream
        )
        obj._at_eof = True
        result = await obj.json()
        assert result is None

    async def test_read_form(self, newline: Any) -> None:
        data = b"foo=bar&foo=baz&boo=%s--:--" % newline
        obj = aiohttp.BodyPartReader(
            BOUNDARY,
            {CONTENT_TYPE: "application/x-www-form-urlencoded"},
            Stream(data),
            _newline=newline,
        )
        result = await obj.form()
        assert [("foo", "bar"), ("foo", "baz"), ("boo", "")] == result

    async def test_read_form_encoding(self, newline: Any) -> None:
        data = b"foo=bar&foo=baz&boo=%s--:--" % newline
        obj = aiohttp.BodyPartReader(
            BOUNDARY,
            {CONTENT_TYPE: "application/x-www-form-urlencoded"},
            Stream(data),
            _newline=newline,
        )
        result = await obj.form(encoding="cp1251")
        assert [("foo", "bar"), ("foo", "baz"), ("boo", "")] == result

    async def test_read_form_guess_encoding(self, newline: Any) -> None:
        data = b"foo=bar&foo=baz&boo=%s--:--" % newline
        obj = aiohttp.BodyPartReader(
            BOUNDARY,
            {CONTENT_TYPE: "application/x-www-form-urlencoded; charset=utf-8"},
            Stream(data),
            _newline=newline,
        )
        result = await obj.form()
        assert [("foo", "bar"), ("foo", "baz"), ("boo", "")] == result

    async def test_read_form_while_closed(self) -> None:
        stream = Stream(b"")
        obj = aiohttp.BodyPartReader(
            BOUNDARY,
            {CONTENT_TYPE: "application/x-www-form-urlencoded"},
            stream,
        )
        obj._at_eof = True
        result = await obj.form()
        assert not result

    async def test_readline(self, newline: Any) -> None:
        data = b"Hello\n,\r\nworld!%s--:--" % newline
        obj = aiohttp.BodyPartReader(
            BOUNDARY,
            {},
            Stream(data),
            _newline=newline,
        )
        result = await obj.readline()
        assert b"Hello\n" == result
        result = await obj.readline()
        assert b",\r\n" == result
        result = await obj.readline()
        assert b"world!" == result
        result = await obj.readline()
        assert b"" == result
        assert obj.at_eof()

    async def test_release(self, newline: Any) -> None:
        data = b"Hello,%s--:\r\n\r\nworld!%s--:--" % (newline, newline)
        stream = Stream(data)
        obj = aiohttp.BodyPartReader(
            BOUNDARY,
            {},
            stream,
            _newline=newline,
        )
        remained = b"--:\r\n\r\nworld!%s--:--" % newline
        await obj.release()
        assert obj.at_eof()
        assert remained == stream.content.read()

    async def test_release_respects_content_length(self, newline: Any) -> None:
        obj = aiohttp.BodyPartReader(
            BOUNDARY,
            {"CONTENT-LENGTH": 100500},
            Stream(b"." * 100500 + b"%s--:--" % newline),
            _newline=newline,
        )
        result = await obj.release()
        assert result is None
        assert obj.at_eof()

    async def test_release_release(self, newline: Any) -> None:
        data = b"Hello,%s--:\r\n\r\nworld!%s--:--" % (newline, newline)
        remained = b"--:\r\n\r\nworld!%s--:--" % newline
        stream = Stream(data)
        obj = aiohttp.BodyPartReader(
            BOUNDARY,
            {},
            stream,
            _newline=newline,
        )
        await obj.release()
        await obj.release()
        assert remained == stream.content.read()

    async def test_filename(self) -> None:
        part = aiohttp.BodyPartReader(
            BOUNDARY, {CONTENT_DISPOSITION: "attachment; filename=foo.html"}, None
        )
        assert "foo.html" == part.filename

    async def test_reading_long_part(self, newline: Any) -> None:
        size = 2 * 2**16
        protocol = mock.Mock(_reading_paused=False)
        stream = StreamReader(protocol, 2**16, loop=asyncio.get_event_loop())
        stream.feed_data(b"0" * size + b"%s--:--" % newline)
        stream.feed_eof()
        obj = aiohttp.BodyPartReader(BOUNDARY, {}, stream, _newline=newline)
        data = await obj.read()
        assert len(data) == size


class TestMultipartReader:
    def test_from_response(self, newline: Any) -> None:
        resp = Response(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b"--:%s\r\nhello%s--:--" % (newline, newline)),
        )
        res = aiohttp.MultipartReader.from_response(resp)
        assert isinstance(res, MultipartResponseWrapper)
        assert isinstance(res.stream, aiohttp.MultipartReader)

    def test_bad_boundary(self) -> None:
        resp = Response(
            {CONTENT_TYPE: "multipart/related;boundary=" + "a" * 80}, Stream(b"")
        )
        with pytest.raises(ValueError):
            aiohttp.MultipartReader.from_response(resp)

    def test_dispatch(self, newline: Any) -> None:
        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b"--:%s\r\necho%s--:--" % (newline, newline)),
        )
        res = reader._get_part_reader({CONTENT_TYPE: "text/plain"})
        assert isinstance(res, reader.part_reader_cls)

    def test_dispatch_bodypart(self, newline: Any) -> None:
        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b"--:%s\r\necho%s--:--" % (newline, newline)),
        )
        res = reader._get_part_reader({CONTENT_TYPE: "text/plain"})
        assert isinstance(res, reader.part_reader_cls)

    def test_dispatch_multipart(self, newline: Any) -> None:
        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(
                newline.join(
                    [
                        b"----:--",
                        b"",
                        b"test",
                        b"----:--",
                        b"",
                        b"passed",
                        b"----:----" b"--:--",
                    ]
                )
            ),
        )
        res = reader._get_part_reader(
            {CONTENT_TYPE: "multipart/related;boundary=--:--"}
        )
        assert isinstance(res, reader.__class__)

    def test_dispatch_custom_multipart_reader(self, newline: Any) -> None:
        class CustomReader(aiohttp.MultipartReader):
            pass

        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(
                newline.join(
                    [
                        b"----:--",
                        b"",
                        b"test",
                        b"----:--",
                        b"",
                        b"passed",
                        b"----:----",
                        b"--:--",
                    ]
                )
            ),
        )
        reader.multipart_reader_cls = CustomReader
        res = reader._get_part_reader(
            {CONTENT_TYPE: "multipart/related;boundary=--:--"}
        )
        assert isinstance(res, CustomReader)

    async def test_emit_next(self, newline: Any) -> None:
        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b"--:%s\r\necho%s--:--" % (newline, newline)),
        )
        res = await reader.next()
        assert isinstance(res, reader.part_reader_cls)

    async def test_invalid_boundary(self, newline: Any) -> None:
        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b"---:%s\r\necho%s---:--" % (newline, newline)),
        )
        with pytest.raises(ValueError):
            await reader.next()

    async def test_release(self, newline: Any) -> None:
        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/mixed;boundary=":"'},
            Stream(
                newline.join(
                    [
                        b"--:",
                        b"Content-Type: multipart/related;boundary=--:--",
                        b"",
                        b"----:--",
                        b"",
                        b"test",
                        b"----:--",
                        b"",
                        b"passed",
                        b"----:----",
                        b"",
                        b"--:--",
                    ]
                )
            ),
        )
        await reader.release()
        assert reader.at_eof()

    async def test_release_release(self, newline: Any) -> None:
        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b"--:%s\r\necho%s--:--" % (newline, newline)),
        )
        await reader.release()
        assert reader.at_eof()
        await reader.release()
        assert reader.at_eof()

    async def test_release_next(self, newline: Any) -> None:
        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b"--:%s\r\necho%s--:--" % (newline, newline)),
        )
        await reader.release()
        assert reader.at_eof()
        res = await reader.next()
        assert res is None

    async def test_second_next_releases_previous_object(self, newline: Any) -> None:
        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(
                newline.join(
                    [
                        b"--:",
                        b"",
                        b"test",
                        b"--:",
                        b"",
                        b"passed",
                        b"--:--",
                    ]
                )
            ),
        )
        first = await reader.next()
        assert isinstance(first, aiohttp.BodyPartReader)
        second = await reader.next()
        assert first.at_eof()
        assert not second.at_eof()

    async def test_release_without_read_the_last_object(self, newline: Any) -> None:
        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(
                newline.join(
                    [
                        b"--:",
                        b"",
                        b"test",
                        b"--:",
                        b"",
                        b"passed",
                        b"--:--",
                    ]
                )
            ),
        )
        first = await reader.next()
        second = await reader.next()
        third = await reader.next()
        assert first.at_eof()
        assert second.at_eof()
        assert second.at_eof()
        assert third is None

    async def test_read_chunk_by_length_doesnt_breaks_reader(
        self, newline: Any
    ) -> None:
        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(
                newline.join(
                    [
                        b"--:",
                        b"Content-Length: 4",
                        b"",
                        b"test",
                        b"--:",
                        b"Content-Length: 6",
                        b"",
                        b"passed",
                        b"--:--",
                    ]
                )
            ),
        )
        body_parts = []
        while True:
            read_part = b""
            part = await reader.next()
            if part is None:
                break
            while not part.at_eof():
                read_part += await part.read_chunk(3)
            body_parts.append(read_part)
        assert body_parts == [b"test", b"passed"]

    async def test_read_chunk_from_stream_doesnt_breaks_reader(
        self, newline: Any
    ) -> None:
        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(
                newline.join(
                    [
                        b"--:",
                        b"",
                        b"chunk",
                        b"--:",
                        b"",
                        b"two_chunks",
                        b"--:--",
                    ]
                )
            ),
        )
        body_parts = []
        while True:
            read_part = b""
            part = await reader.next()
            if part is None:
                break
            while not part.at_eof():
                chunk = await part.read_chunk(5)
                assert chunk
                read_part += chunk
            body_parts.append(read_part)
        assert body_parts == [b"chunk", b"two_chunks"]

    async def test_reading_skips_prelude(self, newline: Any) -> None:
        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(
                newline.join(
                    [
                        b"Multi-part data is not supported.",
                        b"",
                        b"--:",
                        b"",
                        b"test",
                        b"--:",
                        b"",
                        b"passed",
                        b"--:--",
                    ]
                )
            ),
        )
        first = await reader.next()
        assert isinstance(first, aiohttp.BodyPartReader)
        second = await reader.next()
        assert first.at_eof()
        assert not second.at_eof()

    async def test_read_mixed_newlines(self) -> None:
        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/mixed;boundary=":"'},
            Stream(
                b"".join(
                    [
                        b"--:\n",
                        b"Content-Type: multipart/related;boundary=--:--\n",
                        b"\n",
                        b"----:--\r\n",
                        b"\r\n",
                        b"test\r\n",
                        b"----:--\r\n",
                        b"\r\n",
                        b"passed\r\n",
                        b"----:----\r\n",
                        b"\n",
                        b"--:--",
                    ]
                )
            ),
        )
        while True:
            part = await reader.next()
            if part is None:
                break
            while True:
                subpart = await part.next()
                if subpart is None:
                    break


async def test_writer(writer: Any) -> None:
    assert writer.size == 7
    assert writer.boundary == ":"


async def test_writer_serialize_io_chunk(buf: Any, stream: Any, writer: Any) -> None:
    flo = io.BytesIO(b"foobarbaz")
    writer.append(flo)
    await writer.write(stream)
    assert (
        buf == b"--:\r\nContent-Type: application/octet-stream"
        b"\r\nContent-Length: 9\r\n\r\nfoobarbaz\r\n--:--\r\n"
    )


async def test_writer_serialize_json(buf: Any, stream: Any, writer: Any) -> None:
    writer.append_json({"привет": "мир"})
    await writer.write(stream)
    assert (
        b'{"\\u043f\\u0440\\u0438\\u0432\\u0435\\u0442":'
        b' "\\u043c\\u0438\\u0440"}' in buf
    )


async def test_writer_serialize_form(buf: Any, stream: Any, writer: Any) -> None:
    data = [("foo", "bar"), ("foo", "baz"), ("boo", "zoo")]
    writer.append_form(data)
    await writer.write(stream)

    assert b"foo=bar&foo=baz&boo=zoo" in buf


async def test_writer_serialize_form_dict(buf: Any, stream: Any, writer: Any) -> None:
    data = {"hello": "мир"}
    writer.append_form(data)
    await writer.write(stream)

    assert b"hello=%D0%BC%D0%B8%D1%80" in buf


async def test_writer_write(buf: Any, stream: Any, writer: Any) -> None:
    writer.append("foo-bar-baz")
    writer.append_json({"test": "passed"})
    writer.append_form({"test": "passed"})
    writer.append_form([("one", 1), ("two", 2)])

    sub_multipart = aiohttp.MultipartWriter(boundary="::")
    sub_multipart.append("nested content")
    sub_multipart.headers["X-CUSTOM"] = "test"
    writer.append(sub_multipart)
    await writer.write(stream)

    assert (
        b"--:\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Length: 11\r\n\r\n"
        b"foo-bar-baz"
        b"\r\n"
        b"--:\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 18\r\n\r\n"
        b'{"test": "passed"}'
        b"\r\n"
        b"--:\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 11\r\n\r\n"
        b"test=passed"
        b"\r\n"
        b"--:\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 11\r\n\r\n"
        b"one=1&two=2"
        b"\r\n"
        b"--:\r\n"
        b'Content-Type: multipart/mixed; boundary="::"\r\n'
        b"X-CUSTOM: test\r\nContent-Length: 93\r\n\r\n"
        b"--::\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Length: 14\r\n\r\n"
        b"nested content\r\n"
        b"--::--\r\n"
        b"\r\n"
        b"--:--\r\n"
    ) == bytes(buf)


async def test_writer_write_no_close_boundary(buf: Any, stream: Any) -> None:
    writer = aiohttp.MultipartWriter(boundary=":")
    writer.append("foo-bar-baz")
    writer.append_json({"test": "passed"})
    writer.append_form({"test": "passed"})
    writer.append_form([("one", 1), ("two", 2)])
    await writer.write(stream, close_boundary=False)

    assert (
        b"--:\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Length: 11\r\n\r\n"
        b"foo-bar-baz"
        b"\r\n"
        b"--:\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 18\r\n\r\n"
        b'{"test": "passed"}'
        b"\r\n"
        b"--:\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 11\r\n\r\n"
        b"test=passed"
        b"\r\n"
        b"--:\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 11\r\n\r\n"
        b"one=1&two=2"
        b"\r\n"
    ) == bytes(buf)


async def test_writer_write_no_parts(buf: Any, stream: Any, writer: Any) -> None:
    await writer.write(stream)
    assert b"--:--\r\n" == bytes(buf)


async def test_writer_serialize_with_content_encoding_gzip(
    buf: Any, stream: Any, writer: Any
) -> None:
    writer.append("Time to Relax!", {CONTENT_ENCODING: "gzip"})
    await writer.write(stream)
    headers, message = bytes(buf).split(b"\r\n\r\n", 1)

    assert (
        b"--:\r\nContent-Type: text/plain; charset=utf-8\r\n"
        b"Content-Encoding: gzip" == headers
    )

    decompressor = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
    data = decompressor.decompress(message.split(b"\r\n")[0])
    data += decompressor.flush()
    assert b"Time to Relax!" == data


async def test_writer_serialize_with_content_encoding_deflate(
    buf: Any, stream: Any, writer: Any
) -> None:
    writer.append("Time to Relax!", {CONTENT_ENCODING: "deflate"})
    await writer.write(stream)
    headers, message = bytes(buf).split(b"\r\n\r\n", 1)

    assert (
        b"--:\r\nContent-Type: text/plain; charset=utf-8\r\n"
        b"Content-Encoding: deflate" == headers
    )

    thing = b"\x0b\xc9\xccMU(\xc9W\x08J\xcdI\xacP\x04\x00\r\n--:--\r\n"
    assert thing == message


async def test_writer_serialize_with_content_encoding_identity(
    buf: Any, stream: Any, writer: Any
) -> None:
    thing = b"\x0b\xc9\xccMU(\xc9W\x08J\xcdI\xacP\x04\x00"
    writer.append(thing, {CONTENT_ENCODING: "identity"})
    await writer.write(stream)
    headers, message = bytes(buf).split(b"\r\n\r\n", 1)

    assert (
        b"--:\r\nContent-Type: application/octet-stream\r\n"
        b"Content-Encoding: identity\r\n"
        b"Content-Length: 16" == headers
    )

    assert thing == message.split(b"\r\n")[0]


def test_writer_serialize_with_content_encoding_unknown(
    buf: Any, stream: Any, writer: Any
) -> None:
    with pytest.raises(RuntimeError):
        writer.append("Time to Relax!", {CONTENT_ENCODING: "snappy"})


async def test_writer_with_content_transfer_encoding_base64(
    buf: Any, stream: Any, writer: Any
) -> None:
    writer.append("Time to Relax!", {CONTENT_TRANSFER_ENCODING: "base64"})
    await writer.write(stream)
    headers, message = bytes(buf).split(b"\r\n\r\n", 1)

    assert (
        b"--:\r\nContent-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: base64" == headers
    )

    assert b"VGltZSB0byBSZWxheCE=" == message.split(b"\r\n")[0]


async def test_writer_content_transfer_encoding_quote_printable(
    buf: Any, stream: Any, writer: Any
) -> None:
    writer.append("Привет, мир!", {CONTENT_TRANSFER_ENCODING: "quoted-printable"})
    await writer.write(stream)
    headers, message = bytes(buf).split(b"\r\n\r\n", 1)

    assert (
        b"--:\r\nContent-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: quoted-printable" == headers
    )

    assert (
        b"=D0=9F=D1=80=D0=B8=D0=B2=D0=B5=D1=82,"
        b" =D0=BC=D0=B8=D1=80!" == message.split(b"\r\n")[0]
    )


def test_writer_content_transfer_encoding_unknown(
    buf: Any, stream: Any, writer: Any
) -> None:
    with pytest.raises(RuntimeError):
        writer.append("Time to Relax!", {CONTENT_TRANSFER_ENCODING: "unknown"})


class TestMultipartWriter:
    def test_default_subtype(self, writer: Any) -> None:
        mimetype = parse_mimetype(writer.headers.get(CONTENT_TYPE))

        assert "multipart" == mimetype.type
        assert "mixed" == mimetype.subtype

    def test_unquoted_boundary(self) -> None:
        writer = aiohttp.MultipartWriter(boundary="abc123")
        expected = {CONTENT_TYPE: "multipart/mixed; boundary=abc123"}
        assert expected == writer.headers

    def test_quoted_boundary(self) -> None:
        writer = aiohttp.MultipartWriter(boundary=R"\"")
        expected = {CONTENT_TYPE: R'multipart/mixed; boundary="\\\""'}
        assert expected == writer.headers

    def test_bad_boundary(self) -> None:
        with pytest.raises(ValueError):
            aiohttp.MultipartWriter(boundary="тест")
        with pytest.raises(ValueError):
            aiohttp.MultipartWriter(boundary="test\n")
        with pytest.raises(ValueError):
            aiohttp.MultipartWriter(boundary="X" * 71)

    def test_default_headers(self, writer: Any) -> None:
        expected = {CONTENT_TYPE: 'multipart/mixed; boundary=":"'}
        assert expected == writer.headers

    def test_iter_parts(self, writer: Any) -> None:
        writer.append("foo")
        writer.append("bar")
        writer.append("baz")
        assert 3 == len(list(writer))

    def test_append(self, writer: Any) -> None:
        assert 0 == len(writer)
        writer.append("hello, world!")
        assert 1 == len(writer)
        assert isinstance(writer._parts[0][0], payload.Payload)

    def test_append_with_headers(self, writer: Any) -> None:
        writer.append("hello, world!", {"x-foo": "bar"})
        assert 1 == len(writer)
        assert "x-foo" in writer._parts[0][0].headers
        assert writer._parts[0][0].headers["x-foo"] == "bar"

    def test_append_json(self, writer: Any) -> None:
        writer.append_json({"foo": "bar"})
        assert 1 == len(writer)
        part = writer._parts[0][0]
        assert part.headers[CONTENT_TYPE] == "application/json"

    def test_append_part(self, writer: Any) -> None:
        part = payload.get_payload("test", headers={CONTENT_TYPE: "text/plain"})
        writer.append(part, {CONTENT_TYPE: "test/passed"})
        assert 1 == len(writer)
        part = writer._parts[0][0]
        assert part.headers[CONTENT_TYPE] == "test/passed"

    def test_append_json_overrides_content_type(self, writer: Any) -> None:
        writer.append_json({"foo": "bar"}, {CONTENT_TYPE: "test/passed"})
        assert 1 == len(writer)
        part = writer._parts[0][0]
        assert part.headers[CONTENT_TYPE] == "test/passed"

    def test_append_form(self, writer: Any) -> None:
        writer.append_form({"foo": "bar"}, {CONTENT_TYPE: "test/passed"})
        assert 1 == len(writer)
        part = writer._parts[0][0]
        assert part.headers[CONTENT_TYPE] == "test/passed"

    def test_append_multipart(self, writer: Any) -> None:
        subwriter = aiohttp.MultipartWriter(boundary=":")
        subwriter.append_json({"foo": "bar"})
        writer.append(subwriter, {CONTENT_TYPE: "test/passed"})
        assert 1 == len(writer)
        part = writer._parts[0][0]
        assert part.headers[CONTENT_TYPE] == "test/passed"

    def test_with(self) -> None:
        with aiohttp.MultipartWriter(boundary=":") as writer:
            writer.append("foo")
            writer.append(b"bar")
            writer.append_json({"baz": True})
        assert 3 == len(writer)

    def test_append_int_not_allowed(self) -> None:
        with pytest.raises(TypeError):
            with aiohttp.MultipartWriter(boundary=":") as writer:
                writer.append(1)

    def test_append_float_not_allowed(self) -> None:
        with pytest.raises(TypeError):
            with aiohttp.MultipartWriter(boundary=":") as writer:
                writer.append(1.1)

    def test_append_none_not_allowed(self) -> None:
        with pytest.raises(TypeError):
            with aiohttp.MultipartWriter(boundary=":") as writer:
                writer.append(None)

    async def test_write_preserves_content_disposition(
        self, buf: Any, stream: Any
    ) -> None:
        with aiohttp.MultipartWriter(boundary=":") as writer:
            part = writer.append(b"foo", headers={CONTENT_TYPE: "test/passed"})
            part.set_content_disposition("form-data", filename="bug")
        await writer.write(stream)

        headers, message = bytes(buf).split(b"\r\n\r\n", 1)

        assert headers == (
            b"--:\r\n"
            b"Content-Type: test/passed\r\n"
            b"Content-Length: 3\r\n"
            b"Content-Disposition:"
            b' form-data; filename="bug"'
        )
        assert message == b"foo\r\n--:--\r\n"

    async def test_preserve_content_disposition_header(
        self, buf: Any, stream: Any
    ) -> None:
        # https://github.com/aio-libs/aiohttp/pull/3475#issuecomment-451072381
        with pathlib.Path(__file__).open("rb") as fobj:
            with aiohttp.MultipartWriter("form-data", boundary=":") as writer:
                part = writer.append(
                    fobj,
                    headers={
                        CONTENT_DISPOSITION: 'attachments; filename="bug.py"',
                        CONTENT_TYPE: "text/python",
                    },
                )
            content_length = part.size
            await writer.write(stream)

        assert part.headers[CONTENT_TYPE] == "text/python"
        assert part.headers[CONTENT_DISPOSITION] == ('attachments; filename="bug.py"')

        headers, _ = bytes(buf).split(b"\r\n\r\n", 1)

        assert headers == (
            b"--:\r\n"
            b"Content-Type: text/python\r\n"
            b'Content-Disposition: attachments; filename="bug.py"\r\n'
            b"Content-Length: %s"
            b"" % (str(content_length).encode(),)
        )

    async def test_set_content_disposition_override(
        self, buf: Any, stream: Any
    ) -> None:
        # https://github.com/aio-libs/aiohttp/pull/3475#issuecomment-451072381
        with pathlib.Path(__file__).open("rb") as fobj:
            with aiohttp.MultipartWriter("form-data", boundary=":") as writer:
                part = writer.append(
                    fobj,
                    headers={
                        CONTENT_DISPOSITION: 'attachments; filename="bug.py"',
                        CONTENT_TYPE: "text/python",
                    },
                )
            content_length = part.size
            await writer.write(stream)

        assert part.headers[CONTENT_TYPE] == "text/python"
        assert part.headers[CONTENT_DISPOSITION] == ('attachments; filename="bug.py"')

        headers, _ = bytes(buf).split(b"\r\n\r\n", 1)

        assert headers == (
            b"--:\r\n"
            b"Content-Type: text/python\r\n"
            b'Content-Disposition: attachments; filename="bug.py"\r\n'
            b"Content-Length: %s"
            b"" % (str(content_length).encode(),)
        )

    async def test_reset_content_disposition_header(
        self, buf: Any, stream: Any
    ) -> None:
        # https://github.com/aio-libs/aiohttp/pull/3475#issuecomment-451072381
        with pathlib.Path(__file__).open("rb") as fobj:
            with aiohttp.MultipartWriter("form-data", boundary=":") as writer:
                part = writer.append(
                    fobj,
                    headers={CONTENT_TYPE: "text/plain"},
                )

            content_length = part.size

            assert CONTENT_DISPOSITION in part.headers

            part.set_content_disposition("attachments", filename="bug.py")

            await writer.write(stream)

        headers, _ = bytes(buf).split(b"\r\n\r\n", 1)

        assert headers == (
            b"--:\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Disposition:"
            b' attachments; filename="bug.py"\r\n'
            b"Content-Length: %s"
            b"" % (str(content_length).encode(),)
        )


async def test_async_for_reader() -> None:
    data = [{"test": "passed"}, 42, b"plain text", b"aiohttp\n", b"no epilogue"]
    reader = aiohttp.MultipartReader(
        headers={CONTENT_TYPE: 'multipart/mixed; boundary=":"'},
        content=Stream(
            b"\r\n".join(
                [
                    b"--:",
                    b"Content-Type: application/json",
                    b"",
                    json.dumps(data[0]).encode(),
                    b"--:",
                    b"Content-Type: application/json",
                    b"",
                    json.dumps(data[1]).encode(),
                    b"--:",
                    b'Content-Type: multipart/related; boundary="::"',
                    b"",
                    b"--::",
                    b"Content-Type: text/plain",
                    b"",
                    data[2],
                    b"--::",
                    b'Content-Disposition: attachment; filename="aiohttp"',
                    b"Content-Type: text/plain",
                    b"Content-Length: 28",
                    b"Content-Encoding: gzip",
                    b"",
                    b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03K\xcc\xcc\xcf())"
                    b"\xe0\x02\x00\xd6\x90\xe2O\x08\x00\x00\x00",
                    b"--::",
                    b'Content-Type: multipart/related; boundary=":::"',
                    b"",
                    b"--:::",
                    b"Content-Type: text/plain",
                    b"",
                    data[4],
                    b"--:::--",
                    b"--::--",
                    b"",
                    b"--:--",
                    b"",
                ]
            )
        ),
    )
    idata = iter(data)

    async def check(reader):
        async for part in reader:
            if isinstance(part, aiohttp.BodyPartReader):
                if part.headers[CONTENT_TYPE] == "application/json":
                    assert next(idata) == (await part.json())
                else:
                    assert next(idata) == await part.read(decode=True)
            else:
                await check(part)

    await check(reader)


async def test_async_for_bodypart() -> None:
    part = aiohttp.BodyPartReader(
        boundary=b"--:", headers={}, content=Stream(b"foobarbaz\r\n--:--")
    )
    async for data in part:
        assert data == b"foobarbaz"
