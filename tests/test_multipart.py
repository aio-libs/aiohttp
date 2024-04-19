import asyncio
import io
import json
import pathlib
import zlib
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

BOUNDARY = b"--:"


newline = b"\r\n"


@pytest.fixture
def buf():
    return bytearray()


@pytest.fixture
def stream(buf):
    writer = mock.Mock()

    async def write(chunk):
        buf.extend(chunk)

    writer.write.side_effect = write
    return writer


@pytest.fixture
def writer():
    return aiohttp.MultipartWriter(boundary=":")


class Response:
    def __init__(self, headers, content):
        self.headers = headers
        self.content = content


class Stream:
    def __init__(self, content):
        self.content = io.BytesIO(content)

    async def read(self, size=None):
        return self.content.read(size)

    def at_eof(self):
        return self.content.tell() == len(self.content.getbuffer())

    async def readline(self):
        return self.content.readline()

    def unread_data(self, data):
        self.content = io.BytesIO(data + self.content.read())

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.content.close()


class StreamWithShortenRead(Stream):
    def __init__(self, content):
        self._first = True
        super().__init__(content)

    async def read(self, size=None):
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
    async def test_next(self) -> None:
        data = b"Hello, world!%s--:" % newline
        with Stream(data) as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, {}, stream)
            result = await obj.next()
            assert b"Hello, world!" == result
            assert obj.at_eof()

    async def test_next_next(self) -> None:
        data = b"Hello, world!%s--:" % newline
        with Stream(data) as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, {}, stream)
            result = await obj.next()
            assert b"Hello, world!" == result
            assert obj.at_eof()
            result = await obj.next()
            assert result is None

    async def test_read(self) -> None:
        data = b"Hello, world!%s--:" % newline
        with Stream(data) as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, {}, stream)
            result = await obj.read()
            assert b"Hello, world!" == result
            assert obj.at_eof()

    async def test_read_chunk_at_eof(self) -> None:
        with Stream(b"--:") as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, {}, stream)
            obj._at_eof = True
            result = await obj.read_chunk()
        assert b"" == result

    async def test_read_chunk_without_content_length(self) -> None:
        data = b"Hello, world!%s--:" % newline
        with Stream(data) as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, {}, stream)
            c1 = await obj.read_chunk(8)
            c2 = await obj.read_chunk(8)
            c3 = await obj.read_chunk(8)
        assert c1 + c2 == b"Hello, world!"
        assert c3 == b""

    async def test_read_incomplete_chunk(self) -> None:
        with Stream(b"") as stream:

            def prepare(data):
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
                obj = aiohttp.BodyPartReader(BOUNDARY, {}, stream)
                c1 = await obj.read_chunk(8)
                assert c1 == b"Hello, "
                c2 = await obj.read_chunk(8)
                assert c2 == b"World"
                c3 = await obj.read_chunk(8)
                assert c3 == b"!"

    async def test_read_all_at_once(self) -> None:
        data = b"Hello, World!%s--:--%s" % (newline, newline)
        with Stream(data) as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, {}, stream)
            result = await obj.read_chunk()
            assert b"Hello, World!" == result
            result = await obj.read_chunk()
            assert b"" == result
            assert obj.at_eof()

    async def test_read_incomplete_body_chunked(self) -> None:
        data = b"Hello, World!%s--" % newline
        with Stream(data) as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, {}, stream)
            result = b""
            with pytest.raises(AssertionError):
                for _ in range(4):
                    result += await obj.read_chunk(7)
        assert data == result

    async def test_read_boundary_with_incomplete_chunk(self) -> None:
        with Stream(b"") as stream:

            def prepare(data):
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
                obj = aiohttp.BodyPartReader(BOUNDARY, {}, stream)
                c1 = await obj.read_chunk(12)
                assert c1 == b"Hello, World"
                c2 = await obj.read_chunk(8)
                assert c2 == b"!"
                c3 = await obj.read_chunk(8)
                assert c3 == b""

    async def test_multi_read_chunk(self) -> None:
        data = b"Hello,%s--:%s%sworld!%s--:--" % ((newline,) * 4)
        with Stream(data) as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, {}, stream)
            result = await obj.read_chunk(8)
            assert b"Hello," == result
            result = await obj.read_chunk(8)
            assert b"" == result
            assert obj.at_eof()

    async def test_read_chunk_properly_counts_read_bytes(self) -> None:
        expected = b"." * 10
        tail = b"%s--:--" % newline
        size = len(expected)
        with StreamWithShortenRead(expected + tail) as stream:
            obj = aiohttp.BodyPartReader(
                BOUNDARY,
                {"CONTENT-LENGTH": size},
                stream,
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

    async def test_read_does_not_read_boundary(self) -> None:
        data = b"Hello, world!%s--:" % newline
        with Stream(data) as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, {}, stream)
            result = await obj.read()
            assert b"Hello, world!" == result
            assert b"--:" == (await stream.read())

    async def test_multiread(self) -> None:
        data = b"Hello,%s--:%s%sworld!%s--:--" % ((newline,) * 4)
        with Stream(data) as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, {}, stream)
            result = await obj.read()
            assert b"Hello," == result
            result = await obj.read()
            assert b"" == result
            assert obj.at_eof()

    async def test_read_multiline(self) -> None:
        data = b"Hello\n,\r\nworld!%s--:--" % newline
        with Stream(data) as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, {}, stream)
            result = await obj.read()
            assert b"Hello\n,\r\nworld!" == result
            result = await obj.read()
            assert b"" == result
            assert obj.at_eof()

    async def test_read_respects_content_length(self) -> None:
        data = b"." * 100500
        tail = b"%s--:--" % newline
        with Stream(data + tail) as stream:
            obj = aiohttp.BodyPartReader(
                BOUNDARY,
                {"CONTENT-LENGTH": 100500},
                stream,
            )
            result = await obj.read()
            assert data == result
            assert obj.at_eof()

    async def test_read_with_content_encoding_gzip(self) -> None:
        with Stream(
            b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x0b\xc9\xccMU"
            b"(\xc9W\x08J\xcdI\xacP\x04\x00$\xfb\x9eV\x0e\x00\x00\x00"
            b"%s--:--" % newline
        ) as stream:
            obj = aiohttp.BodyPartReader(
                BOUNDARY,
                {CONTENT_ENCODING: "gzip"},
                stream,
            )
            result = await obj.read(decode=True)
        assert b"Time to Relax!" == result

    async def test_read_with_content_encoding_deflate(self) -> None:
        data = b"\x0b\xc9\xccMU(\xc9W\x08J\xcdI\xacP\x04\x00"
        tail = b"%s--:--" % newline
        with Stream(data + tail) as stream:
            obj = aiohttp.BodyPartReader(
                BOUNDARY,
                {CONTENT_ENCODING: "deflate"},
                stream,
            )
            result = await obj.read(decode=True)
        assert b"Time to Relax!" == result

    async def test_read_with_content_encoding_identity(self) -> None:
        thing = (
            b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x0b\xc9\xccMU"
            b"(\xc9W\x08J\xcdI\xacP\x04\x00$\xfb\x9eV\x0e\x00\x00\x00"
        )
        with Stream(thing + b"%s--:--" % newline) as stream:
            obj = aiohttp.BodyPartReader(
                BOUNDARY,
                {CONTENT_ENCODING: "identity"},
                stream,
            )
            result = await obj.read(decode=True)
        assert thing == result

    async def test_read_with_content_encoding_unknown(self) -> None:
        with Stream(b"\x0e4Time to Relax!%s--:--" % newline) as stream:
            obj = aiohttp.BodyPartReader(
                BOUNDARY,
                {CONTENT_ENCODING: "snappy"},
                stream,
            )
            with pytest.raises(RuntimeError):
                await obj.read(decode=True)

    async def test_read_with_content_transfer_encoding_base64(self) -> None:
        with Stream(b"VGltZSB0byBSZWxheCE=%s--:--" % newline) as stream:
            obj = aiohttp.BodyPartReader(
                BOUNDARY,
                {CONTENT_TRANSFER_ENCODING: "base64"},
                stream,
            )
            result = await obj.read(decode=True)
        assert b"Time to Relax!" == result

    async def test_read_with_content_transfer_encoding_quoted_printable(self) -> None:
        with Stream(
            b"=D0=9F=D1=80=D0=B8=D0=B2=D0=B5=D1=82,"
            b" =D0=BC=D0=B8=D1=80!%s--:--" % newline
        ) as stream:
            obj = aiohttp.BodyPartReader(
                BOUNDARY,
                {CONTENT_TRANSFER_ENCODING: "quoted-printable"},
                stream,
            )
            result = await obj.read(decode=True)
        expected = (
            b"\xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82,"
            b" \xd0\xbc\xd0\xb8\xd1\x80!"
        )
        assert result == expected

    @pytest.mark.parametrize("encoding", ("binary", "8bit", "7bit"))
    async def test_read_with_content_transfer_encoding_binary(
        self, encoding: str
    ) -> None:
        data = (
            b"\xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82,"
            b" \xd0\xbc\xd0\xb8\xd1\x80!"
        )
        with Stream(data + b"%s--:--" % newline) as stream:
            obj = aiohttp.BodyPartReader(
                BOUNDARY,
                {CONTENT_TRANSFER_ENCODING: encoding},
                stream,
            )
            result = await obj.read(decode=True)
        assert data == result

    async def test_read_with_content_transfer_encoding_unknown(self) -> None:
        with Stream(b"\x0e4Time to Relax!%s--:--" % newline) as stream:
            obj = aiohttp.BodyPartReader(
                BOUNDARY,
                {CONTENT_TRANSFER_ENCODING: "unknown"},
                stream,
            )
            with pytest.raises(RuntimeError):
                await obj.read(decode=True)

    async def test_read_text(self) -> None:
        with Stream(b"Hello, world!%s--:--" % newline) as stream:
            obj = aiohttp.BodyPartReader(
                BOUNDARY,
                {},
                stream,
            )
            result = await obj.text()
        assert "Hello, world!" == result

    async def test_read_text_default_encoding(self) -> None:
        data = "Привет, Мир!"
        tail = b"%s--:--" % newline
        with Stream(data.encode("utf-8") + tail) as stream:
            obj = aiohttp.BodyPartReader(
                BOUNDARY,
                {},
                stream,
            )
            result = await obj.text()
        assert data == result

    async def test_read_text_encoding(self) -> None:
        data = "Привет, Мир!"
        tail = b"%s--:--" % newline
        with Stream(data.encode("cp1251") + tail) as stream:
            obj = aiohttp.BodyPartReader(
                BOUNDARY,
                {},
                stream,
            )
            result = await obj.text(encoding="cp1251")
        assert data == result

    async def test_read_text_guess_encoding(self) -> None:
        data = "Привет, Мир!"
        tail = b"%s--:--" % newline
        with Stream(data.encode("cp1251") + tail) as stream:
            obj = aiohttp.BodyPartReader(
                BOUNDARY,
                {CONTENT_TYPE: "text/plain;charset=cp1251"},
                stream,
            )
            result = await obj.text()
        assert data == result

    async def test_read_text_compressed(self) -> None:
        data = b"\x0b\xc9\xccMU(\xc9W\x08J\xcdI\xacP\x04\x00" b"%s--:--" % newline
        with Stream(data) as stream:
            obj = aiohttp.BodyPartReader(
                BOUNDARY,
                {CONTENT_ENCODING: "deflate", CONTENT_TYPE: "text/plain"},
                stream,
            )
            result = await obj.text()
        assert "Time to Relax!" == result

    async def test_read_text_while_closed(self) -> None:
        with Stream(b"") as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, {CONTENT_TYPE: "text/plain"}, stream)
            obj._at_eof = True
            result = await obj.text()
        assert "" == result

    async def test_read_json(self) -> None:
        with Stream(b'{"test": "passed"}%s--:--' % newline) as stream:
            obj = aiohttp.BodyPartReader(
                BOUNDARY,
                {CONTENT_TYPE: "application/json"},
                stream,
            )
            result = await obj.json()
        assert {"test": "passed"} == result

    async def test_read_json_encoding(self) -> None:
        data = '{"тест": "пассед"}'.encode("cp1251")
        tail = b"%s--:--" % newline
        with Stream(data + tail) as stream:
            obj = aiohttp.BodyPartReader(
                BOUNDARY,
                {CONTENT_TYPE: "application/json"},
                stream,
            )
            result = await obj.json(encoding="cp1251")
        assert {"тест": "пассед"} == result

    async def test_read_json_guess_encoding(self) -> None:
        data = '{"тест": "пассед"}'.encode("cp1251")
        tail = b"%s--:--" % newline
        with Stream(data + tail) as stream:
            obj = aiohttp.BodyPartReader(
                BOUNDARY,
                {CONTENT_TYPE: "application/json; charset=cp1251"},
                stream,
            )
            result = await obj.json()
        assert {"тест": "пассед"} == result

    async def test_read_json_compressed(self) -> None:
        with Stream(
            b"\xabV*I-.Q\xb2RP*H,.NMQ\xaa\x05\x00" b"%s--:--" % newline
        ) as stream:
            obj = aiohttp.BodyPartReader(
                BOUNDARY,
                {CONTENT_ENCODING: "deflate", CONTENT_TYPE: "application/json"},
                stream,
            )
            result = await obj.json()
        assert {"test": "passed"} == result

    async def test_read_json_while_closed(self) -> None:
        with Stream(b"") as stream:
            obj = aiohttp.BodyPartReader(
                BOUNDARY, {CONTENT_TYPE: "application/json"}, stream
            )
            obj._at_eof = True
            result = await obj.json()
        assert result is None

    async def test_read_form(self) -> None:
        data = b"foo=bar&foo=baz&boo=%s--:--" % newline
        with Stream(data) as stream:
            obj = aiohttp.BodyPartReader(
                BOUNDARY,
                {CONTENT_TYPE: "application/x-www-form-urlencoded"},
                stream,
            )
            result = await obj.form()
        assert [("foo", "bar"), ("foo", "baz"), ("boo", "")] == result

    async def test_read_form_invalid_utf8(self) -> None:
        invalid_unicode_byte = b"\xff"
        data = invalid_unicode_byte + b"%s--:--" % newline
        with Stream(data) as stream:
            obj = aiohttp.BodyPartReader(
                BOUNDARY,
                {CONTENT_TYPE: "application/x-www-form-urlencoded"},
                stream,
            )
            with pytest.raises(
                ValueError, match="data cannot be decoded with utf-8 encoding"
            ):
                await obj.form()

    async def test_read_form_encoding(self) -> None:
        data = b"foo=bar&foo=baz&boo=%s--:--" % newline
        with Stream(data) as stream:
            obj = aiohttp.BodyPartReader(
                BOUNDARY,
                {CONTENT_TYPE: "application/x-www-form-urlencoded"},
                stream,
            )
            result = await obj.form(encoding="cp1251")
        assert [("foo", "bar"), ("foo", "baz"), ("boo", "")] == result

    async def test_read_form_guess_encoding(self) -> None:
        data = b"foo=bar&foo=baz&boo=%s--:--" % newline
        with Stream(data) as stream:
            obj = aiohttp.BodyPartReader(
                BOUNDARY,
                {CONTENT_TYPE: "application/x-www-form-urlencoded; charset=utf-8"},
                stream,
            )
            result = await obj.form()
        assert [("foo", "bar"), ("foo", "baz"), ("boo", "")] == result

    async def test_read_form_while_closed(self) -> None:
        with Stream(b"") as stream:
            obj = aiohttp.BodyPartReader(
                BOUNDARY,
                {CONTENT_TYPE: "application/x-www-form-urlencoded"},
                stream,
            )
            obj._at_eof = True
            result = await obj.form()
        assert not result

    async def test_readline(self) -> None:
        data = b"Hello\n,\r\nworld!%s--:--" % newline
        with Stream(data) as stream:
            obj = aiohttp.BodyPartReader(
                BOUNDARY,
                {},
                stream,
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

    async def test_release(self) -> None:
        data = b"Hello,%s--:\r\n\r\nworld!%s--:--" % (newline, newline)
        with Stream(data) as stream:
            obj = aiohttp.BodyPartReader(
                BOUNDARY,
                {},
                stream,
            )
            remained = b"--:\r\n\r\nworld!%s--:--" % newline
            await obj.release()
            assert obj.at_eof()
            assert remained == stream.content.read()

    async def test_release_respects_content_length(self) -> None:
        with Stream(b"." * 100500 + b"%s--:--" % newline) as stream:
            obj = aiohttp.BodyPartReader(
                BOUNDARY,
                {"CONTENT-LENGTH": 100500},
                stream,
            )
            result = await obj.release()
            assert result is None
            assert obj.at_eof()

    async def test_release_release(self) -> None:
        data = b"Hello,%s--:\r\n\r\nworld!%s--:--" % (newline, newline)
        remained = b"--:\r\n\r\nworld!%s--:--" % newline
        with Stream(data) as stream:
            obj = aiohttp.BodyPartReader(
                BOUNDARY,
                {},
                stream,
            )
            await obj.release()
            await obj.release()
            assert remained == stream.content.read()

    async def test_filename(self) -> None:
        part = aiohttp.BodyPartReader(
            BOUNDARY, {CONTENT_DISPOSITION: "attachment; filename=foo.html"}, None
        )
        assert "foo.html" == part.filename

    async def test_reading_long_part(self) -> None:
        size = 2 * 2**16
        protocol = mock.Mock(_reading_paused=False)
        stream = StreamReader(protocol, 2**16, loop=asyncio.get_event_loop())
        stream.feed_data(b"0" * size + b"\r\n--:--")
        stream.feed_eof()
        obj = aiohttp.BodyPartReader(BOUNDARY, {}, stream)
        data = await obj.read()
        assert len(data) == size


class TestMultipartReader:
    def test_from_response(self) -> None:
        with Stream(b"--:%s\r\nhello%s--:--" % (newline, newline)) as stream:
            resp = Response(
                {CONTENT_TYPE: 'multipart/related;boundary=":"'},
                stream,
            )
            res = aiohttp.MultipartReader.from_response(resp)
        assert isinstance(res, MultipartResponseWrapper)
        assert isinstance(res.stream, aiohttp.MultipartReader)

    def test_bad_boundary(self) -> None:
        with Stream(b"") as stream:
            resp = Response(
                {CONTENT_TYPE: "multipart/related;boundary=" + "a" * 80}, stream
            )
            with pytest.raises(ValueError):
                aiohttp.MultipartReader.from_response(resp)

    def test_dispatch(self) -> None:
        with Stream(b"--:%s\r\necho%s--:--" % (newline, newline)) as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/related;boundary=":"'},
                stream,
            )
            res = reader._get_part_reader({CONTENT_TYPE: "text/plain"})
        assert isinstance(res, reader.part_reader_cls)

    def test_dispatch_bodypart(self) -> None:
        with Stream(b"--:%s\r\necho%s--:--" % (newline, newline)) as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/related;boundary=":"'},
                stream,
            )
            res = reader._get_part_reader({CONTENT_TYPE: "text/plain"})
        assert isinstance(res, reader.part_reader_cls)

    def test_dispatch_multipart(self) -> None:
        with Stream(
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
        ) as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/related;boundary=":"'},
                stream,
            )
            res = reader._get_part_reader(
                {CONTENT_TYPE: "multipart/related;boundary=--:--"}
            )
        assert isinstance(res, reader.__class__)

    def test_dispatch_custom_multipart_reader(self) -> None:
        class CustomReader(aiohttp.MultipartReader):
            pass

        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(
                b"----:--\r\n"
                b"\r\n"
                b"test\r\n"
                b"----:--\r\n"
                b"\r\n"
                b"passed\r\n"
                b"----:----\r\n"
                b"--:--"
            ),
        )
        reader.multipart_reader_cls = CustomReader
        res = reader._get_part_reader(
            {CONTENT_TYPE: "multipart/related;boundary=--:--"}
        )
        assert isinstance(res, CustomReader)

    async def test_emit_next(self) -> None:
        with Stream(b"--:%s\r\necho%s--:--" % (newline, newline)) as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/related;boundary=":"'},
                stream,
            )
            res = await reader.next()
        assert isinstance(res, reader.part_reader_cls)

    async def test_invalid_boundary(self) -> None:
        with Stream(b"---:%s\r\necho%s---:--" % (newline, newline)) as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/related;boundary=":"'},
                stream,
            )
            with pytest.raises(ValueError):
                await reader.next()

    async def test_release(self) -> None:
        with Stream(
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
        ) as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/mixed;boundary=":"'},
                stream,
            )
            await reader.release()
            assert reader.at_eof()

    async def test_release_release(self) -> None:
        with Stream(b"--:%s\r\necho%s--:--" % (newline, newline)) as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/related;boundary=":"'},
                stream,
            )
            await reader.release()
            assert reader.at_eof()
            await reader.release()
            assert reader.at_eof()

    async def test_release_next(self) -> None:
        with Stream(b"--:%s\r\necho%s--:--" % (newline, newline)) as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/related;boundary=":"'},
                stream,
            )
            await reader.release()
            assert reader.at_eof()
            res = await reader.next()
            assert res is None

    async def test_second_next_releases_previous_object(self) -> None:
        with Stream(
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
        ) as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/related;boundary=":"'},
                stream,
            )
            first = await reader.next()
            assert isinstance(first, aiohttp.BodyPartReader)
            second = await reader.next()
            assert first.at_eof()
            assert not second.at_eof()

    async def test_release_without_read_the_last_object(self) -> None:
        with Stream(
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
        ) as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/related;boundary=":"'},
                stream,
            )
            first = await reader.next()
            second = await reader.next()
            third = await reader.next()

            assert first.at_eof()
            assert second.at_eof()
            assert second.at_eof()
            assert third is None

    async def test_read_chunk_by_length_doesnt_breaks_reader(self) -> None:
        with Stream(
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
        ) as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/related;boundary=":"'},
                stream,
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

    async def test_read_chunk_from_stream_doesnt_breaks_reader(self) -> None:
        with Stream(
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
        ) as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/related;boundary=":"'},
                stream,
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

    async def test_reading_skips_prelude(self) -> None:
        with Stream(
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
        ) as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/related;boundary=":"'},
                stream,
            )
            first = await reader.next()
            assert isinstance(first, aiohttp.BodyPartReader)
            second = await reader.next()

            assert first.at_eof()
            assert not second.at_eof()

    async def test_read_form_default_encoding(self) -> None:
        with Stream(
            b"--:\r\n"
            b'Content-Disposition: form-data; name="_charset_"\r\n\r\n'
            b"ascii"
            b"\r\n"
            b"--:\r\n"
            b'Content-Disposition: form-data; name="field1"\r\n\r\n'
            b"foo"
            b"\r\n"
            b"--:\r\n"
            b"Content-Type: text/plain;charset=UTF-8\r\n"
            b'Content-Disposition: form-data; name="field2"\r\n\r\n'
            b"foo"
            b"\r\n"
            b"--:\r\n"
            b'Content-Disposition: form-data; name="field3"\r\n\r\n'
            b"foo"
            b"\r\n"
        ) as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/form-data;boundary=":"'},
                stream,
            )
            field1 = await reader.next()
            assert field1.name == "field1"
            assert field1.get_charset("default") == "ascii"
            field2 = await reader.next()
            assert field2.name == "field2"
            assert field2.get_charset("default") == "UTF-8"
            field3 = await reader.next()
            assert field3.name == "field3"
            assert field3.get_charset("default") == "ascii"

    async def test_read_form_invalid_default_encoding(self) -> None:
        with Stream(
            b"--:\r\n"
            b'Content-Disposition: form-data; name="_charset_"\r\n\r\n'
            b"this-value-is-too-long-to-be-a-charset"
            b"\r\n"
            b"--:\r\n"
            b'Content-Disposition: form-data; name="field1"\r\n\r\n'
            b"foo"
            b"\r\n"
        ) as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/form-data;boundary=":"'},
                stream,
            )
            with pytest.raises(RuntimeError, match="Invalid default charset"):
                await reader.next()


async def test_writer(writer) -> None:
    assert writer.size == 7
    assert writer.boundary == ":"


async def test_writer_serialize_io_chunk(buf, stream, writer) -> None:
    with io.BytesIO(b"foobarbaz") as file_handle:
        writer.append(file_handle)
        await writer.write(stream)
    assert (
        buf == b"--:\r\nContent-Type: application/octet-stream"
        b"\r\nContent-Length: 9\r\n\r\nfoobarbaz\r\n--:--\r\n"
    )


async def test_writer_serialize_json(buf, stream, writer) -> None:
    writer.append_json({"привет": "мир"})
    await writer.write(stream)
    assert (
        b'{"\\u043f\\u0440\\u0438\\u0432\\u0435\\u0442":'
        b' "\\u043c\\u0438\\u0440"}' in buf
    )


async def test_writer_serialize_form(buf, stream, writer) -> None:
    data = [("foo", "bar"), ("foo", "baz"), ("boo", "zoo")]
    writer.append_form(data)
    await writer.write(stream)

    assert b"foo=bar&foo=baz&boo=zoo" in buf


async def test_writer_serialize_form_dict(buf, stream, writer) -> None:
    data = {"hello": "мир"}
    writer.append_form(data)
    await writer.write(stream)

    assert b"hello=%D0%BC%D0%B8%D1%80" in buf


async def test_writer_write(buf, stream, writer) -> None:
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


async def test_writer_write_no_close_boundary(buf, stream) -> None:
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


async def test_writer_write_no_parts(buf, stream, writer) -> None:
    await writer.write(stream)
    assert b"--:--\r\n" == bytes(buf)


async def test_writer_serialize_with_content_encoding_gzip(buf, stream, writer):
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


async def test_writer_serialize_with_content_encoding_deflate(buf, stream, writer):
    writer.append("Time to Relax!", {CONTENT_ENCODING: "deflate"})
    await writer.write(stream)
    headers, message = bytes(buf).split(b"\r\n\r\n", 1)

    assert (
        b"--:\r\nContent-Type: text/plain; charset=utf-8\r\n"
        b"Content-Encoding: deflate" == headers
    )

    thing = b"\x0b\xc9\xccMU(\xc9W\x08J\xcdI\xacP\x04\x00\r\n--:--\r\n"
    assert thing == message


async def test_writer_serialize_with_content_encoding_identity(buf, stream, writer):
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


def test_writer_serialize_with_content_encoding_unknown(buf, stream, writer):
    with pytest.raises(RuntimeError):
        writer.append("Time to Relax!", {CONTENT_ENCODING: "snappy"})


async def test_writer_with_content_transfer_encoding_base64(buf, stream, writer):
    writer.append("Time to Relax!", {CONTENT_TRANSFER_ENCODING: "base64"})
    await writer.write(stream)
    headers, message = bytes(buf).split(b"\r\n\r\n", 1)

    assert (
        b"--:\r\nContent-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: base64" == headers
    )

    assert b"VGltZSB0byBSZWxheCE=" == message.split(b"\r\n")[0]


async def test_writer_content_transfer_encoding_quote_printable(buf, stream, writer):
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


def test_writer_content_transfer_encoding_unknown(buf, stream, writer) -> None:
    with pytest.raises(RuntimeError):
        writer.append("Time to Relax!", {CONTENT_TRANSFER_ENCODING: "unknown"})


class TestMultipartWriter:
    def test_default_subtype(self, writer) -> None:
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

    def test_default_headers(self, writer) -> None:
        expected = {CONTENT_TYPE: 'multipart/mixed; boundary=":"'}
        assert expected == writer.headers

    def test_iter_parts(self, writer) -> None:
        writer.append("foo")
        writer.append("bar")
        writer.append("baz")
        assert 3 == len(list(writer))

    def test_append(self, writer) -> None:
        assert 0 == len(writer)
        writer.append("hello, world!")
        assert 1 == len(writer)
        assert isinstance(writer._parts[0][0], payload.Payload)

    def test_append_with_headers(self, writer) -> None:
        writer.append("hello, world!", {"x-foo": "bar"})
        assert 1 == len(writer)
        assert "x-foo" in writer._parts[0][0].headers
        assert writer._parts[0][0].headers["x-foo"] == "bar"

    def test_append_json(self, writer) -> None:
        writer.append_json({"foo": "bar"})
        assert 1 == len(writer)
        part = writer._parts[0][0]
        assert part.headers[CONTENT_TYPE] == "application/json"

    def test_append_part(self, writer) -> None:
        part = payload.get_payload("test", headers={CONTENT_TYPE: "text/plain"})
        writer.append(part, {CONTENT_TYPE: "test/passed"})
        assert 1 == len(writer)
        part = writer._parts[0][0]
        assert part.headers[CONTENT_TYPE] == "test/passed"

    def test_append_json_overrides_content_type(self, writer) -> None:
        writer.append_json({"foo": "bar"}, {CONTENT_TYPE: "test/passed"})
        assert 1 == len(writer)
        part = writer._parts[0][0]
        assert part.headers[CONTENT_TYPE] == "test/passed"

    def test_append_form(self, writer) -> None:
        writer.append_form({"foo": "bar"}, {CONTENT_TYPE: "test/passed"})
        assert 1 == len(writer)
        part = writer._parts[0][0]
        assert part.headers[CONTENT_TYPE] == "test/passed"

    def test_append_multipart(self, writer) -> None:
        subwriter = aiohttp.MultipartWriter(boundary=":")
        subwriter.append_json({"foo": "bar"})
        writer.append(subwriter, {CONTENT_TYPE: "test/passed"})
        assert 1 == len(writer)
        part = writer._parts[0][0]
        assert part.headers[CONTENT_TYPE] == "test/passed"

    def test_set_content_disposition_after_append(self):
        writer = aiohttp.MultipartWriter("form-data")
        part = writer.append("some-data")
        part.set_content_disposition("form-data", name="method")
        assert 'name="method"' in part.headers[CONTENT_DISPOSITION]

    def test_automatic_content_disposition(self):
        writer = aiohttp.MultipartWriter("form-data")
        writer.append_json(())
        part = payload.StringPayload("foo")
        part.set_content_disposition("form-data", name="second")
        writer.append_payload(part)
        writer.append("foo")

        disps = tuple(p[0].headers[CONTENT_DISPOSITION] for p in writer._parts)
        assert 'name="section-0"' in disps[0]
        assert 'name="second"' in disps[1]
        assert 'name="section-2"' in disps[2]

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

    async def test_write_preserves_content_disposition(self, buf, stream) -> None:
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

    async def test_preserve_content_disposition_header(self, buf, stream):
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
            await writer.write(stream)

        assert part.headers[CONTENT_TYPE] == "text/python"
        assert part.headers[CONTENT_DISPOSITION] == ('attachments; filename="bug.py"')

        headers, _ = bytes(buf).split(b"\r\n\r\n", 1)

        assert headers == (
            b"--:\r\n"
            b"Content-Type: text/python\r\n"
            b'Content-Disposition: attachments; filename="bug.py"'
        )

    async def test_set_content_disposition_override(self, buf, stream):
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
            await writer.write(stream)

        assert part.headers[CONTENT_TYPE] == "text/python"
        assert part.headers[CONTENT_DISPOSITION] == ('attachments; filename="bug.py"')

        headers, _ = bytes(buf).split(b"\r\n\r\n", 1)

        assert headers == (
            b"--:\r\n"
            b"Content-Type: text/python\r\n"
            b'Content-Disposition: attachments; filename="bug.py"'
        )

    async def test_reset_content_disposition_header(self, buf, stream):
        # https://github.com/aio-libs/aiohttp/pull/3475#issuecomment-451072381
        with pathlib.Path(__file__).open("rb") as fobj:
            with aiohttp.MultipartWriter("form-data", boundary=":") as writer:
                part = writer.append(
                    fobj,
                    headers={CONTENT_TYPE: "text/plain"},
                )

            assert CONTENT_DISPOSITION in part.headers

            part.set_content_disposition("attachments", filename="bug.py")

            await writer.write(stream)

        headers, _ = bytes(buf).split(b"\r\n\r\n", 1)

        assert headers == (
            b"--:\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Disposition:"
            b' attachments; filename="bug.py"'
        )


async def test_async_for_reader() -> None:
    data = [{"test": "passed"}, 42, b"plain text", b"aiohttp\n", b"no epilogue"]
    with Stream(
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
    ) as stream:
        reader = aiohttp.MultipartReader(
            headers={CONTENT_TYPE: 'multipart/mixed; boundary=":"'},
            content=stream,
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
    with Stream(b"foobarbaz\r\n--:--") as stream:
        part = aiohttp.BodyPartReader(boundary=b"--:", headers={}, content=stream)
        async for data in part:
            assert data == b"foobarbaz"
