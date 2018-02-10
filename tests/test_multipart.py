import io
import json
import zlib
from unittest import mock

import pytest

import aiohttp
from aiohttp import payload
from aiohttp.hdrs import (CONTENT_DISPOSITION, CONTENT_ENCODING,
                          CONTENT_TRANSFER_ENCODING, CONTENT_TYPE)
from aiohttp.helpers import parse_mimetype
from aiohttp.multipart import MultipartResponseWrapper
from aiohttp.streams import DEFAULT_LIMIT as stream_reader_default_limit
from aiohttp.streams import StreamReader
from aiohttp.test_utils import make_mocked_coro


BOUNDARY = b'--:'


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
    return aiohttp.MultipartWriter(boundary=':')


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

    def test_at_eof(self):
        wrapper = MultipartResponseWrapper(mock.Mock(),
                                           mock.Mock())
        wrapper.at_eof()
        assert wrapper.resp.content.at_eof.called

    async def test_next(self):
        wrapper = MultipartResponseWrapper(mock.Mock(),
                                           mock.Mock())
        wrapper.stream.next = make_mocked_coro(b'')
        wrapper.stream.at_eof.return_value = False
        await wrapper.next()
        assert wrapper.stream.next.called

    async def test_release(self):
        wrapper = MultipartResponseWrapper(mock.Mock(),
                                           mock.Mock())
        wrapper.resp.release = make_mocked_coro(None)
        await wrapper.release()
        assert wrapper.resp.release.called

    async def test_release_when_stream_at_eof(self):
        wrapper = MultipartResponseWrapper(mock.Mock(),
                                           mock.Mock())
        wrapper.resp.release = make_mocked_coro(None)
        wrapper.stream.next = make_mocked_coro(b'')
        wrapper.stream.at_eof.return_value = True
        await wrapper.next()
        assert wrapper.stream.next.called
        assert wrapper.resp.release.called


class TestPartReader:

    async def test_next(self):
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {}, Stream(b'Hello, world!\r\n--:'))
        result = await obj.next()
        assert b'Hello, world!' == result
        assert obj.at_eof()

    async def test_next_next(self):
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {}, Stream(b'Hello, world!\r\n--:'))
        result = await obj.next()
        assert b'Hello, world!' == result
        assert obj.at_eof()
        result = await obj.next()
        assert result is None

    async def test_read(self):
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {}, Stream(b'Hello, world!\r\n--:'))
        result = await obj.read()
        assert b'Hello, world!' == result
        assert obj.at_eof()

    async def test_read_chunk_at_eof(self):
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {}, Stream(b'--:'))
        obj._at_eof = True
        result = await obj.read_chunk()
        assert b'' == result

    async def test_read_chunk_without_content_length(self):
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {}, Stream(b'Hello, world!\r\n--:'))
        c1 = await obj.read_chunk(8)
        c2 = await obj.read_chunk(8)
        c3 = await obj.read_chunk(8)
        assert c1 + c2 == b'Hello, world!'
        assert c3 == b''

    async def test_read_incomplete_chunk(self, loop):
        stream = Stream(b'')

        def prepare(data):
            f = loop.create_future()
            f.set_result(data)
            return f

        with mock.patch.object(stream, 'read', side_effect=[
            prepare(b'Hello, '),
            prepare(b'World'),
            prepare(b'!\r\n--:'),
            prepare(b'')
        ]):
            obj = aiohttp.BodyPartReader(
                BOUNDARY, {}, stream)
            c1 = await obj.read_chunk(8)
            assert c1 == b'Hello, '
            c2 = await obj.read_chunk(8)
            assert c2 == b'World'
            c3 = await obj.read_chunk(8)
            assert c3 == b'!'

    async def test_read_all_at_once(self):
        stream = Stream(b'Hello, World!\r\n--:--\r\n')
        obj = aiohttp.BodyPartReader(BOUNDARY, {}, stream)
        result = await obj.read_chunk()
        assert b'Hello, World!' == result
        result = await obj.read_chunk()
        assert b'' == result
        assert obj.at_eof()

    async def test_read_incomplete_body_chunked(self):
        stream = Stream(b'Hello, World!\r\n-')
        obj = aiohttp.BodyPartReader(BOUNDARY, {}, stream)
        result = b''
        with pytest.raises(AssertionError):
            for _ in range(4):
                result += await obj.read_chunk(7)
        assert b'Hello, World!\r\n-' == result

    async def test_read_boundary_with_incomplete_chunk(self, loop):
        stream = Stream(b'')

        def prepare(data):
            f = loop.create_future()
            f.set_result(data)
            return f

        with mock.patch.object(stream, 'read', side_effect=[
            prepare(b'Hello, World'),
            prepare(b'!\r\n'),
            prepare(b'--:'),
            prepare(b'')
        ]):
            obj = aiohttp.BodyPartReader(
                BOUNDARY, {}, stream)
            c1 = await obj.read_chunk(12)
            assert c1 == b'Hello, World'
            c2 = await obj.read_chunk(8)
            assert c2 == b'!'
            c3 = await obj.read_chunk(8)
            assert c3 == b''

    async def test_multi_read_chunk(self):
        stream = Stream(b'Hello,\r\n--:\r\n\r\nworld!\r\n--:--')
        obj = aiohttp.BodyPartReader(BOUNDARY, {}, stream)
        result = await obj.read_chunk(8)
        assert b'Hello,' == result
        result = await obj.read_chunk(8)
        assert b'' == result
        assert obj.at_eof()

    async def test_read_chunk_properly_counts_read_bytes(self):
        expected = b'.' * 10
        size = len(expected)
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {'CONTENT-LENGTH': size},
            StreamWithShortenRead(expected + b'\r\n--:--'))
        result = bytearray()
        while True:
            chunk = await obj.read_chunk()
            if not chunk:
                break
            result.extend(chunk)
        assert size == len(result)
        assert b'.' * size == result
        assert obj.at_eof()

    async def test_read_does_not_read_boundary(self):
        stream = Stream(b'Hello, world!\r\n--:')
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {}, stream)
        result = await obj.read()
        assert b'Hello, world!' == result
        assert b'--:' == (await stream.read())

    async def test_multiread(self):
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {}, Stream(b'Hello,\r\n--:\r\n\r\nworld!\r\n--:--'))
        result = await obj.read()
        assert b'Hello,' == result
        result = await obj.read()
        assert b'' == result
        assert obj.at_eof()

    async def test_read_multiline(self):
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {}, Stream(b'Hello\n,\r\nworld!\r\n--:--'))
        result = await obj.read()
        assert b'Hello\n,\r\nworld!' == result
        result = await obj.read()
        assert b'' == result
        assert obj.at_eof()

    async def test_read_respects_content_length(self):
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {'CONTENT-LENGTH': 100500},
            Stream(b'.' * 100500 + b'\r\n--:--'))
        result = await obj.read()
        assert b'.' * 100500 == result
        assert obj.at_eof()

    async def test_read_with_content_encoding_gzip(self):
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {CONTENT_ENCODING: 'gzip'},
            Stream(b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x0b\xc9\xccMU'
                   b'(\xc9W\x08J\xcdI\xacP\x04\x00$\xfb\x9eV\x0e\x00\x00\x00'
                   b'\r\n--:--'))
        result = await obj.read(decode=True)
        assert b'Time to Relax!' == result

    async def test_read_with_content_encoding_deflate(self):
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {CONTENT_ENCODING: 'deflate'},
            Stream(b'\x0b\xc9\xccMU(\xc9W\x08J\xcdI\xacP\x04\x00\r\n--:--'))
        result = await obj.read(decode=True)
        assert b'Time to Relax!' == result

    async def test_read_with_content_encoding_identity(self):
        thing = (b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x0b\xc9\xccMU'
                 b'(\xc9W\x08J\xcdI\xacP\x04\x00$\xfb\x9eV\x0e\x00\x00\x00'
                 b'\r\n')
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {CONTENT_ENCODING: 'identity'},
            Stream(thing + b'--:--'))
        result = await obj.read(decode=True)
        assert thing[:-2] == result

    async def test_read_with_content_encoding_unknown(self):
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {CONTENT_ENCODING: 'snappy'},
            Stream(b'\x0e4Time to Relax!\r\n--:--'))
        with pytest.raises(RuntimeError):
            await obj.read(decode=True)

    async def test_read_with_content_transfer_encoding_base64(self):
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {CONTENT_TRANSFER_ENCODING: 'base64'},
            Stream(b'VGltZSB0byBSZWxheCE=\r\n--:--'))
        result = await obj.read(decode=True)
        assert b'Time to Relax!' == result

    async def test_read_with_content_transfer_encoding_quoted_printable(self):
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {CONTENT_TRANSFER_ENCODING: 'quoted-printable'},
            Stream(b'=D0=9F=D1=80=D0=B8=D0=B2=D0=B5=D1=82,'
                   b' =D0=BC=D0=B8=D1=80!\r\n--:--'))
        result = await obj.read(decode=True)
        expected = (b'\xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82,'
                    b' \xd0\xbc\xd0\xb8\xd1\x80!')
        assert result == expected

    @pytest.mark.parametrize('encoding', ('binary', '8bit', '7bit'))
    async def test_read_with_content_transfer_encoding_binary(self, encoding):
        data = b'\xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82,' \
               b' \xd0\xbc\xd0\xb8\xd1\x80!'
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {CONTENT_TRANSFER_ENCODING: encoding},
            Stream(data + b'\r\n--:--'))
        result = await obj.read(decode=True)
        assert data == result

    async def test_read_with_content_transfer_encoding_unknown(self):
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {CONTENT_TRANSFER_ENCODING: 'unknown'},
            Stream(b'\x0e4Time to Relax!\r\n--:--'))
        with pytest.raises(RuntimeError):
            await obj.read(decode=True)

    async def test_read_text(self):
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {}, Stream(b'Hello, world!\r\n--:--'))
        result = await obj.text()
        assert 'Hello, world!' == result

    async def test_read_text_default_encoding(self):
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {},
            Stream('Привет, Мир!\r\n--:--'.encode('utf-8')))
        result = await obj.text()
        assert 'Привет, Мир!' == result

    async def test_read_text_encoding(self):
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {},
            Stream('Привет, Мир!\r\n--:--'.encode('cp1251')))
        result = await obj.text(encoding='cp1251')
        assert 'Привет, Мир!' == result

    async def test_read_text_guess_encoding(self):
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {CONTENT_TYPE: 'text/plain;charset=cp1251'},
            Stream('Привет, Мир!\r\n--:--'.encode('cp1251')))
        result = await obj.text()
        assert 'Привет, Мир!' == result

    async def test_read_text_compressed(self):
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {CONTENT_ENCODING: 'deflate',
                       CONTENT_TYPE: 'text/plain'},
            Stream(b'\x0b\xc9\xccMU(\xc9W\x08J\xcdI\xacP\x04\x00\r\n--:--'))
        result = await obj.text()
        assert 'Time to Relax!' == result

    async def test_read_text_while_closed(self):
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {CONTENT_TYPE: 'text/plain'}, Stream(b''))
        obj._at_eof = True
        result = await obj.text()
        assert '' == result

    async def test_read_json(self):
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {CONTENT_TYPE: 'application/json'},
            Stream(b'{"test": "passed"}\r\n--:--'))
        result = await obj.json()
        assert {'test': 'passed'} == result

    async def test_read_json_encoding(self):
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {CONTENT_TYPE: 'application/json'},
            Stream('{"тест": "пассед"}\r\n--:--'.encode('cp1251')))
        result = await obj.json(encoding='cp1251')
        assert {'тест': 'пассед'} == result

    async def test_read_json_guess_encoding(self):
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {CONTENT_TYPE: 'application/json; charset=cp1251'},
            Stream('{"тест": "пассед"}\r\n--:--'.encode('cp1251')))
        result = await obj.json()
        assert {'тест': 'пассед'} == result

    async def test_read_json_compressed(self):
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {CONTENT_ENCODING: 'deflate',
                       CONTENT_TYPE: 'application/json'},
            Stream(b'\xabV*I-.Q\xb2RP*H,.NMQ\xaa\x05\x00\r\n--:--'))
        result = await obj.json()
        assert {'test': 'passed'} == result

    async def test_read_json_while_closed(self):
        stream = Stream(b'')
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {CONTENT_TYPE: 'application/json'}, stream)
        obj._at_eof = True
        result = await obj.json()
        assert result is None

    async def test_read_form(self):
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {CONTENT_TYPE: 'application/x-www-form-urlencoded'},
            Stream(b'foo=bar&foo=baz&boo=\r\n--:--'))
        result = await obj.form()
        assert [('foo', 'bar'), ('foo', 'baz'), ('boo', '')] == result

    async def test_read_form_encoding(self):
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {CONTENT_TYPE: 'application/x-www-form-urlencoded'},
            Stream('foo=bar&foo=baz&boo=\r\n--:--'.encode('cp1251')))
        result = await obj.form(encoding='cp1251')
        assert [('foo', 'bar'), ('foo', 'baz'), ('boo', '')] == result

    async def test_read_form_guess_encoding(self):
        obj = aiohttp.BodyPartReader(
            BOUNDARY,
            {CONTENT_TYPE: 'application/x-www-form-urlencoded; charset=utf-8'},
            Stream('foo=bar&foo=baz&boo=\r\n--:--'.encode('utf-8')))
        result = await obj.form()
        assert [('foo', 'bar'), ('foo', 'baz'), ('boo', '')] == result

    async def test_read_form_while_closed(self):
        stream = Stream(b'')
        obj = aiohttp.BodyPartReader(
            BOUNDARY,
            {CONTENT_TYPE: 'application/x-www-form-urlencoded'}, stream)
        obj._at_eof = True
        result = await obj.form()
        assert result is None

    async def test_readline(self):
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {}, Stream(b'Hello\n,\r\nworld!\r\n--:--'))
        result = await obj.readline()
        assert b'Hello\n' == result
        result = await obj.readline()
        assert b',\r\n' == result
        result = await obj.readline()
        assert b'world!' == result
        result = await obj.readline()
        assert b'' == result
        assert obj.at_eof()

    async def test_release(self):
        stream = Stream(b'Hello,\r\n--:\r\n\r\nworld!\r\n--:--')
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {}, stream)
        await obj.release()
        assert obj.at_eof()
        assert b'--:\r\n\r\nworld!\r\n--:--' == stream.content.read()

    async def test_release_respects_content_length(self):
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {'CONTENT-LENGTH': 100500},
            Stream(b'.' * 100500 + b'\r\n--:--'))
        result = await obj.release()
        assert result is None
        assert obj.at_eof()

    async def test_release_release(self):
        stream = Stream(b'Hello,\r\n--:\r\n\r\nworld!\r\n--:--')
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {}, stream)
        await obj.release()
        await obj.release()
        assert b'--:\r\n\r\nworld!\r\n--:--' == stream.content.read()

    async def test_filename(self):
        part = aiohttp.BodyPartReader(
            BOUNDARY,
            {CONTENT_DISPOSITION: 'attachment; filename=foo.html'},
            None)
        assert 'foo.html' == part.filename

    async def test_reading_long_part(self):
        size = 2 * stream_reader_default_limit
        protocol = mock.Mock(_reading_paused=False)
        stream = StreamReader(protocol)
        stream.feed_data(b'0' * size + b'\r\n--:--')
        stream.feed_eof()
        obj = aiohttp.BodyPartReader(
            BOUNDARY, {}, stream)
        data = await obj.read()
        assert len(data) == size


class TestMultipartReader:

    def test_from_response(self):
        resp = Response({CONTENT_TYPE: 'multipart/related;boundary=":"'},
                        Stream(b'--:\r\n\r\nhello\r\n--:--'))
        res = aiohttp.MultipartReader.from_response(resp)
        assert isinstance(res,
                          MultipartResponseWrapper)
        assert isinstance(res.stream,
                          aiohttp.MultipartReader)

    def test_bad_boundary(self):
        resp = Response(
            {CONTENT_TYPE: 'multipart/related;boundary=' + 'a' * 80},
            Stream(b''))
        with pytest.raises(ValueError):
            aiohttp.MultipartReader.from_response(resp)

    def test_dispatch(self):
        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b'--:\r\n\r\necho\r\n--:--'))
        res = reader._get_part_reader({CONTENT_TYPE: 'text/plain'})
        assert isinstance(res, reader.part_reader_cls)

    def test_dispatch_bodypart(self):
        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b'--:\r\n\r\necho\r\n--:--'))
        res = reader._get_part_reader({CONTENT_TYPE: 'text/plain'})
        assert isinstance(res, reader.part_reader_cls)

    def test_dispatch_multipart(self):
        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b'----:--\r\n'
                   b'\r\n'
                   b'test\r\n'
                   b'----:--\r\n'
                   b'\r\n'
                   b'passed\r\n'
                   b'----:----\r\n'
                   b'--:--'))
        res = reader._get_part_reader(
            {CONTENT_TYPE: 'multipart/related;boundary=--:--'})
        assert isinstance(res, reader.__class__)

    def test_dispatch_custom_multipart_reader(self):
        class CustomReader(aiohttp.MultipartReader):
            pass
        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b'----:--\r\n'
                   b'\r\n'
                   b'test\r\n'
                   b'----:--\r\n'
                   b'\r\n'
                   b'passed\r\n'
                   b'----:----\r\n'
                   b'--:--'))
        reader.multipart_reader_cls = CustomReader
        res = reader._get_part_reader(
            {CONTENT_TYPE: 'multipart/related;boundary=--:--'})
        assert isinstance(res, CustomReader)

    async def test_emit_next(self):
        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b'--:\r\n\r\necho\r\n--:--'))
        res = await reader.next()
        assert isinstance(res, reader.part_reader_cls)

    async def test_invalid_boundary(self):
        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b'---:\r\n\r\necho\r\n---:--'))
        with pytest.raises(ValueError):
            await reader.next()

    async def test_release(self):
        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/mixed;boundary=":"'},
            Stream(b'--:\r\n'
                   b'Content-Type: multipart/related;boundary=--:--\r\n'
                   b'\r\n'
                   b'----:--\r\n'
                   b'\r\n'
                   b'test\r\n'
                   b'----:--\r\n'
                   b'\r\n'
                   b'passed\r\n'
                   b'----:----\r\n'
                   b'\r\n'
                   b'--:--'))
        await reader.release()
        assert reader.at_eof()

    async def test_release_release(self):
        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b'--:\r\n\r\necho\r\n--:--'))
        await reader.release()
        assert reader.at_eof()
        await reader.release()
        assert reader.at_eof()

    async def test_release_next(self):
        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b'--:\r\n\r\necho\r\n--:--'))
        await reader.release()
        assert reader.at_eof()
        res = await reader.next()
        assert res is None

    async def test_second_next_releases_previous_object(self):
        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b'--:\r\n'
                   b'\r\n'
                   b'test\r\n'
                   b'--:\r\n'
                   b'\r\n'
                   b'passed\r\n'
                   b'--:--'))
        first = await reader.next()
        assert isinstance(first, aiohttp.BodyPartReader)
        second = await reader.next()
        assert first.at_eof()
        assert not second.at_eof()

    async def test_release_without_read_the_last_object(self):
        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b'--:\r\n'
                   b'\r\n'
                   b'test\r\n'
                   b'--:\r\n'
                   b'\r\n'
                   b'passed\r\n'
                   b'--:--'))
        first = await reader.next()
        second = await reader.next()
        third = await reader.next()
        assert first.at_eof()
        assert second.at_eof()
        assert second.at_eof()
        assert third is None

    async def test_read_chunk_by_length_doesnt_breaks_reader(self):
        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b'--:\r\n'
                   b'Content-Length: 4\r\n\r\n'
                   b'test'
                   b'\r\n--:\r\n'
                   b'Content-Length: 6\r\n\r\n'
                   b'passed'
                   b'\r\n--:--'))
        body_parts = []
        while True:
            read_part = b''
            part = await reader.next()
            if part is None:
                break
            while not part.at_eof():
                read_part += await part.read_chunk(3)
            body_parts.append(read_part)
        assert body_parts == [b'test', b'passed']

    async def test_read_chunk_from_stream_doesnt_breaks_reader(self):
        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b'--:\r\n'
                   b'\r\n'
                   b'chunk'
                   b'\r\n--:\r\n'
                   b'\r\n'
                   b'two_chunks'
                   b'\r\n--:--'))
        body_parts = []
        while True:
            read_part = b''
            part = await reader.next()
            if part is None:
                break
            while not part.at_eof():
                chunk = await part.read_chunk(5)
                assert chunk
                read_part += chunk
            body_parts.append(read_part)
        assert body_parts == [b'chunk', b'two_chunks']

    async def test_reading_skips_prelude(self):
        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b'Multi-part data is not supported.\r\n'
                   b'\r\n'
                   b'--:\r\n'
                   b'\r\n'
                   b'test\r\n'
                   b'--:\r\n'
                   b'\r\n'
                   b'passed\r\n'
                   b'--:--'))
        first = await reader.next()
        assert isinstance(first, aiohttp.BodyPartReader)
        second = await reader.next()
        assert first.at_eof()
        assert not second.at_eof()


async def test_writer(writer):
    assert writer.size == 0
    assert writer.boundary == ':'


async def test_writer_serialize_io_chunk(buf, stream, writer):
    flo = io.BytesIO(b'foobarbaz')
    writer.append(flo)
    await writer.write(stream)
    assert (buf == b'--:\r\nContent-Type: application/octet-stream'
            b'\r\nContent-Length: 9\r\n\r\nfoobarbaz\r\n--:--\r\n')


async def test_writer_serialize_json(buf, stream, writer):
    writer.append_json({'привет': 'мир'})
    await writer.write(stream)
    assert (b'{"\\u043f\\u0440\\u0438\\u0432\\u0435\\u0442":'
            b' "\\u043c\\u0438\\u0440"}' in buf)


async def test_writer_serialize_form(buf, stream, writer):
    data = [('foo', 'bar'), ('foo', 'baz'), ('boo', 'zoo')]
    writer.append_form(data)
    await writer.write(stream)

    assert (b'foo=bar&foo=baz&boo=zoo' in buf)


async def test_writer_serialize_form_dict(buf, stream, writer):
    data = {'hello': 'мир'}
    writer.append_form(data)
    await writer.write(stream)

    assert (b'hello=%D0%BC%D0%B8%D1%80' in buf)


async def test_writer_write(buf, stream, writer):
    writer.append('foo-bar-baz')
    writer.append_json({'test': 'passed'})
    writer.append_form({'test': 'passed'})
    writer.append_form([('one', 1), ('two', 2)])

    sub_multipart = aiohttp.MultipartWriter(boundary='::')
    sub_multipart.append('nested content')
    sub_multipart.headers['X-CUSTOM'] = 'test'
    writer.append(sub_multipart)
    await writer.write(stream)

    assert (
        (b'--:\r\n'
         b'Content-Type: text/plain; charset=utf-8\r\n'
         b'Content-Length: 11\r\n\r\n'
         b'foo-bar-baz'
         b'\r\n'

         b'--:\r\n'
         b'Content-Type: application/json\r\n'
         b'Content-Length: 18\r\n\r\n'
         b'{"test": "passed"}'
         b'\r\n'

         b'--:\r\n'
         b'Content-Type: application/x-www-form-urlencoded\r\n'
         b'Content-Length: 11\r\n\r\n'
         b'test=passed'
         b'\r\n'

         b'--:\r\n'
         b'Content-Type: application/x-www-form-urlencoded\r\n'
         b'Content-Length: 11\r\n\r\n'
         b'one=1&two=2'
         b'\r\n'

         b'--:\r\n'
         b'Content-Type: multipart/mixed; boundary="::"\r\n'
         b'X-CUSTOM: test\r\nContent-Length: 93\r\n\r\n'
         b'--::\r\n'
         b'Content-Type: text/plain; charset=utf-8\r\n'
         b'Content-Length: 14\r\n\r\n'
         b'nested content\r\n'
         b'--::--\r\n'
         b'\r\n'
         b'--:--\r\n') == bytes(buf))


async def test_writer_serialize_with_content_encoding_gzip(buf, stream,
                                                           writer):
    writer.append('Time to Relax!', {CONTENT_ENCODING: 'gzip'})
    await writer.write(stream)
    headers, message = bytes(buf).split(b'\r\n\r\n', 1)

    assert (b'--:\r\nContent-Encoding: gzip\r\n'
            b'Content-Type: text/plain; charset=utf-8' == headers)

    decompressor = zlib.decompressobj(wbits=16+zlib.MAX_WBITS)
    data = decompressor.decompress(message.split(b'\r\n')[0])
    data += decompressor.flush()
    assert b'Time to Relax!' == data


async def test_writer_serialize_with_content_encoding_deflate(buf, stream,
                                                              writer):
    writer.append('Time to Relax!', {CONTENT_ENCODING: 'deflate'})
    await writer.write(stream)
    headers, message = bytes(buf).split(b'\r\n\r\n', 1)

    assert (b'--:\r\nContent-Encoding: deflate\r\n'
            b'Content-Type: text/plain; charset=utf-8' == headers)

    thing = b'\x0b\xc9\xccMU(\xc9W\x08J\xcdI\xacP\x04\x00\r\n--:--\r\n'
    assert thing == message


async def test_writer_serialize_with_content_encoding_identity(buf, stream,
                                                               writer):
    thing = b'\x0b\xc9\xccMU(\xc9W\x08J\xcdI\xacP\x04\x00'
    writer.append(thing, {CONTENT_ENCODING: 'identity'})
    await writer.write(stream)
    headers, message = bytes(buf).split(b'\r\n\r\n', 1)

    assert (b'--:\r\nContent-Encoding: identity\r\n'
            b'Content-Type: application/octet-stream\r\n'
            b'Content-Length: 16' == headers)

    assert thing == message.split(b'\r\n')[0]


def test_writer_serialize_with_content_encoding_unknown(buf, stream,
                                                        writer):
    with pytest.raises(RuntimeError):
        writer.append('Time to Relax!', {CONTENT_ENCODING: 'snappy'})


async def test_writer_with_content_transfer_encoding_base64(buf, stream,
                                                            writer):
    writer.append('Time to Relax!', {CONTENT_TRANSFER_ENCODING: 'base64'})
    await writer.write(stream)
    headers, message = bytes(buf).split(b'\r\n\r\n', 1)

    assert (b'--:\r\nContent-Transfer-Encoding: base64\r\n'
            b'Content-Type: text/plain; charset=utf-8' ==
            headers)

    assert b'VGltZSB0byBSZWxheCE=' == message.split(b'\r\n')[0]


async def test_writer_content_transfer_encoding_quote_printable(buf, stream,
                                                                writer):
    writer.append('Привет, мир!',
                  {CONTENT_TRANSFER_ENCODING: 'quoted-printable'})
    await writer.write(stream)
    headers, message = bytes(buf).split(b'\r\n\r\n', 1)

    assert (b'--:\r\nContent-Transfer-Encoding: quoted-printable\r\n'
            b'Content-Type: text/plain; charset=utf-8' == headers)

    assert (b'=D0=9F=D1=80=D0=B8=D0=B2=D0=B5=D1=82,'
            b' =D0=BC=D0=B8=D1=80!' == message.split(b'\r\n')[0])


def test_writer_content_transfer_encoding_unknown(buf, stream, writer):
    with pytest.raises(RuntimeError):
        writer.append('Time to Relax!', {CONTENT_TRANSFER_ENCODING: 'unknown'})


class TestMultipartWriter:

    def test_default_subtype(self, writer):
        mimetype = parse_mimetype(writer.headers.get(CONTENT_TYPE))

        assert 'multipart' == mimetype.type
        assert 'mixed' == mimetype.subtype

    def test_unquoted_boundary(self):
        writer = aiohttp.MultipartWriter(boundary='abc123')
        expected = {CONTENT_TYPE: 'multipart/mixed; boundary=abc123'}
        assert expected == writer.headers

    def test_quoted_boundary(self):
        writer = aiohttp.MultipartWriter(boundary=R'\"')
        expected = {CONTENT_TYPE: R'multipart/mixed; boundary="\\\""'}
        assert expected == writer.headers

    def test_bad_boundary(self):
        with pytest.raises(ValueError):
            aiohttp.MultipartWriter(boundary='тест')
        with pytest.raises(ValueError):
            aiohttp.MultipartWriter(boundary='test\n')

    def test_default_headers(self, writer):
        expected = {CONTENT_TYPE: 'multipart/mixed; boundary=":"'}
        assert expected == writer.headers

    def test_iter_parts(self, writer):
        writer.append('foo')
        writer.append('bar')
        writer.append('baz')
        assert 3 == len(list(writer))

    def test_append(self, writer):
        assert 0 == len(writer)
        writer.append('hello, world!')
        assert 1 == len(writer)
        assert isinstance(writer._parts[0][0], payload.Payload)

    def test_append_with_headers(self, writer):
        writer.append('hello, world!', {'x-foo': 'bar'})
        assert 1 == len(writer)
        assert 'x-foo' in writer._parts[0][0].headers
        assert writer._parts[0][0].headers['x-foo'] == 'bar'

    def test_append_json(self, writer):
        writer.append_json({'foo': 'bar'})
        assert 1 == len(writer)
        part = writer._parts[0][0]
        assert part.headers[CONTENT_TYPE] == 'application/json'

    def test_append_part(self, writer):
        part = payload.get_payload(
            'test', headers={CONTENT_TYPE: 'text/plain'})
        writer.append(part, {CONTENT_TYPE: 'test/passed'})
        assert 1 == len(writer)
        part = writer._parts[0][0]
        assert part.headers[CONTENT_TYPE] == 'test/passed'

    def test_append_json_overrides_content_type(self, writer):
        writer.append_json({'foo': 'bar'}, {CONTENT_TYPE: 'test/passed'})
        assert 1 == len(writer)
        part = writer._parts[0][0]
        assert part.headers[CONTENT_TYPE] == 'test/passed'

    def test_append_form(self, writer):
        writer.append_form({'foo': 'bar'}, {CONTENT_TYPE: 'test/passed'})
        assert 1 == len(writer)
        part = writer._parts[0][0]
        assert part.headers[CONTENT_TYPE] == 'test/passed'

    def test_append_multipart(self, writer):
        subwriter = aiohttp.MultipartWriter(boundary=':')
        subwriter.append_json({'foo': 'bar'})
        writer.append(subwriter, {CONTENT_TYPE: 'test/passed'})
        assert 1 == len(writer)
        part = writer._parts[0][0]
        assert part.headers[CONTENT_TYPE] == 'test/passed'

    async def test_write(self, writer, stream):
        await writer.write(stream)

    def test_with(self):
        with aiohttp.MultipartWriter(boundary=':') as writer:
            writer.append('foo')
            writer.append(b'bar')
            writer.append_json({'baz': True})
        assert 3 == len(writer)

    def test_append_int_not_allowed(self):
        with pytest.raises(TypeError):
            with aiohttp.MultipartWriter(boundary=':') as writer:
                writer.append(1)

    def test_append_float_not_allowed(self):
        with pytest.raises(TypeError):
            with aiohttp.MultipartWriter(boundary=':') as writer:
                writer.append(1.1)

    def test_append_none_not_allowed(self):
        with pytest.raises(TypeError):
            with aiohttp.MultipartWriter(boundary=':') as writer:
                writer.append(None)


async def test_async_for_reader(loop):
    data = [
        {"test": "passed"},
        42,
        b'plain text',
        b'aiohttp\n',
        b'no epilogue']
    reader = aiohttp.MultipartReader(
        headers={CONTENT_TYPE: 'multipart/mixed; boundary=":"'},
        content=Stream(b'\r\n'.join([
            b'--:',
            b'Content-Type: application/json',
            b'',
            json.dumps(data[0]).encode(),
            b'--:',
            b'Content-Type: application/json',
            b'',
            json.dumps(data[1]).encode(),
            b'--:',
            b'Content-Type: multipart/related; boundary="::"',
            b'',
            b'--::',
            b'Content-Type: text/plain',
            b'',
            data[2],
            b'--::',
            b'Content-Disposition: attachment; filename="aiohttp"',
            b'Content-Type: text/plain',
            b'Content-Length: 28',
            b'Content-Encoding: gzip',
            b'',
            b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03K\xcc\xcc\xcf())'
            b'\xe0\x02\x00\xd6\x90\xe2O\x08\x00\x00\x00',
            b'--::',
            b'Content-Type: multipart/related; boundary=":::"',
            b'',
            b'--:::',
            b'Content-Type: text/plain',
            b'',
            data[4],
            b'--:::--',
            b'--::--',
            b'',
            b'--:--',
            b''])))
    idata = iter(data)

    async def check(reader):
        async for part in reader:
            if isinstance(part, aiohttp.BodyPartReader):
                if part.headers[CONTENT_TYPE] == 'application/json':
                    assert next(idata) == (await part.json())
                else:
                    assert next(idata) == await part.read(decode=True)
            else:
                await check(part)

    await check(reader)


async def test_async_for_bodypart(loop):
    part = aiohttp.BodyPartReader(
        boundary=b'--:',
        headers={},
        content=Stream(b'foobarbaz\r\n--:--'))
    async for data in part:
        assert data == b'foobarbaz'
