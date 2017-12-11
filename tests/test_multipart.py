import asyncio
import functools
import io
import json
import unittest
import zlib
from unittest import mock

import pytest

import aiohttp.multipart
from aiohttp import payload
from aiohttp.hdrs import (CONTENT_DISPOSITION, CONTENT_ENCODING,
                          CONTENT_TRANSFER_ENCODING, CONTENT_TYPE)
from aiohttp.helpers import parse_mimetype
from aiohttp.multipart import (content_disposition_filename,
                               parse_content_disposition)
from aiohttp.streams import DEFAULT_LIMIT as stream_reader_default_limit
from aiohttp.streams import StreamReader


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
    return aiohttp.multipart.MultipartWriter(boundary=':')


def run_in_loop(f):
    @functools.wraps(f)
    def wrapper(testcase, *args, **kwargs):
        coro = asyncio.coroutine(f)
        future = asyncio.wait_for(coro(testcase, *args, **kwargs), timeout=5)
        return testcase.loop.run_until_complete(future)
    return wrapper


class MetaAioTestCase(type):

    def __new__(cls, name, bases, attrs):
        for key, obj in attrs.items():
            if key.startswith('test_'):
                attrs[key] = run_in_loop(obj)
        return super().__new__(cls, name, bases, attrs)


class TestCase(unittest.TestCase, metaclass=MetaAioTestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    def tearDown(self):
        self.loop.close()

    def future(self, obj):
        fut = self.loop.create_future()
        fut.set_result(obj)
        return fut


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


class MultipartResponseWrapperTestCase(TestCase):

    def setUp(self):
        super().setUp()
        wrapper = aiohttp.multipart.MultipartResponseWrapper(mock.Mock(),
                                                             mock.Mock())
        self.wrapper = wrapper

    def test_at_eof(self):
        self.wrapper.at_eof()
        self.assertTrue(self.wrapper.resp.content.at_eof.called)

    async def test_next(self):
        self.wrapper.stream.next.return_value = self.future(b'')
        self.wrapper.stream.at_eof.return_value = False
        await self.wrapper.next()
        self.assertTrue(self.wrapper.stream.next.called)

    async def test_release(self):
        self.wrapper.resp.release.return_value = self.future(None)
        await self.wrapper.release()
        self.assertTrue(self.wrapper.resp.release.called)

    async def test_release_when_stream_at_eof(self):
        self.wrapper.resp.release.return_value = self.future(None)
        self.wrapper.stream.next.return_value = self.future(b'')
        self.wrapper.stream.at_eof.return_value = True
        await self.wrapper.next()
        self.assertTrue(self.wrapper.stream.next.called)
        self.assertTrue(self.wrapper.resp.release.called)


class PartReaderTestCase(TestCase):

    def setUp(self):
        super().setUp()
        self.boundary = b'--:'

    async def test_next(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {}, Stream(b'Hello, world!\r\n--:'))
        result = await obj.next()
        self.assertEqual(b'Hello, world!', result)
        self.assertTrue(obj.at_eof())

    async def test_next_next(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {}, Stream(b'Hello, world!\r\n--:'))
        result = await obj.next()
        self.assertEqual(b'Hello, world!', result)
        self.assertTrue(obj.at_eof())
        result = await obj.next()
        self.assertIsNone(result)

    async def test_read(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {}, Stream(b'Hello, world!\r\n--:'))
        result = await obj.read()
        self.assertEqual(b'Hello, world!', result)
        self.assertTrue(obj.at_eof())

    async def test_read_chunk_at_eof(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {}, Stream(b'--:'))
        obj._at_eof = True
        result = await obj.read_chunk()
        self.assertEqual(b'', result)

    async def test_read_chunk_without_content_length(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {}, Stream(b'Hello, world!\r\n--:'))
        c1 = await obj.read_chunk(8)
        c2 = await obj.read_chunk(8)
        c3 = await obj.read_chunk(8)
        self.assertEqual(c1 + c2, b'Hello, world!')
        self.assertEqual(c3, b'')

    async def test_read_incomplete_chunk(self):
        stream = Stream(b'')

        def prepare(data):
            f = self.loop.create_future()
            f.set_result(data)
            return f

        with mock.patch.object(stream, 'read', side_effect=[
            prepare(b'Hello, '),
            prepare(b'World'),
            prepare(b'!\r\n--:'),
            prepare(b'')
        ]):
            obj = aiohttp.multipart.BodyPartReader(
                self.boundary, {}, stream)
            c1 = await obj.read_chunk(8)
            self.assertEqual(c1, b'Hello, ')
            c2 = await obj.read_chunk(8)
            self.assertEqual(c2, b'World')
            c3 = await obj.read_chunk(8)
            self.assertEqual(c3, b'!')

    async def test_read_all_at_once(self):
        stream = Stream(b'Hello, World!\r\n--:--\r\n')
        obj = aiohttp.multipart.BodyPartReader(self.boundary, {}, stream)
        result = await obj.read_chunk()
        self.assertEqual(b'Hello, World!', result)
        result = await obj.read_chunk()
        self.assertEqual(b'', result)
        self.assertTrue(obj.at_eof())

    async def test_read_incomplete_body_chunked(self):
        stream = Stream(b'Hello, World!\r\n-')
        obj = aiohttp.multipart.BodyPartReader(self.boundary, {}, stream)
        result = b''
        with self.assertRaises(AssertionError):
            for _ in range(4):
                result += await obj.read_chunk(7)
        self.assertEqual(b'Hello, World!\r\n-', result)

    async def test_read_boundary_with_incomplete_chunk(self):
        stream = Stream(b'')

        def prepare(data):
            f = self.loop.create_future()
            f.set_result(data)
            return f

        with mock.patch.object(stream, 'read', side_effect=[
            prepare(b'Hello, World'),
            prepare(b'!\r\n'),
            prepare(b'--:'),
            prepare(b'')
        ]):
            obj = aiohttp.multipart.BodyPartReader(
                self.boundary, {}, stream)
            c1 = await obj.read_chunk(12)
            self.assertEqual(c1, b'Hello, World')
            c2 = await obj.read_chunk(8)
            self.assertEqual(c2, b'!')
            c3 = await obj.read_chunk(8)
            self.assertEqual(c3, b'')

    async def test_multi_read_chunk(self):
        stream = Stream(b'Hello,\r\n--:\r\n\r\nworld!\r\n--:--')
        obj = aiohttp.multipart.BodyPartReader(self.boundary, {}, stream)
        result = await obj.read_chunk(8)
        self.assertEqual(b'Hello,', result)
        result = await obj.read_chunk(8)
        self.assertEqual(b'', result)
        self.assertTrue(obj.at_eof())

    async def test_read_chunk_properly_counts_read_bytes(self):
        expected = b'.' * 10
        size = len(expected)
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {'CONTENT-LENGTH': size},
            StreamWithShortenRead(expected + b'\r\n--:--'))
        result = bytearray()
        while True:
            chunk = await obj.read_chunk()
            if not chunk:
                break
            result.extend(chunk)
        self.assertEqual(size, len(result))
        self.assertEqual(b'.' * size, result)
        self.assertTrue(obj.at_eof())

    async def test_read_does_not_read_boundary(self):
        stream = Stream(b'Hello, world!\r\n--:')
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {}, stream)
        result = await obj.read()
        self.assertEqual(b'Hello, world!', result)
        self.assertEqual(b'--:', (await stream.read()))

    async def test_multiread(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {}, Stream(b'Hello,\r\n--:\r\n\r\nworld!\r\n--:--'))
        result = await obj.read()
        self.assertEqual(b'Hello,', result)
        result = await obj.read()
        self.assertEqual(b'', result)
        self.assertTrue(obj.at_eof())

    async def test_read_multiline(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {}, Stream(b'Hello\n,\r\nworld!\r\n--:--'))
        result = await obj.read()
        self.assertEqual(b'Hello\n,\r\nworld!', result)
        result = await obj.read()
        self.assertEqual(b'', result)
        self.assertTrue(obj.at_eof())

    async def test_read_respects_content_length(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {'CONTENT-LENGTH': 100500},
            Stream(b'.' * 100500 + b'\r\n--:--'))
        result = await obj.read()
        self.assertEqual(b'.' * 100500, result)
        self.assertTrue(obj.at_eof())

    async def test_read_with_content_encoding_gzip(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_ENCODING: 'gzip'},
            Stream(b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x0b\xc9\xccMU'
                   b'(\xc9W\x08J\xcdI\xacP\x04\x00$\xfb\x9eV\x0e\x00\x00\x00'
                   b'\r\n--:--'))
        result = await obj.read(decode=True)
        self.assertEqual(b'Time to Relax!', result)

    async def test_read_with_content_encoding_deflate(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_ENCODING: 'deflate'},
            Stream(b'\x0b\xc9\xccMU(\xc9W\x08J\xcdI\xacP\x04\x00\r\n--:--'))
        result = await obj.read(decode=True)
        self.assertEqual(b'Time to Relax!', result)

    async def test_read_with_content_encoding_identity(self):
        thing = (b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x0b\xc9\xccMU'
                 b'(\xc9W\x08J\xcdI\xacP\x04\x00$\xfb\x9eV\x0e\x00\x00\x00'
                 b'\r\n')
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_ENCODING: 'identity'},
            Stream(thing + b'--:--'))
        result = await obj.read(decode=True)
        self.assertEqual(thing[:-2], result)

    async def test_read_with_content_encoding_unknown(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_ENCODING: 'snappy'},
            Stream(b'\x0e4Time to Relax!\r\n--:--'))
        with self.assertRaises(RuntimeError):
            await obj.read(decode=True)

    async def test_read_with_content_transfer_encoding_base64(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_TRANSFER_ENCODING: 'base64'},
            Stream(b'VGltZSB0byBSZWxheCE=\r\n--:--'))
        result = await obj.read(decode=True)
        self.assertEqual(b'Time to Relax!', result)

    async def test_read_with_content_transfer_encoding_quoted_printable(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_TRANSFER_ENCODING: 'quoted-printable'},
            Stream(b'=D0=9F=D1=80=D0=B8=D0=B2=D0=B5=D1=82,'
                   b' =D0=BC=D0=B8=D1=80!\r\n--:--'))
        result = await obj.read(decode=True)
        self.assertEqual(b'\xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82,'
                         b' \xd0\xbc\xd0\xb8\xd1\x80!', result)

    @pytest.mark.parametrize('encoding', [])
    async def test_read_with_content_transfer_encoding_binary(self):
        data = b'\xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82,' \
               b' \xd0\xbc\xd0\xb8\xd1\x80!'
        for encoding in ('binary', '8bit', '7bit'):
            with self.subTest(encoding):
                obj = aiohttp.multipart.BodyPartReader(
                    self.boundary, {CONTENT_TRANSFER_ENCODING: encoding},
                    Stream(data + b'\r\n--:--'))
                result = await obj.read(decode=True)
                self.assertEqual(data, result)

    async def test_read_with_content_transfer_encoding_unknown(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_TRANSFER_ENCODING: 'unknown'},
            Stream(b'\x0e4Time to Relax!\r\n--:--'))
        with self.assertRaises(RuntimeError):
            await obj.read(decode=True)

    async def test_read_text(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {}, Stream(b'Hello, world!\r\n--:--'))
        result = await obj.text()
        self.assertEqual('Hello, world!', result)

    async def test_read_text_default_encoding(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {},
            Stream('Привет, Мир!\r\n--:--'.encode('utf-8')))
        result = await obj.text()
        self.assertEqual('Привет, Мир!', result)

    async def test_read_text_encoding(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {},
            Stream('Привет, Мир!\r\n--:--'.encode('cp1251')))
        result = await obj.text(encoding='cp1251')
        self.assertEqual('Привет, Мир!', result)

    async def test_read_text_guess_encoding(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_TYPE: 'text/plain;charset=cp1251'},
            Stream('Привет, Мир!\r\n--:--'.encode('cp1251')))
        result = await obj.text()
        self.assertEqual('Привет, Мир!', result)

    async def test_read_text_compressed(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_ENCODING: 'deflate',
                            CONTENT_TYPE: 'text/plain'},
            Stream(b'\x0b\xc9\xccMU(\xc9W\x08J\xcdI\xacP\x04\x00\r\n--:--'))
        result = await obj.text()
        self.assertEqual('Time to Relax!', result)

    async def test_read_text_while_closed(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_TYPE: 'text/plain'}, Stream(b''))
        obj._at_eof = True
        result = await obj.text()
        self.assertEqual('', result)

    async def test_read_json(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_TYPE: 'application/json'},
            Stream(b'{"test": "passed"}\r\n--:--'))
        result = await obj.json()
        self.assertEqual({'test': 'passed'}, result)

    async def test_read_json_encoding(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_TYPE: 'application/json'},
            Stream('{"тест": "пассед"}\r\n--:--'.encode('cp1251')))
        result = await obj.json(encoding='cp1251')
        self.assertEqual({'тест': 'пассед'}, result)

    async def test_read_json_guess_encoding(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_TYPE: 'application/json; charset=cp1251'},
            Stream('{"тест": "пассед"}\r\n--:--'.encode('cp1251')))
        result = await obj.json()
        self.assertEqual({'тест': 'пассед'}, result)

    async def test_read_json_compressed(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_ENCODING: 'deflate',
                            CONTENT_TYPE: 'application/json'},
            Stream(b'\xabV*I-.Q\xb2RP*H,.NMQ\xaa\x05\x00\r\n--:--'))
        result = await obj.json()
        self.assertEqual({'test': 'passed'}, result)

    async def test_read_json_while_closed(self):
        stream = Stream(b'')
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_TYPE: 'application/json'}, stream)
        obj._at_eof = True
        result = await obj.json()
        self.assertEqual(None, result)

    async def test_read_form(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_TYPE: 'application/x-www-form-urlencoded'},
            Stream(b'foo=bar&foo=baz&boo=\r\n--:--'))
        result = await obj.form()
        self.assertEqual([('foo', 'bar'), ('foo', 'baz'), ('boo', '')],
                         result)

    async def test_read_form_encoding(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_TYPE: 'application/x-www-form-urlencoded'},
            Stream('foo=bar&foo=baz&boo=\r\n--:--'.encode('cp1251')))
        result = await obj.form(encoding='cp1251')
        self.assertEqual([('foo', 'bar'), ('foo', 'baz'), ('boo', '')],
                         result)

    async def test_read_form_guess_encoding(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary,
            {CONTENT_TYPE: 'application/x-www-form-urlencoded; charset=utf-8'},
            Stream('foo=bar&foo=baz&boo=\r\n--:--'.encode('utf-8')))
        result = await obj.form()
        self.assertEqual([('foo', 'bar'), ('foo', 'baz'), ('boo', '')],
                         result)

    async def test_read_form_while_closed(self):
        stream = Stream(b'')
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary,
            {CONTENT_TYPE: 'application/x-www-form-urlencoded'}, stream)
        obj._at_eof = True
        result = await obj.form()
        self.assertEqual(None, result)

    async def test_readline(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {}, Stream(b'Hello\n,\r\nworld!\r\n--:--'))
        result = await obj.readline()
        self.assertEqual(b'Hello\n', result)
        result = await obj.readline()
        self.assertEqual(b',\r\n', result)
        result = await obj.readline()
        self.assertEqual(b'world!', result)
        result = await obj.readline()
        self.assertEqual(b'', result)
        self.assertTrue(obj.at_eof())

    async def test_release(self):
        stream = Stream(b'Hello,\r\n--:\r\n\r\nworld!\r\n--:--')
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {}, stream)
        await obj.release()
        self.assertTrue(obj.at_eof())
        self.assertEqual(b'--:\r\n\r\nworld!\r\n--:--', stream.content.read())

    async def test_release_respects_content_length(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {'CONTENT-LENGTH': 100500},
            Stream(b'.' * 100500 + b'\r\n--:--'))
        result = await obj.release()
        self.assertIsNone(result)
        self.assertTrue(obj.at_eof())

    async def test_release_release(self):
        stream = Stream(b'Hello,\r\n--:\r\n\r\nworld!\r\n--:--')
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {}, stream)
        await obj.release()
        await obj.release()
        self.assertEqual(b'--:\r\n\r\nworld!\r\n--:--', stream.content.read())

    async def test_filename(self):
        part = aiohttp.multipart.BodyPartReader(
            self.boundary,
            {CONTENT_DISPOSITION: 'attachment; filename=foo.html'},
            None)
        self.assertEqual('foo.html', part.filename)

    async def test_reading_long_part(self):
        size = 2 * stream_reader_default_limit
        protocol = mock.Mock(_reading_paused=False)
        stream = StreamReader(protocol)
        stream.feed_data(b'0' * size + b'\r\n--:--')
        stream.feed_eof()
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {}, stream)
        data = await obj.read()
        self.assertEqual(len(data), size)


class MultipartReaderTestCase(TestCase):

    def test_from_response(self):
        resp = Response({CONTENT_TYPE: 'multipart/related;boundary=":"'},
                        Stream(b'--:\r\n\r\nhello\r\n--:--'))
        res = aiohttp.multipart.MultipartReader.from_response(resp)
        self.assertIsInstance(res,
                              aiohttp.multipart.MultipartResponseWrapper)
        self.assertIsInstance(res.stream,
                              aiohttp.multipart.MultipartReader)

    def test_bad_boundary(self):
        resp = Response(
            {CONTENT_TYPE: 'multipart/related;boundary=' + 'a' * 80},
            Stream(b''))
        with self.assertRaises(ValueError):
            aiohttp.multipart.MultipartReader.from_response(resp)

    def test_dispatch(self):
        reader = aiohttp.multipart.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b'--:\r\n\r\necho\r\n--:--'))
        res = reader._get_part_reader({CONTENT_TYPE: 'text/plain'})
        self.assertIsInstance(res, reader.part_reader_cls)

    def test_dispatch_bodypart(self):
        reader = aiohttp.multipart.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b'--:\r\n\r\necho\r\n--:--'))
        res = reader._get_part_reader({CONTENT_TYPE: 'text/plain'})
        self.assertIsInstance(res, reader.part_reader_cls)

    def test_dispatch_multipart(self):
        reader = aiohttp.multipart.MultipartReader(
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
        self.assertIsInstance(res, reader.__class__)

    def test_dispatch_custom_multipart_reader(self):
        class CustomReader(aiohttp.multipart.MultipartReader):
            pass
        reader = aiohttp.multipart.MultipartReader(
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
        self.assertIsInstance(res, CustomReader)

    async def test_emit_next(self):
        reader = aiohttp.multipart.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b'--:\r\n\r\necho\r\n--:--'))
        res = await reader.next()
        self.assertIsInstance(res, reader.part_reader_cls)

    async def test_invalid_boundary(self):
        reader = aiohttp.multipart.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b'---:\r\n\r\necho\r\n---:--'))
        with self.assertRaises(ValueError):
            await reader.next()

    async def test_release(self):
        reader = aiohttp.multipart.MultipartReader(
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
        self.assertTrue(reader.at_eof())

    async def test_release_release(self):
        reader = aiohttp.multipart.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b'--:\r\n\r\necho\r\n--:--'))
        await reader.release()
        self.assertTrue(reader.at_eof())
        await reader.release()
        self.assertTrue(reader.at_eof())

    async def test_release_next(self):
        reader = aiohttp.multipart.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b'--:\r\n\r\necho\r\n--:--'))
        await reader.release()
        self.assertTrue(reader.at_eof())
        res = await reader.next()
        self.assertIsNone(res)

    async def test_second_next_releases_previous_object(self):
        reader = aiohttp.multipart.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b'--:\r\n'
                   b'\r\n'
                   b'test\r\n'
                   b'--:\r\n'
                   b'\r\n'
                   b'passed\r\n'
                   b'--:--'))
        first = await reader.next()
        self.assertIsInstance(first, aiohttp.multipart.BodyPartReader)
        second = await reader.next()
        self.assertTrue(first.at_eof())
        self.assertFalse(second.at_eof())

    async def test_release_without_read_the_last_object(self):
        reader = aiohttp.multipart.MultipartReader(
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
        self.assertTrue(first.at_eof())
        self.assertTrue(second.at_eof())
        self.assertTrue(second.at_eof())
        self.assertIsNone(third)

    async def test_read_chunk_by_length_doesnt_breaks_reader(self):
        reader = aiohttp.multipart.MultipartReader(
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
        self.assertListEqual(body_parts, [b'test', b'passed'])

    async def test_read_chunk_from_stream_doesnt_breaks_reader(self):
        reader = aiohttp.multipart.MultipartReader(
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
                self.assertTrue(chunk)
                read_part += chunk
            body_parts.append(read_part)
        self.assertListEqual(body_parts, [b'chunk', b'two_chunks'])

    async def test_reading_skips_prelude(self):
        reader = aiohttp.multipart.MultipartReader(
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
        self.assertIsInstance(first, aiohttp.multipart.BodyPartReader)
        second = await reader.next()
        self.assertTrue(first.at_eof())
        self.assertFalse(second.at_eof())


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

    sub_multipart = aiohttp.multipart.MultipartWriter(boundary='::')
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


class MultipartWriterTestCase(TestCase):

    def setUp(self):
        super().setUp()
        self.buf = bytearray()
        self.stream = mock.Mock()

        async def write(chunk):
            self.buf.extend(chunk)

        self.stream.write.side_effect = write

        self.writer = aiohttp.multipart.MultipartWriter(boundary=':')

    def test_default_subtype(self):
        mimetype = parse_mimetype(self.writer.headers.get(CONTENT_TYPE))

        self.assertEqual('multipart', mimetype.type)
        self.assertEqual('mixed', mimetype.subtype)

    def test_unquoted_boundary(self):
        writer = aiohttp.multipart.MultipartWriter(boundary='abc123')
        self.assertEqual({CONTENT_TYPE: 'multipart/mixed; boundary=abc123'},
                         writer.headers)

    def test_quoted_boundary(self):
        writer = aiohttp.multipart.MultipartWriter(boundary=R'\"')
        self.assertEqual({CONTENT_TYPE: R'multipart/mixed; boundary="\\\""'},
                         writer.headers)

    def test_bad_boundary(self):
        with self.assertRaises(ValueError):
            aiohttp.multipart.MultipartWriter(boundary='тест')
        with self.assertRaises(ValueError):
            aiohttp.multipart.MultipartWriter(boundary='test\n')

    def test_default_headers(self):
        self.assertEqual({CONTENT_TYPE: 'multipart/mixed; boundary=":"'},
                         self.writer.headers)

    def test_iter_parts(self):
        self.writer.append('foo')
        self.writer.append('bar')
        self.writer.append('baz')
        self.assertEqual(3, len(list(self.writer)))

    def test_append(self):
        self.assertEqual(0, len(self.writer))
        self.writer.append('hello, world!')
        self.assertEqual(1, len(self.writer))
        self.assertIsInstance(self.writer._parts[0][0], payload.Payload)

    def test_append_with_headers(self):
        self.writer.append('hello, world!', {'x-foo': 'bar'})
        self.assertEqual(1, len(self.writer))
        self.assertIn('x-foo', self.writer._parts[0][0].headers)
        self.assertEqual(self.writer._parts[0][0].headers['x-foo'], 'bar')

    def test_append_json(self):
        self.writer.append_json({'foo': 'bar'})
        self.assertEqual(1, len(self.writer))
        part = self.writer._parts[0][0]
        self.assertEqual(part.headers[CONTENT_TYPE], 'application/json')

    def test_append_part(self):
        part = payload.get_payload(
            'test', headers={CONTENT_TYPE: 'text/plain'})
        self.writer.append(part, {CONTENT_TYPE: 'test/passed'})
        self.assertEqual(1, len(self.writer))
        part = self.writer._parts[0][0]
        self.assertEqual(part.headers[CONTENT_TYPE], 'test/passed')

    def test_append_json_overrides_content_type(self):
        self.writer.append_json({'foo': 'bar'}, {CONTENT_TYPE: 'test/passed'})
        self.assertEqual(1, len(self.writer))
        part = self.writer._parts[0][0]
        self.assertEqual(part.headers[CONTENT_TYPE], 'test/passed')

    def test_append_form(self):
        self.writer.append_form({'foo': 'bar'}, {CONTENT_TYPE: 'test/passed'})
        self.assertEqual(1, len(self.writer))
        part = self.writer._parts[0][0]
        self.assertEqual(part.headers[CONTENT_TYPE], 'test/passed')

    def test_append_multipart(self):
        subwriter = aiohttp.multipart.MultipartWriter(boundary=':')
        subwriter.append_json({'foo': 'bar'})
        self.writer.append(subwriter, {CONTENT_TYPE: 'test/passed'})
        self.assertEqual(1, len(self.writer))
        part = self.writer._parts[0][0]
        self.assertEqual(part.headers[CONTENT_TYPE], 'test/passed')

    async def test_write(self):
        await self.writer.write(self.stream)

    def test_with(self):
        with aiohttp.multipart.MultipartWriter(boundary=':') as writer:
            writer.append('foo')
            writer.append(b'bar')
            writer.append_json({'baz': True})
        self.assertEqual(3, len(writer))

    def test_append_int_not_allowed(self):
        with self.assertRaises(TypeError):
            with aiohttp.multipart.MultipartWriter(boundary=':') as writer:
                writer.append(1)

    def test_append_float_not_allowed(self):
        with self.assertRaises(TypeError):
            with aiohttp.multipart.MultipartWriter(boundary=':') as writer:
                writer.append(1.1)

    def test_append_none_not_allowed(self):
        with self.assertRaises(TypeError):
            with aiohttp.multipart.MultipartWriter(boundary=':') as writer:
                writer.append(None)


class ParseContentDispositionTestCase(unittest.TestCase):
    # http://greenbytes.de/tech/tc2231/

    def test_parse_empty(self):
        disptype, params = parse_content_disposition(None)
        self.assertEqual(None, disptype)
        self.assertEqual({}, params)

    def test_inlonly(self):
        disptype, params = parse_content_disposition('inline')
        self.assertEqual('inline', disptype)
        self.assertEqual({}, params)

    def test_inlonlyquoted(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionHeader):
            disptype, params = parse_content_disposition('"inline"')
        self.assertEqual(None, disptype)
        self.assertEqual({}, params)

    def test_semicolon(self):
        disptype, params = parse_content_disposition(
            'form-data; name="data"; filename="file ; name.mp4"')
        self.assertEqual(disptype, 'form-data')
        self.assertEqual(
            params, {'name': 'data', 'filename': 'file ; name.mp4'})

    def test_inlwithasciifilename(self):
        disptype, params = parse_content_disposition(
            'inline; filename="foo.html"')
        self.assertEqual('inline', disptype)
        self.assertEqual({'filename': 'foo.html'}, params)

    def test_inlwithfnattach(self):
        disptype, params = parse_content_disposition(
            'inline; filename="Not an attachment!"')
        self.assertEqual('inline', disptype)
        self.assertEqual({'filename': 'Not an attachment!'}, params)

    def test_attonly(self):
        disptype, params = parse_content_disposition('attachment')
        self.assertEqual('attachment', disptype)
        self.assertEqual({}, params)

    def test_attonlyquoted(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionHeader):
            disptype, params = parse_content_disposition('"attachment"')
        self.assertEqual(None, disptype)
        self.assertEqual({}, params)

    def test_attonlyucase(self):
        disptype, params = parse_content_disposition('ATTACHMENT')
        self.assertEqual('attachment', disptype)
        self.assertEqual({}, params)

    def test_attwithasciifilename(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="foo.html"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename': 'foo.html'}, params)

    def test_inlwithasciifilenamepdf(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="foo.pdf"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename': 'foo.pdf'}, params)

    def test_attwithasciifilename25(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="0000000000111111111122222"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename': '0000000000111111111122222'}, params)

    def test_attwithasciifilename35(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="00000000001111111111222222222233333"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename': '00000000001111111111222222222233333'},
                         params)

    def test_attwithasciifnescapedchar(self):
        disptype, params = parse_content_disposition(
            r'attachment; filename="f\oo.html"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename': 'foo.html'}, params)

    def test_attwithasciifnescapedquote(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="\"quoting\" tested.html"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename': '"quoting" tested.html'}, params)

    @unittest.skip('need more smart parser which respects quoted text')
    def test_attwithquotedsemicolon(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="Here\'s a semicolon;.html"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename': 'Here\'s a semicolon;.html'}, params)

    def test_attwithfilenameandextparam(self):
        disptype, params = parse_content_disposition(
            'attachment; foo="bar"; filename="foo.html"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename': 'foo.html', 'foo': 'bar'}, params)

    def test_attwithfilenameandextparamescaped(self):
        disptype, params = parse_content_disposition(
            'attachment; foo="\"\\";filename="foo.html"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename': 'foo.html', 'foo': '"\\'}, params)

    def test_attwithasciifilenameucase(self):
        disptype, params = parse_content_disposition(
            'attachment; FILENAME="foo.html"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename': 'foo.html'}, params)

    def test_attwithasciifilenamenq(self):
        disptype, params = parse_content_disposition(
            'attachment; filename=foo.html')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename': 'foo.html'}, params)

    def test_attwithtokfncommanq(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; filename=foo,bar.html')
        self.assertEqual(None, disptype)
        self.assertEqual({}, params)

    def test_attwithasciifilenamenqs(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; filename=foo.html ;')
        self.assertEqual(None, disptype)
        self.assertEqual({}, params)

    def test_attemptyparam(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; ;filename=foo')
        self.assertEqual(None, disptype)
        self.assertEqual({}, params)

    def test_attwithasciifilenamenqws(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; filename=foo bar.html')
        self.assertEqual(None, disptype)
        self.assertEqual({}, params)

    def test_attwithfntokensq(self):
        disptype, params = parse_content_disposition(
            "attachment; filename='foo.html'")
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename': "'foo.html'"}, params)

    def test_attwithisofnplain(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="foo-ä.html"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename': 'foo-ä.html'}, params)

    def test_attwithutf8fnplain(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="foo-Ã¤.html"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename': 'foo-Ã¤.html'}, params)

    def test_attwithfnrawpctenca(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="foo-%41.html"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename': 'foo-%41.html'}, params)

    def test_attwithfnusingpct(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="50%.html"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename': '50%.html'}, params)

    def test_attwithfnrawpctencaq(self):
        disptype, params = parse_content_disposition(
            r'attachment; filename="foo-%\41.html"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename': r'foo-%41.html'}, params)

    def test_attwithnamepct(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="foo-%41.html"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename': 'foo-%41.html'}, params)

    def test_attwithfilenamepctandiso(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="ä-%41.html"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename': 'ä-%41.html'}, params)

    def test_attwithfnrawpctenclong(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="foo-%c3%a4-%e2%82%ac.html"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename': 'foo-%c3%a4-%e2%82%ac.html'}, params)

    def test_attwithasciifilenamews1(self):
        disptype, params = parse_content_disposition(
            'attachment; filename ="foo.html"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename': 'foo.html'}, params)

    def test_attwith2filenames(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; filename="foo.html"; filename="bar.html"')
        self.assertEqual(None, disptype)
        self.assertEqual({}, params)

    def test_attfnbrokentoken(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; filename=foo[1](2).html')
        self.assertEqual(None, disptype)
        self.assertEqual({}, params)

    def test_attfnbrokentokeniso(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; filename=foo-ä.html')
        self.assertEqual(None, disptype)
        self.assertEqual({}, params)

    def test_attfnbrokentokenutf(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; filename=foo-Ã¤.html')
        self.assertEqual(None, disptype)
        self.assertEqual({}, params)

    def test_attmissingdisposition(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'filename=foo.html')
        self.assertEqual(None, disptype)
        self.assertEqual({}, params)

    def test_attmissingdisposition2(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'x=y; filename=foo.html')
        self.assertEqual(None, disptype)
        self.assertEqual({}, params)

    def test_attmissingdisposition3(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                '"foo; filename=bar;baz"; filename=qux')
        self.assertEqual(None, disptype)
        self.assertEqual({}, params)

    def test_attmissingdisposition4(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'filename=foo.html, filename=bar.html')
        self.assertEqual(None, disptype)
        self.assertEqual({}, params)

    def test_emptydisposition(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                '; filename=foo.html')
        self.assertEqual(None, disptype)
        self.assertEqual({}, params)

    def test_doublecolon(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                ': inline; attachment; filename=foo.html')
        self.assertEqual(None, disptype)
        self.assertEqual({}, params)

    def test_attandinline(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'inline; attachment; filename=foo.html')
        self.assertEqual(None, disptype)
        self.assertEqual({}, params)

    def test_attandinline2(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; inline; filename=foo.html')
        self.assertEqual(None, disptype)
        self.assertEqual({}, params)

    def test_attbrokenquotedfn(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; filename="foo.html".txt')
        self.assertEqual(None, disptype)
        self.assertEqual({}, params)

    def test_attbrokenquotedfn2(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; filename="bar')
        self.assertEqual(None, disptype)
        self.assertEqual({}, params)

    def test_attbrokenquotedfn3(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; filename=foo"bar;baz"qux')
        self.assertEqual(None, disptype)
        self.assertEqual({}, params)

    def test_attmultinstances(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; filename=foo.html, attachment; filename=bar.html')
        self.assertEqual(None, disptype)
        self.assertEqual({}, params)

    def test_attmissingdelim(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; foo=foo filename=bar')
        self.assertEqual(None, disptype)
        self.assertEqual({}, params)

    def test_attmissingdelim2(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; filename=bar foo=foo')
        self.assertEqual(None, disptype)
        self.assertEqual({}, params)

    def test_attmissingdelim3(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment filename=bar')
        self.assertEqual(None, disptype)
        self.assertEqual({}, params)

    def test_attreversed(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'filename=foo.html; attachment')
        self.assertEqual(None, disptype)
        self.assertEqual({}, params)

    def test_attconfusedparam(self):
        disptype, params = parse_content_disposition(
            'attachment; xfilename=foo.html')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'xfilename': 'foo.html'}, params)

    def test_attabspath(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="/foo.html"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename': 'foo.html'}, params)

    def test_attabspathwin(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="\\foo.html"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename': 'foo.html'}, params)

    def test_attcdate(self):
        disptype, params = parse_content_disposition(
            'attachment; creation-date="Wed, 12 Feb 1997 16:29:51 -0500"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'creation-date': 'Wed, 12 Feb 1997 16:29:51 -0500'},
                         params)

    def test_attmdate(self):
        disptype, params = parse_content_disposition(
            'attachment; modification-date="Wed, 12 Feb 1997 16:29:51 -0500"')
        self.assertEqual('attachment', disptype)
        self.assertEqual(
            {'modification-date': 'Wed, 12 Feb 1997 16:29:51 -0500'},
            params)

    def test_dispext(self):
        disptype, params = parse_content_disposition('foobar')
        self.assertEqual('foobar', disptype)
        self.assertEqual({}, params)

    def test_dispextbadfn(self):
        disptype, params = parse_content_disposition(
            'attachment; example="filename=example.txt"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'example': 'filename=example.txt'}, params)

    def test_attwithisofn2231iso(self):
        disptype, params = parse_content_disposition(
            "attachment; filename*=iso-8859-1''foo-%E4.html")
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename*': 'foo-ä.html'}, params)

    def test_attwithfn2231utf8(self):
        disptype, params = parse_content_disposition(
            "attachment; filename*=UTF-8''foo-%c3%a4-%e2%82%ac.html")
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename*': 'foo-ä-€.html'}, params)

    def test_attwithfn2231noc(self):
        disptype, params = parse_content_disposition(
            "attachment; filename*=''foo-%c3%a4-%e2%82%ac.html")
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename*': 'foo-ä-€.html'}, params)

    def test_attwithfn2231utf8comp(self):
        disptype, params = parse_content_disposition(
            "attachment; filename*=UTF-8''foo-a%cc%88.html")
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename*': 'foo-ä.html'}, params)

    @unittest.skip('should raise decoding error: %82 is invalid for latin1')
    def test_attwithfn2231utf8_bad(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionParam):
            disptype, params = parse_content_disposition(
                "attachment; filename*=iso-8859-1''foo-%c3%a4-%e2%82%ac.html")
        self.assertEqual('attachment', disptype)
        self.assertEqual({}, params)

    @unittest.skip('should raise decoding error: %E4 is invalid for utf-8')
    def test_attwithfn2231iso_bad(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionParam):
            disptype, params = parse_content_disposition(
                "attachment; filename*=utf-8''foo-%E4.html")
        self.assertEqual('attachment', disptype)
        self.assertEqual({}, params)

    def test_attwithfn2231ws1(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionParam):
            disptype, params = parse_content_disposition(
                "attachment; filename *=UTF-8''foo-%c3%a4.html")
        self.assertEqual('attachment', disptype)
        self.assertEqual({}, params)

    def test_attwithfn2231ws2(self):
        disptype, params = parse_content_disposition(
            "attachment; filename*= UTF-8''foo-%c3%a4.html")
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename*': 'foo-ä.html'}, params)

    def test_attwithfn2231ws3(self):
        disptype, params = parse_content_disposition(
            "attachment; filename* =UTF-8''foo-%c3%a4.html")
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename*': 'foo-ä.html'}, params)

    def test_attwithfn2231quot(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionParam):
            disptype, params = parse_content_disposition(
                "attachment; filename*=\"UTF-8''foo-%c3%a4.html\"")
        self.assertEqual('attachment', disptype)
        self.assertEqual({}, params)

    def test_attwithfn2231quot2(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionParam):
            disptype, params = parse_content_disposition(
                "attachment; filename*=\"foo%20bar.html\"")
        self.assertEqual('attachment', disptype)
        self.assertEqual({}, params)

    def test_attwithfn2231singleqmissing(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionParam):
            disptype, params = parse_content_disposition(
                "attachment; filename*=UTF-8'foo-%c3%a4.html")
        self.assertEqual('attachment', disptype)
        self.assertEqual({}, params)

    @unittest.skip('urllib.parse.unquote is tolerate to standalone % chars')
    def test_attwithfn2231nbadpct1(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionParam):
            disptype, params = parse_content_disposition(
                "attachment; filename*=UTF-8''foo%")
        self.assertEqual('attachment', disptype)
        self.assertEqual({}, params)

    @unittest.skip('urllib.parse.unquote is tolerate to standalone % chars')
    def test_attwithfn2231nbadpct2(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionParam):
            disptype, params = parse_content_disposition(
                "attachment; filename*=UTF-8''f%oo.html")
        self.assertEqual('attachment', disptype)
        self.assertEqual({}, params)

    def test_attwithfn2231dpct(self):
        disptype, params = parse_content_disposition(
            "attachment; filename*=UTF-8''A-%2541.html")
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename*': 'A-%41.html'}, params)

    def test_attwithfn2231abspathdisguised(self):
        disptype, params = parse_content_disposition(
            "attachment; filename*=UTF-8''%5cfoo.html")
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename*': '\\foo.html'}, params)

    def test_attfncont(self):
        disptype, params = parse_content_disposition(
            'attachment; filename*0="foo."; filename*1="html"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename*0': 'foo.',
                          'filename*1': 'html'}, params)

    def test_attfncontqs(self):
        disptype, params = parse_content_disposition(
            r'attachment; filename*0="foo"; filename*1="\b\a\r.html"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename*0': 'foo',
                          'filename*1': 'bar.html'}, params)

    def test_attfncontenc(self):
        disptype, params = parse_content_disposition(
            'attachment; filename*0*=UTF-8''foo-%c3%a4; filename*1=".html"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename*0*': 'UTF-8''foo-%c3%a4',
                          'filename*1': '.html'}, params)

    def test_attfncontlz(self):
        disptype, params = parse_content_disposition(
            'attachment; filename*0="foo"; filename*01="bar"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename*0': 'foo',
                          'filename*01': 'bar'}, params)

    def test_attfncontnc(self):
        disptype, params = parse_content_disposition(
            'attachment; filename*0="foo"; filename*2="bar"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename*0': 'foo',
                          'filename*2': 'bar'}, params)

    def test_attfnconts1(self):
        disptype, params = parse_content_disposition(
            'attachment; filename*0="foo."; filename*2="html"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename*0': 'foo.',
                          'filename*2': 'html'}, params)

    def test_attfncontord(self):
        disptype, params = parse_content_disposition(
            'attachment; filename*1="bar"; filename*0="foo"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename*0': 'foo',
                          'filename*1': 'bar'}, params)

    def test_attfnboth(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="foo-ae.html";'
            " filename*=UTF-8''foo-%c3%a4.html")
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename': 'foo-ae.html',
                          'filename*': 'foo-ä.html'}, params)

    def test_attfnboth2(self):
        disptype, params = parse_content_disposition(
            "attachment; filename*=UTF-8''foo-%c3%a4.html;"
            ' filename="foo-ae.html"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename': 'foo-ae.html',
                          'filename*': 'foo-ä.html'}, params)

    def test_attfnboth3(self):
        disptype, params = parse_content_disposition(
            "attachment; filename*0*=ISO-8859-15''euro-sign%3d%a4;"
            " filename*=ISO-8859-1''currency-sign%3d%a4")
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename*': 'currency-sign=¤',
                          'filename*0*': "ISO-8859-15''euro-sign%3d%a4"},
                         params)

    def test_attnewandfn(self):
        disptype, params = parse_content_disposition(
            'attachment; foobar=x; filename="foo.html"')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'foobar': 'x',
                          'filename': 'foo.html'}, params)

    def test_attrfc2047token(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; filename==?ISO-8859-1?Q?foo-=E4.html?=')
        self.assertEqual(None, disptype)
        self.assertEqual({}, params)

    def test_attrfc2047quoted(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="=?ISO-8859-1?Q?foo-=E4.html?="')
        self.assertEqual('attachment', disptype)
        self.assertEqual({'filename': '=?ISO-8859-1?Q?foo-=E4.html?='}, params)

    def test_bad_continuous_param(self):
        with self.assertWarns(aiohttp.multipart.BadContentDispositionParam):
            disptype, params = parse_content_disposition(
                'attachment; filename*0=foo bar')
        self.assertEqual('attachment', disptype)
        self.assertEqual({}, params)


class ContentDispositionFilenameTestCase(unittest.TestCase):
    # http://greenbytes.de/tech/tc2231/

    def test_no_filename(self):
        self.assertIsNone(content_disposition_filename({}))
        self.assertIsNone(content_disposition_filename({'foo': 'bar'}))

    def test_filename(self):
        params = {'filename': 'foo.html'}
        self.assertEqual('foo.html', content_disposition_filename(params))

    def test_filename_ext(self):
        params = {'filename*': 'файл.html'}
        self.assertEqual('файл.html', content_disposition_filename(params))

    def test_attfncont(self):
        params = {'filename*0': 'foo.', 'filename*1': 'html'}
        self.assertEqual('foo.html', content_disposition_filename(params))

    def test_attfncontqs(self):
        params = {'filename*0': 'foo', 'filename*1': 'bar.html'}
        self.assertEqual('foobar.html', content_disposition_filename(params))

    def test_attfncontenc(self):
        params = {'filename*0*': "UTF-8''foo-%c3%a4",
                  'filename*1': '.html'}
        self.assertEqual('foo-ä.html', content_disposition_filename(params))

    def test_attfncontlz(self):
        params = {'filename*0': 'foo',
                  'filename*01': 'bar'}
        self.assertEqual('foo', content_disposition_filename(params))

    def test_attfncontnc(self):
        params = {'filename*0': 'foo',
                  'filename*2': 'bar'}
        self.assertEqual('foo', content_disposition_filename(params))

    def test_attfnconts1(self):
        params = {'filename*1': 'foo',
                  'filename*2': 'bar'}
        self.assertEqual(None, content_disposition_filename(params))

    def test_attfnboth(self):
        params = {'filename': 'foo-ae.html',
                  'filename*': 'foo-ä.html'}
        self.assertEqual('foo-ä.html', content_disposition_filename(params))

    def test_attfnboth3(self):
        params = {'filename*0*': "ISO-8859-15''euro-sign%3d%a4",
                  'filename*': 'currency-sign=¤'}
        self.assertEqual('currency-sign=¤',
                         content_disposition_filename(params))

    def test_attrfc2047quoted(self):
        params = {'filename': '=?ISO-8859-1?Q?foo-=E4.html?='}
        self.assertEqual('=?ISO-8859-1?Q?foo-=E4.html?=',
                         content_disposition_filename(params))


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
