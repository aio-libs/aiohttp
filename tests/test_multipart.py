import asyncio
import functools
import io
import os
import unittest
import unittest.mock as mock
import zlib

import aiohttp.multipart
from aiohttp.helpers import parse_mimetype
from aiohttp.hdrs import (
    CONTENT_DISPOSITION,
    CONTENT_ENCODING,
    CONTENT_TRANSFER_ENCODING,
    CONTENT_TYPE
)
from aiohttp.multipart import (
    parse_content_disposition,
    content_disposition_filename
)


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
        fut = asyncio.Future(loop=self.loop)
        fut.set_result(obj)
        return fut


class Response(object):

    def __init__(self, headers, content):
        self.headers = headers
        self.content = content


class Stream(object):

    def __init__(self, content):
        self.content = io.BytesIO(content)

    @asyncio.coroutine
    def read(self, size=None):
        return self.content.read(size)

    @asyncio.coroutine
    def readline(self):
        return self.content.readline()


class StreamWithShortenRead(Stream):

    def __init__(self, content):
        self._first = True
        super().__init__(content)

    @asyncio.coroutine
    def read(self, size=None):
        if size is not None and self._first:
            self._first = False
            size = size // 2
        return (yield from super().read(size))


class MultipartResponseWrapperTestCase(TestCase):

    def setUp(self):
        super().setUp()
        wrapper = aiohttp.multipart.MultipartResponseWrapper(mock.Mock(),
                                                             mock.Mock())
        self.wrapper = wrapper

    def test_at_eof(self):
        self.wrapper.at_eof()
        self.assertTrue(self.wrapper.resp.content.at_eof.called)

    def test_next(self):
        self.wrapper.stream.next.return_value = self.future(b'')
        self.wrapper.stream.at_eof.return_value = False
        yield from self.wrapper.next()
        self.assertTrue(self.wrapper.stream.next.called)

    def test_release(self):
        self.wrapper.resp.release.return_value = self.future(None)
        yield from self.wrapper.release()
        self.assertTrue(self.wrapper.resp.release.called)

    def test_release_when_stream_at_eof(self):
        self.wrapper.resp.release.return_value = self.future(None)
        self.wrapper.stream.next.return_value = self.future(b'')
        self.wrapper.stream.at_eof.return_value = True
        yield from self.wrapper.next()
        self.assertTrue(self.wrapper.stream.next.called)
        self.assertTrue(self.wrapper.resp.release.called)


class PartReaderTestCase(TestCase):

    def setUp(self):
        super().setUp()
        self.boundary = b'--:'

    def test_next(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {}, Stream(b'Hello, world!\r\n--:'))
        result = yield from obj.next()
        self.assertEqual(b'Hello, world!', result)
        self.assertTrue(obj.at_eof())

    def test_next_next(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {}, Stream(b'Hello, world!\r\n--:'))
        result = yield from obj.next()
        self.assertEqual(b'Hello, world!', result)
        self.assertTrue(obj.at_eof())
        result = yield from obj.next()
        self.assertIsNone(result)

    def test_read(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {}, Stream(b'Hello, world!\r\n--:'))
        result = yield from obj.read()
        self.assertEqual(b'Hello, world!', result)
        self.assertTrue(obj.at_eof())

    def test_read_chunk_at_eof(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {}, Stream(b'--:'))
        obj._at_eof = True
        result = yield from obj.read_chunk()
        self.assertEqual(b'', result)

    def test_read_chunk_requires_content_length(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {}, Stream(b'Hello, world!\r\n--:'))
        with self.assertRaises(AssertionError):
            yield from obj.read_chunk()

    def test_read_chunk_properly_counts_read_bytes(self):
        expected = b'.' * 10
        size = len(expected)
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {'CONTENT-LENGTH': size},
            StreamWithShortenRead(expected + b'\r\n--:--'))
        result = bytearray()
        while True:
            chunk = yield from obj.read_chunk()
            if not chunk:
                break
            result.extend(chunk)
        self.assertEqual(size, len(result))
        self.assertEqual(b'.' * size, result)
        self.assertTrue(obj.at_eof())

    def test_read_does_reads_boundary(self):
        stream = Stream(b'Hello, world!\r\n--:')
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {}, stream)
        result = yield from obj.read()
        self.assertEqual(b'Hello, world!', result)
        self.assertEqual(b'', (yield from stream.read()))
        self.assertEqual([b'--:'], list(obj._unread))

    def test_multiread(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {}, Stream(b'Hello,\r\n--:\r\n\r\nworld!\r\n--:--'))
        result = yield from obj.read()
        self.assertEqual(b'Hello,', result)
        result = yield from obj.read()
        self.assertEqual(b'', result)
        self.assertTrue(obj.at_eof())

    def test_read_multiline(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {}, Stream(b'Hello\n,\r\nworld!\r\n--:--'))
        result = yield from obj.read()
        self.assertEqual(b'Hello\n,\r\nworld!', result)
        result = yield from obj.read()
        self.assertEqual(b'', result)
        self.assertTrue(obj.at_eof())

    def test_read_respects_content_length(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {'CONTENT-LENGTH': 100500},
            Stream(b'.' * 100500 + b'\r\n--:--'))
        result = yield from obj.read()
        self.assertEqual(b'.' * 100500, result)
        self.assertTrue(obj.at_eof())

    def test_read_with_content_encoding_gzip(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_ENCODING: 'gzip'},
            Stream(b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x0b\xc9\xccMU'
                   b'(\xc9W\x08J\xcdI\xacP\x04\x00$\xfb\x9eV\x0e\x00\x00\x00'
                   b'\r\n--:--'))
        result = yield from obj.read(decode=True)
        self.assertEqual(b'Time to Relax!', result)

    def test_read_with_content_encoding_deflate(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_ENCODING: 'deflate'},
            Stream(b'\x0b\xc9\xccMU(\xc9W\x08J\xcdI\xacP\x04\x00\r\n--:--'))
        result = yield from obj.read(decode=True)
        self.assertEqual(b'Time to Relax!', result)

    def test_read_with_content_encoding_identity(self):
        thing = (b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x0b\xc9\xccMU'
                 b'(\xc9W\x08J\xcdI\xacP\x04\x00$\xfb\x9eV\x0e\x00\x00\x00'
                 b'\r\n')
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_ENCODING: 'identity'},
            Stream(thing + b'--:--'))
        result = yield from obj.read(decode=True)
        self.assertEqual(thing[:-2], result)

    def test_read_with_content_encoding_unknown(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_ENCODING: 'snappy'},
            Stream(b'\x0e4Time to Relax!\r\n--:--'))
        with self.assertRaises(RuntimeError):
            yield from obj.read(decode=True)

    def test_read_with_content_transfer_encoding_base64(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_TRANSFER_ENCODING: 'base64'},
            Stream(b'VGltZSB0byBSZWxheCE=\r\n--:--'))
        result = yield from obj.read(decode=True)
        self.assertEqual(b'Time to Relax!', result)

    def test_read_with_content_transfer_encoding_quoted_printable(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_TRANSFER_ENCODING: 'quoted-printable'},
            Stream(b'=D0=9F=D1=80=D0=B8=D0=B2=D0=B5=D1=82,'
                   b' =D0=BC=D0=B8=D1=80!\r\n--:--'))
        result = yield from obj.read(decode=True)
        self.assertEqual(b'\xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82,'
                         b' \xd0\xbc\xd0\xb8\xd1\x80!', result)

    def test_read_with_content_transfer_encoding_unknown(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_TRANSFER_ENCODING: 'unknown'},
            Stream(b'\x0e4Time to Relax!\r\n--:--'))
        with self.assertRaises(RuntimeError):
            yield from obj.read(decode=True)

    def test_read_text(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {}, Stream(b'Hello, world!\r\n--:--'))
        result = yield from obj.text()
        self.assertEqual('Hello, world!', result)

    def test_read_text_encoding(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {},
            Stream('Привет, Мир!\r\n--:--'.encode('cp1251')))
        result = yield from obj.text(encoding='cp1251')
        self.assertEqual('Привет, Мир!', result)

    def test_read_text_guess_encoding(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_TYPE: 'text/plain;charset=cp1251'},
            Stream('Привет, Мир!\r\n--:--'.encode('cp1251')))
        result = yield from obj.text()
        self.assertEqual('Привет, Мир!', result)

    def test_read_text_compressed(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_ENCODING: 'deflate',
                            CONTENT_TYPE: 'text/plain'},
            Stream(b'\x0b\xc9\xccMU(\xc9W\x08J\xcdI\xacP\x04\x00\r\n--:--'))
        result = yield from obj.text()
        self.assertEqual('Time to Relax!', result)

    def test_read_text_while_closed(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_TYPE: 'text/plain'}, Stream(b''))
        obj._at_eof = True
        result = yield from obj.text()
        self.assertEqual('', result)

    def test_read_json(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_TYPE: 'application/json'},
            Stream(b'{"test": "passed"}\r\n--:--'))
        result = yield from obj.json()
        self.assertEqual({'test': 'passed'}, result)

    def test_read_json_encoding(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_TYPE: 'application/json'},
            Stream('{"тест": "пассед"}\r\n--:--'.encode('cp1251')))
        result = yield from obj.json(encoding='cp1251')
        self.assertEqual({'тест': 'пассед'}, result)

    def test_read_json_guess_encoding(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_TYPE: 'application/json; charset=cp1251'},
            Stream('{"тест": "пассед"}\r\n--:--'.encode('cp1251')))
        result = yield from obj.json()
        self.assertEqual({'тест': 'пассед'}, result)

    def test_read_json_compressed(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_ENCODING: 'deflate',
                            CONTENT_TYPE: 'application/json'},
            Stream(b'\xabV*I-.Q\xb2RP*H,.NMQ\xaa\x05\x00\r\n--:--'))
        result = yield from obj.json()
        self.assertEqual({'test': 'passed'}, result)

    def test_read_json_while_closed(self):
        stream = Stream(b'')
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_TYPE: 'application/json'}, stream)
        obj._at_eof = True
        result = yield from obj.json()
        self.assertEqual(None, result)

    def test_read_form(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_TYPE: 'application/x-www-form-urlencoded'},
            Stream(b'foo=bar&foo=baz&boo=zoo\r\n--:--'))
        result = yield from obj.form()
        self.assertEqual([('foo', 'bar'), ('foo', 'baz'), ('boo', 'zoo')],
                         result)

    def test_read_form_encoding(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {CONTENT_TYPE: 'application/x-www-form-urlencoded'},
            Stream('foo=bar&foo=baz&boo=zoo\r\n--:--'.encode('cp1251')))
        result = yield from obj.form(encoding='cp1251')
        self.assertEqual([('foo', 'bar'), ('foo', 'baz'), ('boo', 'zoo')],
                         result)

    def test_read_form_guess_encoding(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary,
            {CONTENT_TYPE: 'application/x-www-form-urlencoded; charset=utf-8'},
            Stream('foo=bar&foo=baz&boo=zoo\r\n--:--'.encode('utf-8')))
        result = yield from obj.form()
        self.assertEqual([('foo', 'bar'), ('foo', 'baz'), ('boo', 'zoo')],
                         result)

    def test_read_form_while_closed(self):
        stream = Stream(b'')
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary,
            {CONTENT_TYPE: 'application/x-www-form-urlencoded'}, stream)
        obj._at_eof = True
        result = yield from obj.form()
        self.assertEqual(None, result)

    def test_release(self):
        stream = Stream(b'Hello,\r\n--:\r\n\r\nworld!\r\n--:--')
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {}, stream)
        yield from obj.release()
        self.assertTrue(obj.at_eof())
        self.assertEqual(b'\r\nworld!\r\n--:--', stream.content.read())
        self.assertEqual([b'--:\r\n'], list(obj._unread))

    def test_release_respects_content_length(self):
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {'CONTENT-LENGTH': 100500},
            Stream(b'.' * 100500 + b'\r\n--:--'))
        result = yield from obj.release()
        self.assertIsNone(result)
        self.assertTrue(obj.at_eof())

    def test_release_release(self):
        stream = Stream(b'Hello,\r\n--:\r\n\r\nworld!\r\n--:--')
        obj = aiohttp.multipart.BodyPartReader(
            self.boundary, {}, stream)
        yield from obj.release()
        yield from obj.release()
        self.assertEqual(b'\r\nworld!\r\n--:--', stream.content.read())
        self.assertEqual([b'--:\r\n'], list(obj._unread))

    def test_filename(self):
        part = aiohttp.multipart.BodyPartReader(
            self.boundary,
            {CONTENT_DISPOSITION: 'attachment; filename=foo.html'},
            None)
        self.assertEqual('foo.html', part.filename)


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

    def test_emit_next(self):
        reader = aiohttp.multipart.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b'--:\r\n\r\necho\r\n--:--'))
        res = yield from reader.next()
        self.assertIsInstance(res, reader.part_reader_cls)

    def test_invalid_boundary(self):
        reader = aiohttp.multipart.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b'---:\r\n\r\necho\r\n---:--'))
        with self.assertRaises(ValueError):
            yield from reader.next()

    def test_release(self):
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
                   b'--:--'))
        yield from reader.release()
        self.assertTrue(reader.at_eof())

    def test_release_release(self):
        reader = aiohttp.multipart.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b'--:\r\n\r\necho\r\n--:--'))
        yield from reader.release()
        self.assertTrue(reader.at_eof())
        yield from reader.release()
        self.assertTrue(reader.at_eof())

    def test_release_next(self):
        reader = aiohttp.multipart.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b'--:\r\n\r\necho\r\n--:--'))
        yield from reader.release()
        self.assertTrue(reader.at_eof())
        res = yield from reader.next()
        self.assertIsNone(res)

    def test_second_next_releases_previous_object(self):
        reader = aiohttp.multipart.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b'--:\r\n'
                   b'\r\n'
                   b'test\r\n'
                   b'--:\r\n'
                   b'\r\n'
                   b'passed\r\n'
                   b'--:--'))
        first = yield from reader.next()
        self.assertIsInstance(first, aiohttp.multipart.BodyPartReader)
        second = yield from reader.next()
        self.assertTrue(first.at_eof())
        self.assertFalse(second.at_eof())

    def test_release_without_read_the_last_object(self):
        reader = aiohttp.multipart.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b'--:\r\n'
                   b'\r\n'
                   b'test\r\n'
                   b'--:\r\n'
                   b'\r\n'
                   b'passed\r\n'
                   b'--:--'))
        first = yield from reader.next()
        second = yield from reader.next()
        third = yield from reader.next()
        self.assertTrue(first.at_eof())
        self.assertTrue(second.at_eof())
        self.assertTrue(second.at_eof())
        self.assertIsNone(third)

    def test_read_chunk_doesnt_breaks_reader(self):
        reader = aiohttp.multipart.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary=":"'},
            Stream(b'--:\r\n'
                   b'Content-Length: 4\r\n\r\n'
                   b'test'
                   b'\r\n--:\r\n'
                   b'Content-Length: 6\r\n\r\n'
                   b'passed'
                   b'\r\n--:--'))
        while True:
            part = yield from reader.next()
            if part is None:
                break
            while not part.at_eof():
                yield from part.read_chunk(3)


class BodyPartWriterTestCase(unittest.TestCase):

    def setUp(self):
        self.part = aiohttp.multipart.BodyPartWriter(b'')

    def test_guess_content_length(self):
        self.part.headers[CONTENT_TYPE] = 'text/plain; charset=utf-8'
        self.assertIsNone(self.part._guess_content_length({}))
        self.assertIsNone(self.part._guess_content_length(object()))
        self.assertEqual(3,
                         self.part._guess_content_length(io.BytesIO(b'foo')))
        self.assertEqual(3,
                         self.part._guess_content_length(io.StringIO('foo')))
        self.assertEqual(6,
                         self.part._guess_content_length(io.StringIO('мяу')))
        self.assertEqual(3, self.part._guess_content_length(b'bar'))
        self.assertEqual(12, self.part._guess_content_length('пассед'))
        with open(__file__, 'rb') as f:
            self.assertEqual(os.fstat(f.fileno()).st_size,
                             self.part._guess_content_length(f))

    def test_guess_content_type(self):
        default = 'application/octet-stream'
        self.assertEqual(default, self.part._guess_content_type(b'foo'))
        self.assertEqual('text/plain; charset=utf-8',
                         self.part._guess_content_type('foo'))

        here = os.path.dirname(__file__)
        filename = os.path.join(here, 'software_development_in_picture.jpg')

        with open(filename, 'rb') as f:
            self.assertEqual('image/jpeg',
                             self.part._guess_content_type(f))

    def test_guess_filename(self):
        class Named:
            name = 'foo'
        self.assertIsNone(self.part._guess_filename({}))
        self.assertIsNone(self.part._guess_filename(object()))
        self.assertIsNone(self.part._guess_filename(io.BytesIO(b'foo')))
        self.assertIsNone(self.part._guess_filename(Named()))
        with open(__file__, 'rb') as f:
            self.assertEqual(os.path.basename(f.name),
                             self.part._guess_filename(f))

    def test_autoset_content_disposition(self):
        self.part.obj = open(__file__, 'rb')
        self.addCleanup(self.part.obj.close)
        self.part._fill_headers_with_defaults()
        self.assertIn(CONTENT_DISPOSITION, self.part.headers)
        fname = os.path.basename(self.part.obj.name)
        self.assertEqual(
            'attachment; filename="{0}"; filename*=utf-8\'\'{0}'.format(fname),
            self.part.headers[CONTENT_DISPOSITION])

    def test_set_content_disposition(self):
        self.part.set_content_disposition('attachment', foo='bar')
        self.assertEqual(
            'attachment; foo=bar',
            self.part.headers[CONTENT_DISPOSITION])

    def test_set_content_disposition_bad_type(self):
        with self.assertRaises(ValueError):
            self.part.set_content_disposition('foo bar')
        with self.assertRaises(ValueError):
            self.part.set_content_disposition('тест')
        with self.assertRaises(ValueError):
            self.part.set_content_disposition('foo\x00bar')
        with self.assertRaises(ValueError):
            self.part.set_content_disposition('')

    def test_set_content_disposition_bad_param(self):
        with self.assertRaises(ValueError):
            self.part.set_content_disposition('inline', **{'foo bar': 'baz'})
        with self.assertRaises(ValueError):
            self.part.set_content_disposition('inline', **{'тест': 'baz'})
        with self.assertRaises(ValueError):
            self.part.set_content_disposition('inline', **{'': 'baz'})
        with self.assertRaises(ValueError):
            self.part.set_content_disposition('inline',
                                              **{'foo\x00bar': 'baz'})

    def test_serialize_bytes(self):
        self.assertEqual(b'foo', next(self.part._serialize_bytes(b'foo')))

    def test_serialize_str(self):
        self.assertEqual(b'foo', next(self.part._serialize_str('foo')))

    def test_serialize_str_custom_encoding(self):
        self.part.headers[CONTENT_TYPE] = \
            'text/plain;charset=cp1251'
        self.assertEqual('привет'.encode('cp1251'),
                         next(self.part._serialize_str('привет')))

    def test_serialize_io(self):
        self.assertEqual(b'foo',
                         next(self.part._serialize_io(io.BytesIO(b'foo'))))
        self.assertEqual(b'foo',
                         next(self.part._serialize_io(io.StringIO('foo'))))

    def test_serialize_io_chunk(self):
        flo = io.BytesIO(b'foobarbaz')
        self.part._chunk_size = 3
        self.assertEqual([b'foo', b'bar', b'baz'],
                         list(self.part._serialize_io(flo)))

    def test_serialize_json(self):
        self.assertEqual(b'{"\\u043f\\u0440\\u0438\\u0432\\u0435\\u0442":'
                         b' "\\u043c\\u0438\\u0440"}',
                         next(self.part._serialize_json({'привет': 'мир'})))

    def test_serialize_form(self):
        data = [('foo', 'bar'), ('foo', 'baz'), ('boo', 'zoo')]
        self.assertEqual(b'foo=bar&foo=baz&boo=zoo',
                         next(self.part._serialize_form(data)))

    def test_serialize_form_dict(self):
        data = {'hello': 'мир'}
        self.assertEqual(b'hello=%D0%BC%D0%B8%D1%80',
                         next(self.part._serialize_form(data)))

    def test_serialize_multipart(self):
        multipart = aiohttp.multipart.MultipartWriter(boundary=':')
        multipart.append('foo-bar-baz')
        multipart.append_json({'test': 'passed'})
        self.assertEqual(
            [b'--:\r\n',
             b'CONTENT-TYPE: text/plain; charset=utf-8\r\n'
             b'CONTENT-LENGTH: 11',
             b'\r\n\r\n',
             b'foo-bar-baz',
             b'\r\n',
             b'--:\r\n',
             b'CONTENT-TYPE: application/json',
             b'\r\n\r\n',
             b'{"test": "passed"}',
             b'\r\n',
             b'--:--\r\n',
             b''],
            list(self.part._serialize_multipart(multipart))
        )

    def test_serialize_default(self):
        with self.assertRaises(TypeError):
            self.part.obj = object()
            list(self.part.serialize())
        with self.assertRaises(TypeError):
            next(self.part._serialize_default(object()))

    def test_serialize_with_content_encoding_gzip(self):
        part = aiohttp.multipart.BodyPartWriter(
            'Time to Relax!', {CONTENT_ENCODING: 'gzip'})
        stream = part.serialize()
        self.assertEqual(b'CONTENT-ENCODING: gzip\r\n'
                         b'CONTENT-TYPE: text/plain; charset=utf-8',
                         next(stream))
        self.assertEqual(b'\r\n\r\n', next(stream))

        result = b''.join(stream)

        decompressor = zlib.decompressobj(wbits=16+zlib.MAX_WBITS)
        data = decompressor.decompress(result)
        self.assertEqual(b'Time to Relax!', data)
        self.assertIsNone(next(stream, None))

    def test_serialize_with_content_encoding_deflate(self):
        part = aiohttp.multipart.BodyPartWriter(
            'Time to Relax!', {CONTENT_ENCODING: 'deflate'})
        stream = part.serialize()
        self.assertEqual(b'CONTENT-ENCODING: deflate\r\n'
                         b'CONTENT-TYPE: text/plain; charset=utf-8',
                         next(stream))
        self.assertEqual(b'\r\n\r\n', next(stream))

        thing = b'\x0b\xc9\xccMU(\xc9W\x08J\xcdI\xacP\x04\x00\r\n'
        self.assertEqual(thing, b''.join(stream))
        self.assertIsNone(next(stream, None))

    def test_serialize_with_content_encoding_identity(self):
        thing = b'\x0b\xc9\xccMU(\xc9W\x08J\xcdI\xacP\x04\x00'
        part = aiohttp.multipart.BodyPartWriter(
            thing, {CONTENT_ENCODING: 'identity'})
        stream = part.serialize()
        self.assertEqual(b'CONTENT-ENCODING: identity\r\n'
                         b'CONTENT-TYPE: application/octet-stream\r\n'
                         b'CONTENT-LENGTH: 16',
                         next(stream))
        self.assertEqual(b'\r\n\r\n', next(stream))

        self.assertEqual(thing, next(stream))
        self.assertEqual(b'\r\n', next(stream))
        self.assertIsNone(next(stream, None))

    def test_serialize_with_content_encoding_unknown(self):
        part = aiohttp.multipart.BodyPartWriter(
            'Time to Relax!', {CONTENT_ENCODING: 'snappy'})
        with self.assertRaises(RuntimeError):
            list(part.serialize())

    def test_serialize_with_content_transfer_encoding_base64(self):
        part = aiohttp.multipart.BodyPartWriter(
            'Time to Relax!', {CONTENT_TRANSFER_ENCODING: 'base64'})
        stream = part.serialize()
        self.assertEqual(b'CONTENT-TRANSFER-ENCODING: base64\r\n'
                         b'CONTENT-TYPE: text/plain; charset=utf-8',
                         next(stream))
        self.assertEqual(b'\r\n\r\n', next(stream))

        self.assertEqual(b'VGltZSB0byBSZWxh', next(stream))
        self.assertEqual(b'eCE=', next(stream))
        self.assertEqual(b'\r\n', next(stream))
        self.assertIsNone(next(stream, None))

    def test_serialize_io_with_content_transfer_encoding_base64(self):
        part = aiohttp.multipart.BodyPartWriter(
            io.BytesIO(b'Time to Relax!'),
            {CONTENT_TRANSFER_ENCODING: 'base64'})
        part._chunk_size = 6
        stream = part.serialize()
        self.assertEqual(b'CONTENT-TRANSFER-ENCODING: base64\r\n'
                         b'CONTENT-TYPE: application/octet-stream',
                         next(stream))
        self.assertEqual(b'\r\n\r\n', next(stream))

        self.assertEqual(b'VGltZSB0', next(stream))
        self.assertEqual(b'byBSZWxh', next(stream))
        self.assertEqual(b'eCE=', next(stream))
        self.assertEqual(b'\r\n', next(stream))
        self.assertIsNone(next(stream, None))

    def test_serialize_with_content_transfer_encoding_quote_printable(self):
        part = aiohttp.multipart.BodyPartWriter(
            'Привет, мир!', {CONTENT_TRANSFER_ENCODING: 'quoted-printable'})
        stream = part.serialize()
        self.assertEqual(b'CONTENT-TRANSFER-ENCODING: quoted-printable\r\n'
                         b'CONTENT-TYPE: text/plain; charset=utf-8',
                         next(stream))
        self.assertEqual(b'\r\n\r\n', next(stream))

        self.assertEqual(b'=D0=9F=D1=80=D0=B8=D0=B2=D0=B5=D1=82,'
                         b' =D0=BC=D0=B8=D1=80!', next(stream))
        self.assertEqual(b'\r\n', next(stream))
        self.assertIsNone(next(stream, None))

    def test_serialize_with_content_transfer_encoding_unknown(self):
        part = aiohttp.multipart.BodyPartWriter(
            'Time to Relax!', {CONTENT_TRANSFER_ENCODING: 'unknown'})
        with self.assertRaises(RuntimeError):
            list(part.serialize())

    def test_filename(self):
        self.part.set_content_disposition('related', filename='foo.html')
        self.assertEqual('foo.html', self.part.filename)


class MultipartWriterTestCase(unittest.TestCase):

    def setUp(self):
        self.writer = aiohttp.multipart.MultipartWriter(boundary=':')

    def test_default_subtype(self):
        mtype, stype, *_ = parse_mimetype(
            self.writer.headers.get(CONTENT_TYPE))
        self.assertEqual('multipart', mtype)
        self.assertEqual('mixed', stype)

    def test_bad_boundary(self):
        with self.assertRaises(ValueError):
            aiohttp.multipart.MultipartWriter(boundary='тест')

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
        self.assertIsInstance(self.writer.parts[0],
                              self.writer.part_writer_cls)

    def test_append_with_headers(self):
        self.writer.append('hello, world!', {'x-foo': 'bar'})
        self.assertEqual(1, len(self.writer))
        self.assertIn('x-foo', self.writer.parts[0].headers)
        self.assertEqual(self.writer.parts[0].headers['x-foo'], 'bar')

    def test_append_json(self):
        self.writer.append_json({'foo': 'bar'})
        self.assertEqual(1, len(self.writer))
        part = self.writer.parts[0]
        self.assertEqual(part.headers[CONTENT_TYPE], 'application/json')

    def test_append_part(self):
        part = aiohttp.multipart.BodyPartWriter('test',
                                                {CONTENT_TYPE: 'text/plain'})
        self.writer.append(part, {CONTENT_TYPE: 'test/passed'})
        self.assertEqual(1, len(self.writer))
        part = self.writer.parts[0]
        self.assertEqual(part.headers[CONTENT_TYPE], 'test/passed')

    def test_append_json_overrides_content_type(self):
        self.writer.append_json({'foo': 'bar'}, {CONTENT_TYPE: 'test/passed'})
        self.assertEqual(1, len(self.writer))
        part = self.writer.parts[0]
        self.assertEqual(part.headers[CONTENT_TYPE], 'application/json')

    def test_append_form(self):
        self.writer.append_form({'foo': 'bar'}, {CONTENT_TYPE: 'test/passed'})
        self.assertEqual(1, len(self.writer))
        part = self.writer.parts[0]
        self.assertEqual(part.headers[CONTENT_TYPE],
                         'application/x-www-form-urlencoded')

    def test_serialize(self):
        self.assertEqual([b''], list(self.writer.serialize()))

    def test_with(self):
        with aiohttp.multipart.MultipartWriter(boundary=':') as writer:
            writer.append('foo')
            writer.append(b'bar')
            writer.append_json({'baz': True})
        self.assertEqual(3, len(writer))


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
