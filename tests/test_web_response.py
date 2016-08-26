import asyncio
import datetime
import json
import re
from unittest import mock

import pytest
from multidict import CIMultiDict

from aiohttp import hdrs, signals
from aiohttp.protocol import (HttpVersion, HttpVersion10, HttpVersion11,
                              RawRequestMessage)
from aiohttp.web import (ContentCoding, Request, Response, StreamResponse,
                         json_response)


def make_request(method, path, headers=CIMultiDict(),
                 version=HttpVersion11, **kwargs):
    message = RawRequestMessage(method, path, version, headers,
                                [(k.encode('utf-8'), v.encode('utf-8'))
                                 for k, v in headers.items()],
                                False, False)
    return request_from_message(message, **kwargs)


def request_from_message(message, **kwargs):
    app = kwargs.get('app') or mock.Mock()
    app._debug = False
    app.on_response_prepare = signals.Signal(app)
    payload = mock.Mock()
    transport = mock.Mock()
    reader = mock.Mock()
    writer = kwargs.get('writer') or mock.Mock()
    req = Request(app, message, payload,
                  transport, reader, writer)
    return req


def test_stream_response_ctor():
    resp = StreamResponse()
    assert 200 == resp.status
    assert resp.keep_alive is None


def test_content_length():
    resp = StreamResponse()
    assert resp.content_length is None


def test_content_length_setter():
    resp = StreamResponse()

    resp.content_length = 234
    assert 234 == resp.content_length


def test_drop_content_length_header_on_setting_len_to_None():
    resp = StreamResponse()

    resp.content_length = 1
    assert "1" == resp.headers['Content-Length']
    resp.content_length = None
    assert 'Content-Length' not in resp.headers


def test_set_content_length_to_None_on_non_set():
    resp = StreamResponse()

    resp.content_length = None
    assert 'Content-Length' not in resp.headers
    resp.content_length = None
    assert 'Content-Length' not in resp.headers


def test_setting_content_type():
    resp = StreamResponse()

    resp.content_type = 'text/html'
    assert 'text/html' == resp.headers['content-type']


def test_setting_charset():
    resp = StreamResponse()

    resp.content_type = 'text/html'
    resp.charset = 'koi8-r'
    assert 'text/html; charset=koi8-r' == resp.headers['content-type']


def test_default_charset():
    resp = StreamResponse()

    assert resp.charset is None


def test_reset_charset():
    resp = StreamResponse()

    resp.content_type = 'text/html'
    resp.charset = None
    assert resp.charset is None


def test_reset_charset_after_setting():
    resp = StreamResponse()

    resp.content_type = 'text/html'
    resp.charset = 'koi8-r'
    resp.charset = None
    assert resp.charset is None


def test_charset_without_content_type():
    resp = StreamResponse()

    with pytest.raises(RuntimeError):
        resp.charset = 'koi8-r'


def test_last_modified_initial():
    resp = StreamResponse()
    assert resp.last_modified is None


def test_last_modified_string():
    resp = StreamResponse()

    dt = datetime.datetime(1990, 1, 2, 3, 4, 5, 0, datetime.timezone.utc)
    resp.last_modified = 'Mon, 2 Jan 1990 03:04:05 GMT'
    assert resp.last_modified == dt


def test_last_modified_timestamp():
    resp = StreamResponse()

    dt = datetime.datetime(1970, 1, 1, 0, 0, 0, 0, datetime.timezone.utc)

    resp.last_modified = 0
    assert resp.last_modified == dt

    resp.last_modified = 0.0
    assert resp.last_modified == dt


def test_last_modified_datetime():
    resp = StreamResponse()

    dt = datetime.datetime(2001, 2, 3, 4, 5, 6, 0, datetime.timezone.utc)
    resp.last_modified = dt
    assert resp.last_modified == dt


def test_last_modified_reset():
    resp = StreamResponse()

    resp.last_modified = 0
    resp.last_modified = None
    assert resp.last_modified is None


@asyncio.coroutine
def test_start():
    req = make_request('GET', '/')
    resp = StreamResponse()
    assert resp.keep_alive is None

    with mock.patch('aiohttp.web_reqrep.ResponseImpl'):
        msg = yield from resp.prepare(req)

        assert msg.send_headers.called
        msg2 = yield from resp.prepare(req)
        assert msg is msg2

        assert resp.keep_alive

    req2 = make_request('GET', '/')
    with pytest.raises(RuntimeError):
        yield from resp.prepare(req2)


@asyncio.coroutine
def test_chunked_encoding():
    req = make_request('GET', '/')
    resp = StreamResponse()
    assert not resp.chunked

    resp.enable_chunked_encoding()
    assert resp.chunked

    with mock.patch('aiohttp.web_reqrep.ResponseImpl'):
        msg = yield from resp.prepare(req)
        assert msg.chunked


@asyncio.coroutine
def test_chunk_size():
    req = make_request('GET', '/')
    resp = StreamResponse()
    assert not resp.chunked

    resp.enable_chunked_encoding(chunk_size=8192)
    assert resp.chunked

    with mock.patch('aiohttp.web_reqrep.ResponseImpl'):
        msg = yield from resp.prepare(req)
        assert msg.chunked
        msg.add_chunking_filter.assert_called_with(8192)
        assert msg.filter is not None


@asyncio.coroutine
def test_chunked_encoding_forbidden_for_http_10():
    req = make_request('GET', '/', version=HttpVersion10)
    resp = StreamResponse()
    resp.enable_chunked_encoding()

    with pytest.raises(RuntimeError) as ctx:
        yield from resp.prepare(req)
    assert re.match("Using chunked encoding is forbidden for HTTP/1.0",
                    str(ctx.value))


@asyncio.coroutine
def test_compression_no_accept():
    req = make_request('GET', '/')
    resp = StreamResponse()
    assert not resp.chunked

    assert not resp.compression
    resp.enable_compression()
    assert resp.compression

    with mock.patch('aiohttp.web_reqrep.ResponseImpl'):
        msg = yield from resp.prepare(req)
        assert not msg.add_compression_filter.called


@asyncio.coroutine
def test_force_compression_no_accept_backwards_compat():
    req = make_request('GET', '/')
    resp = StreamResponse()
    assert not resp.chunked

    assert not resp.compression
    resp.enable_compression(force=True)
    assert resp.compression

    with mock.patch('aiohttp.web_reqrep.ResponseImpl'):
        msg = yield from resp.prepare(req)
    assert msg.add_compression_filter.called
    assert msg.filter is not None


@asyncio.coroutine
def test_force_compression_false_backwards_compat():
    req = make_request('GET', '/')
    resp = StreamResponse()

    assert not resp.compression
    resp.enable_compression(force=False)
    assert resp.compression

    with mock.patch('aiohttp.web_reqrep.ResponseImpl'):
        msg = yield from resp.prepare(req)
    assert not msg.add_compression_filter.called


@asyncio.coroutine
def test_compression_default_coding():
    req = make_request(
        'GET', '/',
        headers=CIMultiDict({hdrs.ACCEPT_ENCODING: 'gzip, deflate'}))
    resp = StreamResponse()
    assert not resp.chunked

    assert not resp.compression
    resp.enable_compression()
    assert resp.compression

    with mock.patch('aiohttp.web_reqrep.ResponseImpl'):
        msg = yield from resp.prepare(req)

    msg.add_compression_filter.assert_called_with('deflate')
    assert 'deflate' == resp.headers.get(hdrs.CONTENT_ENCODING)
    assert msg.filter is not None


@asyncio.coroutine
def test_force_compression_deflate():
    req = make_request(
        'GET', '/',
        headers=CIMultiDict({hdrs.ACCEPT_ENCODING: 'gzip, deflate'}))
    resp = StreamResponse()

    resp.enable_compression(ContentCoding.deflate)
    assert resp.compression

    with mock.patch('aiohttp.web_reqrep.ResponseImpl'):
        msg = yield from resp.prepare(req)
    msg.add_compression_filter.assert_called_with('deflate')
    assert 'deflate' == resp.headers.get(hdrs.CONTENT_ENCODING)


@asyncio.coroutine
def test_force_compression_no_accept_deflate():
    req = make_request('GET', '/')
    resp = StreamResponse()

    resp.enable_compression(ContentCoding.deflate)
    assert resp.compression

    with mock.patch('aiohttp.web_reqrep.ResponseImpl'):
        msg = yield from resp.prepare(req)
    msg.add_compression_filter.assert_called_with('deflate')
    assert 'deflate' == resp.headers.get(hdrs.CONTENT_ENCODING)


@asyncio.coroutine
def test_force_compression_gzip():
    req = make_request(
        'GET', '/',
        headers=CIMultiDict({hdrs.ACCEPT_ENCODING: 'gzip, deflate'}))
    resp = StreamResponse()

    resp.enable_compression(ContentCoding.gzip)
    assert resp.compression

    with mock.patch('aiohttp.web_reqrep.ResponseImpl'):
        msg = yield from resp.prepare(req)
    msg.add_compression_filter.assert_called_with('gzip')
    assert 'gzip' == resp.headers.get(hdrs.CONTENT_ENCODING)


@asyncio.coroutine
def test_force_compression_no_accept_gzip():
    req = make_request('GET', '/')
    resp = StreamResponse()

    resp.enable_compression(ContentCoding.gzip)
    assert resp.compression

    with mock.patch('aiohttp.web_reqrep.ResponseImpl'):
        msg = yield from resp.prepare(req)
    msg.add_compression_filter.assert_called_with('gzip')
    assert 'gzip' == resp.headers.get(hdrs.CONTENT_ENCODING)


@asyncio.coroutine
def test_delete_content_length_if_compression_enabled():
    req = make_request('GET', '/')
    resp = Response(body=b'answer')
    assert 6 == resp.content_length

    resp.enable_compression(ContentCoding.gzip)

    with mock.patch('aiohttp.web_reqrep.ResponseImpl'):
        yield from resp.prepare(req)
    assert resp.content_length is None


@asyncio.coroutine
def test_write_non_byteish():
    resp = StreamResponse()
    yield from resp.prepare(make_request('GET', '/'))

    with pytest.raises(AssertionError):
        resp.write(123)


def test_write_before_start():
    resp = StreamResponse()

    with pytest.raises(RuntimeError):
        resp.write(b'data')


@asyncio.coroutine
def test_cannot_write_after_eof():
    resp = StreamResponse()
    writer = mock.Mock()
    yield from resp.prepare(make_request('GET', '/', writer=writer))

    resp.write(b'data')
    writer.drain.return_value = ()
    yield from resp.write_eof()
    writer.write.reset_mock()

    with pytest.raises(RuntimeError):
        resp.write(b'next data')
    assert not writer.write.called


@asyncio.coroutine
def test_cannot_write_eof_before_headers():
    resp = StreamResponse()

    with pytest.raises(RuntimeError):
        yield from resp.write_eof()


@asyncio.coroutine
def test_cannot_write_eof_twice():
    resp = StreamResponse()
    writer = mock.Mock()
    yield from resp.prepare(make_request('GET', '/', writer=writer))

    resp.write(b'data')
    writer.drain.return_value = ()
    yield from resp.write_eof()
    assert writer.write.called

    writer.write.reset_mock()
    yield from resp.write_eof()
    assert not writer.write.called


@asyncio.coroutine
def test_write_returns_drain():
    resp = StreamResponse()
    yield from resp.prepare(make_request('GET', '/'))

    assert () == resp.write(b'data')


@asyncio.coroutine
def test_write_returns_empty_tuple_on_empty_data():
    resp = StreamResponse()
    yield from resp.prepare(make_request('GET', '/'))

    assert () == resp.write(b'')


def test_force_close():
    resp = StreamResponse()

    assert resp.keep_alive is None
    resp.force_close()
    assert resp.keep_alive is False


def test_response_cookies():
    resp = StreamResponse()

    assert resp.cookies == {}
    assert str(resp.cookies) == ''

    resp.set_cookie('name', 'value')
    assert str(resp.cookies) == 'Set-Cookie: name=value; Path=/'
    resp.set_cookie('name', 'other_value')
    assert str(resp.cookies) == 'Set-Cookie: name=other_value; Path=/'

    resp.cookies['name'] = 'another_other_value'
    resp.cookies['name']['max-age'] = 10
    assert (str(resp.cookies) ==
            'Set-Cookie: name=another_other_value; Max-Age=10; Path=/')

    resp.del_cookie('name')
    expected = ('Set-Cookie: name=("")?; '
                'expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/')
    assert re.match(expected, str(resp.cookies))

    resp.set_cookie('name', 'value', domain='local.host')
    expected = 'Set-Cookie: name=value; Domain=local.host; Path=/'
    assert str(resp.cookies) == expected


def test_response_cookie_path():
    resp = StreamResponse()

    assert resp.cookies == {}

    resp.set_cookie('name', 'value', path='/some/path')
    assert str(resp.cookies) == 'Set-Cookie: name=value; Path=/some/path'
    resp.set_cookie('name', 'value', expires='123')
    assert (str(resp.cookies) ==
            'Set-Cookie: name=value; expires=123; Path=/')
    resp.set_cookie('name', 'value', domain='example.com',
                    path='/home', expires='123', max_age='10',
                    secure=True, httponly=True, version='2.0')
    assert (str(resp.cookies).lower() == 'set-cookie: name=value; '
            'domain=example.com; '
            'expires=123; '
            'httponly; '
            'max-age=10; '
            'path=/home; '
            'secure; '
            'version=2.0')


def test_response_cookie__issue_del_cookie():
    resp = StreamResponse()

    assert resp.cookies == {}
    assert str(resp.cookies) == ''

    resp.del_cookie('name')
    expected = ('Set-Cookie: name=("")?; '
                'expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/')
    assert re.match(expected, str(resp.cookies))


def test_cookie_set_after_del():
    resp = StreamResponse()

    resp.del_cookie('name')
    resp.set_cookie('name', 'val')
    # check for Max-Age dropped
    expected = 'Set-Cookie: name=val; Path=/'
    assert str(resp.cookies) == expected


def test_set_status_with_reason():
    resp = StreamResponse()

    resp.set_status(200, "Everithing is fine!")
    assert 200 == resp.status
    assert "Everithing is fine!" == resp.reason


@asyncio.coroutine
def test_start_force_close():
    req = make_request('GET', '/')
    resp = StreamResponse()
    resp.force_close()
    assert not resp.keep_alive

    msg = yield from resp.prepare(req)
    assert not resp.keep_alive
    assert msg.closing


@asyncio.coroutine
def test___repr__():
    req = make_request('GET', '/path/to')
    resp = StreamResponse(reason=301)
    yield from resp.prepare(req)
    assert "<StreamResponse 301 GET /path/to >" == repr(resp)


def test___repr__not_started():
    resp = StreamResponse(reason=301)
    assert "<StreamResponse 301 not started>" == repr(resp)


@asyncio.coroutine
def test_keep_alive_http10_default():
    message = RawRequestMessage('GET', '/', HttpVersion10, CIMultiDict(),
                                [], True, False)
    req = request_from_message(message)
    resp = StreamResponse()
    yield from resp.prepare(req)
    assert not resp.keep_alive


@asyncio.coroutine
def test_keep_alive_http10_switched_on():
    headers = CIMultiDict(Connection='keep-alive')
    message = RawRequestMessage('GET', '/', HttpVersion10, headers,
                                [(b'Connection', b'keep-alive')],
                                False, False)
    req = request_from_message(message)
    resp = StreamResponse()
    yield from resp.prepare(req)
    assert resp.keep_alive is True


@asyncio.coroutine
def test_keep_alive_http09():
    headers = CIMultiDict(Connection='keep-alive')
    message = RawRequestMessage('GET', '/', HttpVersion(0, 9), headers,
                                [(b'Connection', b'keep-alive')],
                                False, False)
    req = request_from_message(message)
    resp = StreamResponse()
    yield from resp.prepare(req)
    assert not resp.keep_alive


def test_start_twice():
    req = make_request('GET', '/')
    resp = StreamResponse()

    with pytest.warns(DeprecationWarning):
        impl1 = resp.start(req)
        impl2 = resp.start(req)
        assert impl1 is impl2


@asyncio.coroutine
def test_prepare_calls_signal():
    app = mock.Mock()
    req = make_request('GET', '/', app=app)
    resp = StreamResponse()

    sig = mock.Mock()
    app.on_response_prepare.append(sig)
    yield from resp.prepare(req)

    sig.assert_called_with(req, resp)


def test_default_nodelay():
    resp = StreamResponse()
    assert resp.tcp_nodelay


def test_set_tcp_nodelay_before_start():
    resp = StreamResponse()
    resp.set_tcp_nodelay(False)
    assert not resp.tcp_nodelay
    resp.set_tcp_nodelay(True)
    assert resp.tcp_nodelay


@asyncio.coroutine
def test_set_tcp_nodelay_on_start():
    req = make_request('GET', '/')
    resp = StreamResponse()

    with mock.patch('aiohttp.web_reqrep.ResponseImpl'):
        resp_impl = yield from resp.prepare(req)
    resp_impl.transport.set_tcp_nodelay.assert_called_with(True)
    resp_impl.transport.set_tcp_cork.assert_called_with(False)


@asyncio.coroutine
def test_set_tcp_nodelay_after_start():
    req = make_request('GET', '/')
    resp = StreamResponse()

    with mock.patch('aiohttp.web_reqrep.ResponseImpl'):
        resp_impl = yield from resp.prepare(req)
    resp_impl.transport.set_tcp_cork.assert_called_with(False)
    resp_impl.transport.set_tcp_nodelay.assert_called_with(True)
    resp.set_tcp_nodelay(False)
    assert not resp.tcp_nodelay
    resp_impl.transport.set_tcp_nodelay.assert_called_with(False)
    resp.set_tcp_nodelay(True)
    assert resp.tcp_nodelay
    resp_impl.transport.set_tcp_nodelay.assert_called_with(True)


def test_default_cork():
    resp = StreamResponse()
    assert not resp.tcp_cork


def test_set_tcp_cork_before_start():
    resp = StreamResponse()
    resp.set_tcp_cork(True)
    assert resp.tcp_cork
    resp.set_tcp_cork(False)
    assert not resp.tcp_cork


@asyncio.coroutine
def test_set_tcp_cork_on_start():
    req = make_request('GET', '/')
    resp = StreamResponse()
    resp.set_tcp_cork(True)

    with mock.patch('aiohttp.web_reqrep.ResponseImpl'):
        resp_impl = yield from resp.prepare(req)
    resp_impl.transport.set_tcp_nodelay.assert_called_with(False)
    resp_impl.transport.set_tcp_cork.assert_called_with(True)


@asyncio.coroutine
def test_set_tcp_cork_after_start():
    req = make_request('GET', '/')
    resp = StreamResponse()

    with mock.patch('aiohttp.web_reqrep.ResponseImpl'):
        resp_impl = yield from resp.prepare(req)
    resp_impl.transport.set_tcp_cork.assert_called_with(False)
    resp.set_tcp_cork(True)
    assert resp.tcp_cork
    resp_impl.transport.set_tcp_cork.assert_called_with(True)
    resp.set_tcp_cork(False)
    assert not resp.tcp_cork
    resp_impl.transport.set_tcp_cork.assert_called_with(False)


# Response class


def test_response_ctor():
    resp = Response()

    assert 200 == resp.status
    assert 'OK' == resp.reason
    assert resp.body is None
    assert 0 == resp.content_length
    assert (CIMultiDict([('CONTENT-TYPE', 'application/octet-stream'),
                         ('CONTENT-LENGTH', '0')]) ==
            resp.headers)


def test_ctor_with_headers_and_status():
    resp = Response(body=b'body', status=201, headers={'Age': '12'})

    assert 201 == resp.status
    assert b'body' == resp.body
    assert 4 == resp.content_length
    assert (CIMultiDict([('AGE', '12'),
                         ('CONTENT-TYPE', 'application/octet-stream'),
                         ('CONTENT-LENGTH', '4')]) ==
            resp.headers)


def test_ctor_content_type():
    resp = Response(content_type='application/json')

    assert 200 == resp.status
    assert 'OK' == resp.reason
    assert (CIMultiDict([('CONTENT-TYPE', 'application/json'),
                         ('CONTENT-LENGTH', '0')]) ==
            resp.headers)


def test_ctor_text_body_combined():
    with pytest.raises(ValueError):
        Response(body=b'123', text='test text')


def test_ctor_text():
    resp = Response(text='test text')

    assert 200 == resp.status
    assert 'OK' == resp.reason
    assert (CIMultiDict(
        [('CONTENT-TYPE', 'text/plain; charset=utf-8'),
         ('CONTENT-LENGTH', '9')]) == resp.headers)

    assert resp.body == b'test text'
    assert resp.text == 'test text'


def test_ctor_charset():
    resp = Response(text='текст', charset='koi8-r')

    assert 'текст'.encode('koi8-r') == resp.body
    assert 'koi8-r' == resp.charset


def test_ctor_charset_default_utf8():
    resp = Response(text='test test', charset=None)

    assert 'utf-8' == resp.charset


def test_ctor_charset_in_content_type():
    with pytest.raises(ValueError):
        Response(text='test test', content_type='text/plain; charset=utf-8')


def test_ctor_charset_without_text():
    resp = Response(content_type='text/plain', charset='koi8-r')

    assert 'koi8-r' == resp.charset


def test_ctor_both_content_type_param_and_header_with_text():
    with pytest.raises(ValueError):
        Response(headers={'Content-Type': 'application/json'},
                 content_type='text/html', text='text')


def test_ctor_both_charset_param_and_header_with_text():
    with pytest.raises(ValueError):
        Response(headers={'Content-Type': 'application/json'},
                 charset='koi8-r', text='text')


def test_ctor_both_content_type_param_and_header():
    with pytest.raises(ValueError):
        Response(headers={'Content-Type': 'application/json'},
                 content_type='text/html')


def test_ctor_both_charset_param_and_header():
    with pytest.raises(ValueError):
        Response(headers={'Content-Type': 'application/json'},
                 charset='koi8-r')


def test_assign_nonbyteish_body():
    resp = Response(body=b'data')

    with pytest.raises(TypeError):
        resp.body = 123
    assert b'data' == resp.body
    assert 4 == resp.content_length


def test_assign_nonstr_text():
    resp = Response(text='test')

    with pytest.raises(TypeError):
        resp.text = b'123'
    assert b'test' == resp.body
    assert 4 == resp.content_length


@asyncio.coroutine
def test_send_headers_for_empty_body():
    writer = mock.Mock()
    req = make_request('GET', '/', writer=writer)
    resp = Response()

    writer.drain.return_value = ()
    buf = b''

    def append(data):
        nonlocal buf
        buf += data

    writer.write.side_effect = append

    yield from resp.prepare(req)
    yield from resp.write_eof()
    txt = buf.decode('utf8')
    assert re.match('HTTP/1.1 200 OK\r\n'
                    'Content-Type: application/octet-stream\r\n'
                    'Content-Length: 0\r\n'
                    'Date: .+\r\n'
                    'Server: .+\r\n\r\n', txt)


@asyncio.coroutine
def test_render_with_body():
    writer = mock.Mock()
    req = make_request('GET', '/', writer=writer)
    resp = Response(body=b'data')

    writer.drain.return_value = ()
    buf = b''

    def append(data):
        nonlocal buf
        buf += data

    writer.write.side_effect = append

    yield from resp.prepare(req)
    yield from resp.write_eof()
    txt = buf.decode('utf8')
    assert re.match('HTTP/1.1 200 OK\r\n'
                    'Content-Type: application/octet-stream\r\n'
                    'Content-Length: 4\r\n'
                    'Date: .+\r\n'
                    'Server: .+\r\n\r\n'
                    'data', txt)


@asyncio.coroutine
def test_send_set_cookie_header():
    resp = Response()
    resp.cookies['name'] = 'value'

    writer = mock.Mock()
    req = make_request('GET', '/', writer=writer)
    writer.drain.return_value = ()
    buf = b''

    def append(data):
        nonlocal buf
        buf += data

    writer.write.side_effect = append

    yield from resp.prepare(req)
    yield from resp.write_eof()
    txt = buf.decode('utf8')
    assert re.match('HTTP/1.1 200 OK\r\n'
                    'Content-Type: application/octet-stream\r\n'
                    'Content-Length: 0\r\n'
                    'Set-Cookie: name=value\r\n'
                    'Date: .+\r\n'
                    'Server: .+\r\n\r\n', txt)


def test_set_text_with_content_type():
    resp = Response()
    resp.content_type = "text/html"
    resp.text = "text"

    assert "text" == resp.text
    assert b"text" == resp.body
    assert "text/html" == resp.content_type


def test_set_text_with_charset():
    resp = Response()
    resp.content_type = 'text/plain'
    resp.charset = "KOI8-R"
    resp.text = "текст"

    assert "текст" == resp.text
    assert "текст".encode('koi8-r') == resp.body
    assert "koi8-r" == resp.charset


def test_default_content_type_in_stream_response():
    resp = StreamResponse()
    assert resp.content_type == 'application/octet-stream'


def test_default_content_type_in_response():
    resp = Response()
    assert resp.content_type == 'application/octet-stream'


def test_content_type_with_set_text():
    resp = Response(text='text')
    assert resp.content_type == 'text/plain'


def test_content_type_with_set_body():
    resp = Response(body=b'body')
    assert resp.content_type == 'application/octet-stream'


def test_started_when_not_started():
    resp = StreamResponse()
    assert not resp.prepared


@asyncio.coroutine
def test_started_when_started():
    resp = StreamResponse()
    yield from resp.prepare(make_request('GET', '/'))
    assert resp.prepared


@asyncio.coroutine
def test_drain_before_start():
    resp = StreamResponse()
    with pytest.raises(RuntimeError):
        yield from resp.drain()


def test_nonstr_text_in_ctor():
    with pytest.raises(TypeError):
        Response(text=b'data')


def test_text_in_ctor_with_content_type():
    resp = Response(text='data', content_type='text/html')
    assert 'data' == resp.text
    assert 'text/html' == resp.content_type


def test_text_in_ctor_with_content_type_header():
    resp = Response(text='текст',
                    headers={'Content-Type': 'text/html; charset=koi8-r'})
    assert 'текст'.encode('koi8-r') == resp.body
    assert 'text/html' == resp.content_type
    assert 'koi8-r' == resp.charset


def test_text_in_ctor_with_content_type_header_multidict():
    headers = CIMultiDict({'Content-Type': 'text/html; charset=koi8-r'})
    resp = Response(text='текст',
                    headers=headers)
    assert 'текст'.encode('koi8-r') == resp.body
    assert 'text/html' == resp.content_type
    assert 'koi8-r' == resp.charset


def test_body_in_ctor_with_content_type_header_multidict():
    headers = CIMultiDict({'Content-Type': 'text/html; charset=koi8-r'})
    resp = Response(body='текст'.encode('koi8-r'),
                    headers=headers)
    assert 'текст'.encode('koi8-r') == resp.body
    assert 'text/html' == resp.content_type
    assert 'koi8-r' == resp.charset


def test_text_with_empty_payload():
    resp = Response(status=200)
    assert resp.body is None
    assert resp.text is None


class TestJSONResponse:

    def test_content_type_is_application_json_by_default(self):
        resp = json_response('')
        assert 'application/json' == resp.content_type

    def test_passing_text_only(self):
        resp = json_response(text=json.dumps('jaysawn'))
        assert resp.text == json.dumps('jaysawn')

    def test_data_and_text_raises_value_error(self):
        with pytest.raises(ValueError) as excinfo:
            json_response(data='foo', text='bar')
        expected_message = (
            'only one of data, text, or body should be specified'
        )
        assert expected_message == excinfo.value.args[0]

    def test_data_and_body_raises_value_error(self):
        with pytest.raises(ValueError) as excinfo:
            json_response(data='foo', body=b'bar')
        expected_message = (
            'only one of data, text, or body should be specified'
        )
        assert expected_message == excinfo.value.args[0]

    def test_text_is_json_encoded(self):
        resp = json_response({'foo': 42})
        assert json.dumps({'foo': 42}) == resp.text

    def test_content_type_is_overrideable(self):
        resp = json_response({'foo': 42},
                             content_type='application/vnd.json+api')
        assert 'application/vnd.json+api' == resp.content_type
