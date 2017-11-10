import collections
import datetime
import json
import re
from unittest import mock

import pytest
from multidict import CIMultiDict

from aiohttp import HttpVersion, HttpVersion10, HttpVersion11, hdrs, signals
from aiohttp.payload import BytesPayload
from aiohttp.test_utils import make_mocked_coro, make_mocked_request
from aiohttp.web import ContentCoding, Response, StreamResponse, json_response


def make_request(method, path, headers=CIMultiDict(),
                 version=HttpVersion11, on_response_prepare=None, **kwargs):
    app = kwargs.pop('app', None) or mock.Mock()
    app._debug = False
    if on_response_prepare is None:
        on_response_prepare = signals.Signal(app)
    app.on_response_prepare = on_response_prepare
    app.on_response_prepare.freeze()
    protocol = kwargs.pop('protocol', None) or mock.Mock()
    return make_mocked_request(method, path, headers,
                               version=version, protocol=protocol,
                               app=app, **kwargs)


@pytest.yield_fixture
def buf():
    return bytearray()


@pytest.yield_fixture
def writer(buf):
    writer = mock.Mock()

    def acquire(cb):
        cb(writer.transport)

    def buffer_data(chunk):
        buf.extend(chunk)

    def write(chunk):
        buf.extend(chunk)

    def write_headers(status_line, headers):
        headers = status_line + ''.join(
            [k + ': ' + v + '\r\n' for k, v in headers.items()])
        headers = headers.encode('utf-8') + b'\r\n'
        buf.extend(headers)

    async def write_eof(chunk=b''):
        buf.extend(chunk)

    writer.acquire.side_effect = acquire
    writer.transport.write.side_effect = write
    writer.write.side_effect = write
    writer.write_eof.side_effect = write_eof
    writer.write_headers.side_effect = write_headers
    writer.buffer_data.side_effect = buffer_data
    writer.drain.return_value = ()

    return writer


def test_stream_response_ctor():
    resp = StreamResponse()
    assert 200 == resp.status
    assert resp.keep_alive is None

    assert resp.task is None

    req = mock.Mock()
    resp._req = req
    assert resp.task is req.task


def test_stream_response_is_mutable_mapping():
    resp = StreamResponse()
    assert isinstance(resp, collections.MutableMapping)
    resp['key'] = 'value'
    assert 'value' == resp['key']


def test_stream_response_delitem():
    resp = StreamResponse()
    resp['key'] = 'value'
    del resp['key']
    assert 'key' not in resp


def test_stream_response_len():
    resp = StreamResponse()
    assert len(resp) == 0
    resp['key'] = 'value'
    assert len(resp) == 1


def test_request_iter():
    resp = StreamResponse()
    resp['key'] = 'value'
    resp['key2'] = 'value2'
    assert set(resp) == {'key', 'key2'}


def test_content_length():
    resp = StreamResponse()
    assert resp.content_length is None


def test_content_length_setter():
    resp = StreamResponse()

    resp.content_length = 234
    assert 234 == resp.content_length


def test_content_length_setter_with_enable_chunked_encoding():
    resp = StreamResponse()

    resp.enable_chunked_encoding()
    with pytest.raises(RuntimeError):
        resp.content_length = 234


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


async def test_start():
    req = make_request('GET', '/', payload_writer=mock.Mock())
    resp = StreamResponse()
    assert resp.keep_alive is None

    msg = await resp.prepare(req)

    assert msg.write_headers.called
    msg2 = await resp.prepare(req)
    assert msg is msg2

    assert resp.keep_alive

    req2 = make_request('GET', '/')
    # with pytest.raises(RuntimeError):
    msg3 = await resp.prepare(req2)
    assert msg is msg3


async def test_chunked_encoding():
    req = make_request('GET', '/')
    resp = StreamResponse()
    assert not resp.chunked

    resp.enable_chunked_encoding()
    assert resp.chunked

    msg = await resp.prepare(req)
    assert msg.chunked


def test_enable_chunked_encoding_with_content_length():
    resp = StreamResponse()

    resp.content_length = 234
    with pytest.raises(RuntimeError):
        resp.enable_chunked_encoding()


async def test_chunk_size():
    req = make_request('GET', '/', payload_writer=mock.Mock())
    resp = StreamResponse()
    assert not resp.chunked

    with pytest.warns(DeprecationWarning):
        resp.enable_chunked_encoding(chunk_size=8192)
    assert resp.chunked

    msg = await resp.prepare(req)
    assert msg.chunked
    assert msg.enable_chunking.called
    assert msg.filter is not None


async def test_chunked_encoding_forbidden_for_http_10():
    req = make_request('GET', '/', version=HttpVersion10)
    resp = StreamResponse()
    resp.enable_chunked_encoding()

    with pytest.raises(RuntimeError) as ctx:
        await resp.prepare(req)
    assert re.match("Using chunked encoding is forbidden for HTTP/1.0",
                    str(ctx.value))


async def test_compression_no_accept():
    req = make_request('GET', '/', payload_writer=mock.Mock())
    resp = StreamResponse()
    assert not resp.chunked

    assert not resp.compression
    resp.enable_compression()
    assert resp.compression

    msg = await resp.prepare(req)
    assert not msg.enable_compression.called


async def test_force_compression_no_accept_backwards_compat():
    req = make_request('GET', '/', payload_writer=mock.Mock())
    resp = StreamResponse()
    assert not resp.chunked

    assert not resp.compression
    resp.enable_compression(force=True)
    assert resp.compression

    msg = await resp.prepare(req)
    assert msg.enable_compression.called
    assert msg.filter is not None


async def test_force_compression_false_backwards_compat():
    req = make_request('GET', '/', payload_writer=mock.Mock())
    resp = StreamResponse()

    assert not resp.compression
    resp.enable_compression(force=False)
    assert resp.compression

    msg = await resp.prepare(req)
    assert not msg.enable_compression.called


async def test_compression_default_coding():
    req = make_request(
        'GET', '/',
        headers=CIMultiDict({hdrs.ACCEPT_ENCODING: 'gzip, deflate'}))
    resp = StreamResponse()
    assert not resp.chunked

    assert not resp.compression
    resp.enable_compression()
    assert resp.compression

    msg = await resp.prepare(req)

    msg.enable_compression.assert_called_with('deflate')
    assert 'deflate' == resp.headers.get(hdrs.CONTENT_ENCODING)
    assert msg.filter is not None


async def test_force_compression_deflate():
    req = make_request(
        'GET', '/',
        headers=CIMultiDict({hdrs.ACCEPT_ENCODING: 'gzip, deflate'}))
    resp = StreamResponse()

    resp.enable_compression(ContentCoding.deflate)
    assert resp.compression

    msg = await resp.prepare(req)
    msg.enable_compression.assert_called_with('deflate')
    assert 'deflate' == resp.headers.get(hdrs.CONTENT_ENCODING)


async def test_force_compression_no_accept_deflate():
    req = make_request('GET', '/')
    resp = StreamResponse()

    resp.enable_compression(ContentCoding.deflate)
    assert resp.compression

    msg = await resp.prepare(req)
    msg.enable_compression.assert_called_with('deflate')
    assert 'deflate' == resp.headers.get(hdrs.CONTENT_ENCODING)


async def test_force_compression_gzip():
    req = make_request(
        'GET', '/',
        headers=CIMultiDict({hdrs.ACCEPT_ENCODING: 'gzip, deflate'}))
    resp = StreamResponse()

    resp.enable_compression(ContentCoding.gzip)
    assert resp.compression

    msg = await resp.prepare(req)
    msg.enable_compression.assert_called_with('gzip')
    assert 'gzip' == resp.headers.get(hdrs.CONTENT_ENCODING)


async def test_force_compression_no_accept_gzip():
    req = make_request('GET', '/')
    resp = StreamResponse()

    resp.enable_compression(ContentCoding.gzip)
    assert resp.compression

    msg = await resp.prepare(req)
    msg.enable_compression.assert_called_with('gzip')
    assert 'gzip' == resp.headers.get(hdrs.CONTENT_ENCODING)


async def test_change_content_length_if_compression_enabled():
    req = make_request('GET', '/')
    resp = Response(body=b'answer')
    resp.enable_compression(ContentCoding.gzip)

    await resp.prepare(req)
    assert resp.content_length is not None and \
        resp.content_length != len(b'answer')


async def test_set_content_length_if_compression_enabled():
    writer = mock.Mock()

    def write_headers(status_line, headers):
        assert hdrs.CONTENT_LENGTH in headers
        assert headers[hdrs.CONTENT_LENGTH] == '26'
        assert hdrs.TRANSFER_ENCODING not in headers

    writer.write_headers.side_effect = write_headers
    req = make_request('GET', '/', payload_writer=writer)
    resp = Response(body=b'answer')
    resp.enable_compression(ContentCoding.gzip)

    await resp.prepare(req)
    assert resp.content_length == 26
    del resp.headers[hdrs.CONTENT_LENGTH]
    assert resp.content_length == 26


async def test_remove_content_length_if_compression_enabled_http11():
    writer = mock.Mock()

    def write_headers(status_line, headers):
        assert hdrs.CONTENT_LENGTH not in headers
        assert headers.get(hdrs.TRANSFER_ENCODING, '') == 'chunked'

    writer.write_headers.side_effect = write_headers
    req = make_request('GET', '/', payload_writer=writer)
    resp = StreamResponse()
    resp.content_length = 123
    resp.enable_compression(ContentCoding.gzip)
    await resp.prepare(req)
    assert resp.content_length is None


async def test_remove_content_length_if_compression_enabled_http10():
    writer = mock.Mock()

    def write_headers(status_line, headers):
        assert hdrs.CONTENT_LENGTH not in headers
        assert hdrs.TRANSFER_ENCODING not in headers

    writer.write_headers.side_effect = write_headers
    req = make_request('GET', '/', version=HttpVersion10,
                       payload_writer=writer)
    resp = StreamResponse()
    resp.content_length = 123
    resp.enable_compression(ContentCoding.gzip)
    await resp.prepare(req)
    assert resp.content_length is None


async def test_force_compression_identity():
    writer = mock.Mock()

    def write_headers(status_line, headers):
        assert hdrs.CONTENT_LENGTH in headers
        assert hdrs.TRANSFER_ENCODING not in headers

    writer.write_headers.side_effect = write_headers
    req = make_request('GET', '/',
                       payload_writer=writer)
    resp = StreamResponse()
    resp.content_length = 123
    resp.enable_compression(ContentCoding.identity)
    await resp.prepare(req)
    assert resp.content_length == 123


async def test_force_compression_identity_response():
    writer = mock.Mock()

    def write_headers(status_line, headers):
        assert headers[hdrs.CONTENT_LENGTH] == "6"
        assert hdrs.TRANSFER_ENCODING not in headers

    writer.write_headers.side_effect = write_headers
    req = make_request('GET', '/',
                       payload_writer=writer)
    resp = Response(body=b'answer')
    resp.enable_compression(ContentCoding.identity)
    await resp.prepare(req)
    assert resp.content_length == 6


async def test_remove_content_length_if_compression_enabled_on_payload_http11():  # noqa
    writer = mock.Mock()

    def write_headers(status_line, headers):
        assert hdrs.CONTENT_LENGTH not in headers
        assert headers.get(hdrs.TRANSFER_ENCODING, '') == 'chunked'

    writer.write_headers.side_effect = write_headers
    req = make_request('GET', '/', payload_writer=writer)
    payload = BytesPayload(b'answer', headers={"X-Test-Header": "test"})
    resp = Response(body=payload)
    assert resp.content_length == 6
    resp.body = payload
    resp.enable_compression(ContentCoding.gzip)
    await resp.prepare(req)
    assert resp.content_length is None


async def test_remove_content_length_if_compression_enabled_on_payload_http10():  # noqa
    writer = mock.Mock()

    def write_headers(status_line, headers):
        assert hdrs.CONTENT_LENGTH not in headers
        assert hdrs.TRANSFER_ENCODING not in headers

    writer.write_headers.side_effect = write_headers
    req = make_request('GET', '/', version=HttpVersion10,
                       payload_writer=writer)
    resp = Response(body=BytesPayload(b'answer'))
    resp.enable_compression(ContentCoding.gzip)
    await resp.prepare(req)
    assert resp.content_length is None


async def test_content_length_on_chunked():
    req = make_request('GET', '/')
    resp = Response(body=b'answer')
    assert resp.content_length == 6
    resp.enable_chunked_encoding()
    assert resp.content_length is None
    await resp.prepare(req)


async def test_write_non_byteish():
    resp = StreamResponse()
    await resp.prepare(make_request('GET', '/'))

    with pytest.raises(AssertionError):
        await resp.write(123)


async def test_write_before_start():
    resp = StreamResponse()

    with pytest.raises(RuntimeError):
        await resp.write(b'data')


async def test_cannot_write_after_eof():
    resp = StreamResponse()
    req = make_request('GET', '/')
    await resp.prepare(req)

    await resp.write(b'data')
    await resp.write_eof()
    req.writer.write.reset_mock()

    with pytest.raises(RuntimeError):
        await resp.write(b'next data')
    assert not req.writer.write.called


async def test___repr___after_eof():
    resp = StreamResponse()
    await resp.prepare(make_request('GET', '/'))

    assert resp.prepared

    await resp.write(b'data')
    await resp.write_eof()
    assert not resp.prepared
    resp_repr = repr(resp)
    assert resp_repr == '<StreamResponse OK eof>'


async def test_cannot_write_eof_before_headers():
    resp = StreamResponse()

    with pytest.raises(AssertionError):
        await resp.write_eof()


async def test_cannot_write_eof_twice():
    resp = StreamResponse()
    writer = mock.Mock()
    resp_impl = await resp.prepare(make_request('GET', '/'))
    resp_impl.write = make_mocked_coro(None)
    resp_impl.write_eof = make_mocked_coro(None)

    await resp.write(b'data')
    assert resp_impl.write.called

    await resp.write_eof()

    resp_impl.write.reset_mock()
    await resp.write_eof()
    assert not writer.write.called


def test_force_close():
    resp = StreamResponse()

    assert resp.keep_alive is None
    resp.force_close()
    assert resp.keep_alive is False


async def test_response_output_length():
    resp = StreamResponse()
    await resp.prepare(make_request('GET', '/'))
    with pytest.warns(DeprecationWarning):
        assert resp.output_length


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


async def test_start_force_close():
    req = make_request('GET', '/')
    resp = StreamResponse()
    resp.force_close()
    assert not resp.keep_alive

    await resp.prepare(req)
    assert not resp.keep_alive


async def test___repr__():
    req = make_request('GET', '/path/to')
    resp = StreamResponse(reason=301)
    await resp.prepare(req)
    assert "<StreamResponse 301 GET /path/to >" == repr(resp)


def test___repr___not_prepared():
    resp = StreamResponse(reason=301)
    assert "<StreamResponse 301 not prepared>" == repr(resp)


async def test_keep_alive_http10_default():
    req = make_request('GET', '/', version=HttpVersion10)
    resp = StreamResponse()
    await resp.prepare(req)
    assert not resp.keep_alive


async def test_keep_alive_http10_switched_on():
    headers = CIMultiDict(Connection='keep-alive')
    req = make_request('GET', '/', version=HttpVersion10, headers=headers)
    req._message = req._message._replace(should_close=False)
    resp = StreamResponse()
    await resp.prepare(req)
    assert resp.keep_alive


async def test_keep_alive_http09():
    headers = CIMultiDict(Connection='keep-alive')
    req = make_request('GET', '/', version=HttpVersion(0, 9), headers=headers)
    resp = StreamResponse()
    await resp.prepare(req)
    assert not resp.keep_alive


async def test_prepare_twice():
    req = make_request('GET', '/')
    resp = StreamResponse()

    impl1 = await resp.prepare(req)
    impl2 = await resp.prepare(req)
    assert impl1 is impl2


async def test_prepare_calls_signal():
    app = mock.Mock()
    sig = make_mocked_coro()
    on_response_prepare = signals.Signal(app)
    on_response_prepare.append(sig)
    req = make_request('GET', '/', app=app,
                       on_response_prepare=on_response_prepare)
    resp = StreamResponse()

    await resp.prepare(req)

    sig.assert_called_with(req, resp)


def test_get_nodelay_unprepared():
    resp = StreamResponse()
    with pytest.raises(AssertionError):
        resp.tcp_nodelay


def test_set_nodelay_unprepared():
    resp = StreamResponse()
    with pytest.raises(AssertionError):
        resp.set_tcp_nodelay(True)


async def test_get_nodelay_prepared():
    resp = StreamResponse()
    writer = mock.Mock()
    writer.tcp_nodelay = False
    req = make_request('GET', '/', payload_writer=writer)

    await resp.prepare(req)
    assert not resp.tcp_nodelay


async def test_set_nodelay_prepared():
    resp = StreamResponse()
    writer = mock.Mock()
    req = make_request('GET', '/', payload_writer=writer)

    await resp.prepare(req)
    resp.set_tcp_nodelay(True)
    writer.set_tcp_nodelay.assert_called_with(True)


def test_get_cork_unprepared():
    resp = StreamResponse()
    with pytest.raises(AssertionError):
        resp.tcp_cork


def test_set_cork_unprepared():
    resp = StreamResponse()
    with pytest.raises(AssertionError):
        resp.set_tcp_cork(True)


async def test_get_cork_prepared():
    resp = StreamResponse()
    writer = mock.Mock()
    writer.tcp_cork = False
    req = make_request('GET', '/', payload_writer=writer)

    await resp.prepare(req)
    assert not resp.tcp_cork


async def test_set_cork_prepared():
    resp = StreamResponse()
    writer = mock.Mock()
    req = make_request('GET', '/', payload_writer=writer)

    await resp.prepare(req)
    resp.set_tcp_cork(True)
    writer.set_tcp_cork.assert_called_with(True)


# Response class


def test_response_ctor():
    resp = Response()

    assert 200 == resp.status
    assert 'OK' == resp.reason
    assert resp.body is None
    assert resp.content_length == 0
    assert 'CONTENT-LENGTH' not in resp.headers


def test_ctor_with_headers_and_status():
    resp = Response(body=b'body', status=201,
                    headers={'Age': '12', 'DATE': 'date'})

    assert 201 == resp.status
    assert b'body' == resp.body
    assert resp.headers['AGE'] == '12'

    resp._start(mock.Mock(version=HttpVersion11))
    assert 4 == resp.content_length
    assert resp.headers['CONTENT-LENGTH'] == '4'


def test_ctor_content_type():
    resp = Response(content_type='application/json')

    assert 200 == resp.status
    assert 'OK' == resp.reason
    assert 0 == resp.content_length
    assert (CIMultiDict([('CONTENT-TYPE', 'application/json')]) ==
            resp.headers)


def test_ctor_text_body_combined():
    with pytest.raises(ValueError):
        Response(body=b'123', text='test text')


def test_ctor_text():
    resp = Response(text='test text')

    assert 200 == resp.status
    assert 'OK' == resp.reason
    assert 9 == resp.content_length
    assert (CIMultiDict(
        [('CONTENT-TYPE', 'text/plain; charset=utf-8')]) == resp.headers)

    assert resp.body == b'test text'
    assert resp.text == 'test text'

    resp.headers['DATE'] = 'date'
    resp._start(mock.Mock(version=HttpVersion11))
    assert resp.headers['CONTENT-LENGTH'] == '9'


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


def test_ctor_content_type_with_extra():
    resp = Response(text='test test', content_type='text/plain; version=0.0.4')

    assert resp.content_type == 'text/plain'
    assert resp.headers['content-type'] == \
        'text/plain; version=0.0.4; charset=utf-8'


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

    with pytest.raises(ValueError):
        resp.body = 123
    assert b'data' == resp.body
    assert 4 == resp.content_length

    resp.headers['DATE'] = 'date'
    resp._start(mock.Mock(version=HttpVersion11))
    assert resp.headers['CONTENT-LENGTH'] == '4'
    assert 4 == resp.content_length


def test_assign_nonstr_text():
    resp = Response(text='test')

    with pytest.raises(AssertionError):
        resp.text = b'123'
    assert b'test' == resp.body
    assert 4 == resp.content_length


def test_response_set_content_length():
    resp = Response()
    with pytest.raises(RuntimeError):
        resp.content_length = 1


async def test_send_headers_for_empty_body(buf, writer):
    req = make_request('GET', '/', payload_writer=writer)
    resp = Response()

    await resp.prepare(req)
    await resp.write_eof()
    txt = buf.decode('utf8')
    assert re.match('HTTP/1.1 200 OK\r\n'
                    'Content-Length: 0\r\n'
                    'Content-Type: application/octet-stream\r\n'
                    'Date: .+\r\n'
                    'Server: .+\r\n\r\n', txt)


async def test_render_with_body(buf, writer):
    req = make_request('GET', '/', payload_writer=writer)
    resp = Response(body=b'data')

    await resp.prepare(req)
    await resp.write_eof()

    txt = buf.decode('utf8')
    assert re.match('HTTP/1.1 200 OK\r\n'
                    'Content-Length: 4\r\n'
                    'Content-Type: application/octet-stream\r\n'
                    'Date: .+\r\n'
                    'Server: .+\r\n\r\n'
                    'data', txt)


async def test_send_set_cookie_header(buf, writer):
    resp = Response()
    resp.cookies['name'] = 'value'
    req = make_request('GET', '/', payload_writer=writer)

    await resp.prepare(req)
    await resp.write_eof()

    txt = buf.decode('utf8')
    assert re.match('HTTP/1.1 200 OK\r\n'
                    'Content-Length: 0\r\n'
                    'Set-Cookie: name=value\r\n'
                    'Content-Type: application/octet-stream\r\n'
                    'Date: .+\r\n'
                    'Server: .+\r\n\r\n', txt)


async def test_consecutive_write_eof():
    payload_writer = mock.Mock()
    payload_writer.write_eof = make_mocked_coro()
    req = make_request('GET', '/', payload_writer=payload_writer)
    data = b'data'
    resp = Response(body=data)

    await resp.prepare(req)
    await resp.write_eof()
    await resp.write_eof()
    payload_writer.write_eof.assert_called_once_with(data)


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


async def test_started_when_started():
    resp = StreamResponse()
    await resp.prepare(make_request('GET', '/'))
    assert resp.prepared


async def test_drain_before_start():
    resp = StreamResponse()
    with pytest.raises(AssertionError):
        await resp.drain()


async def test_changing_status_after_prepare_raises():
    resp = StreamResponse()
    await resp.prepare(make_request('GET', '/'))
    with pytest.raises(AssertionError):
        resp.set_status(400)


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


def test_response_with_content_length_header_without_body():
    resp = Response(headers={'Content-Length': 123})
    assert resp.content_length == 123


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
