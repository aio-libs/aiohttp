import collections
import re
from unittest import mock

import pytest

from aiohttp import helpers, signals, web
from aiohttp.test_utils import make_mocked_request


@pytest.fixture
def buf():
    return bytearray()


@pytest.fixture
def request(buf):
    method = 'GET'
    path = '/'
    writer = mock.Mock()
    writer.drain.return_value = ()

    def append(data=b''):
        buf.extend(data)
        return helpers.noop()

    def write_headers(status_line, headers):
        headers = status_line + ''.join(
            [k + ': ' + v + '\r\n' for k, v in headers.items()])
        headers = headers.encode('utf-8') + b'\r\n'
        buf.extend(headers)

    writer.buffer_data.side_effect = append
    writer.write.side_effect = append
    writer.write_eof.side_effect = append
    writer.write_headers.side_effect = write_headers

    app = mock.Mock()
    app._debug = False
    app.on_response_prepare = signals.Signal(app)
    app.on_response_prepare.freeze()
    req = make_mocked_request(method, path, app=app, payload_writer=writer)
    return req


def test_all_http_exceptions_exported():
    assert 'HTTPException' in web.__all__
    for name in dir(web):
        if name.startswith('_'):
            continue
        obj = getattr(web, name)
        if isinstance(obj, type) and issubclass(obj, web.HTTPException):
            assert name in web.__all__


async def test_HTTPOk(buf, request):
    exc = web.HTTPOk()
    resp = exc.build_response()
    await resp.prepare(request)
    await resp.write_eof()
    txt = buf.decode('utf8')
    assert re.match(('HTTP/1.1 200 OK\r\n'
                     'Content-Type: text/plain; charset=utf-8\r\n'
                     'Content-Length: 7\r\n'
                     'Date: .+\r\n'
                     'Server: .+\r\n\r\n'
                     '200: OK'), txt)


def test_terminal_classes_has_status():
    terminals = set()
    for name in dir(web):
        obj = getattr(web, name)
        if isinstance(obj, type) and issubclass(obj, web.HTTPException):
            terminals.add(obj)

    dup = frozenset(terminals)
    for cls1 in dup:
        for cls2 in dup:
            if cls1 in cls2.__bases__:
                terminals.discard(cls1)

    for cls in terminals:
        assert cls.status is not None
    codes = collections.Counter(cls.status for cls in terminals)
    assert None not in codes
    assert 1 == codes.most_common(1)[0][1]


async def test_HTTPFound(buf, request):
    exc = web.HTTPFound(location='/redirect')
    assert '/redirect' == exc.location
    resp = exc.build_response()
    assert '/redirect' == resp.headers['location']
    await resp.prepare(request)
    await resp.write_eof()
    txt = buf.decode('utf8')
    assert re.match('HTTP/1.1 302 Found\r\n'
                    'Content-Type: text/plain; charset=utf-8\r\n'
                    'Location: /redirect\r\n'
                    'Content-Length: 10\r\n'
                    'Date: .+\r\n'
                    'Server: .+\r\n\r\n'
                    '302: Found', txt)


def test_HTTPFound_empty_location():
    with pytest.raises(ValueError):
        web.HTTPFound(location='')

    with pytest.raises(ValueError):
        web.HTTPFound(location=None)


async def test_HTTPMethodNotAllowed(buf, request):
    exc = web.HTTPMethodNotAllowed('get', ['POST', 'PUT'])
    assert 'GET' == exc.method
    assert ['POST', 'PUT'] == exc.allowed_methods
    resp = exc.build_response()
    assert 'POST,PUT' == resp.headers['allow']
    await resp.prepare(request)
    await resp.write_eof()
    txt = buf.decode('utf8')
    assert re.match('HTTP/1.1 405 Method Not Allowed\r\n'
                    'Content-Type: text/plain; charset=utf-8\r\n'
                    'Allow: POST,PUT\r\n'
                    'Content-Length: 23\r\n'
                    'Date: .+\r\n'
                    'Server: .+\r\n\r\n'
                    '405: Method Not Allowed', txt)


def test_default_body():
    exc = web.HTTPOk()
    resp = exc.build_response()
    assert b'200: OK' == resp.body


def test_empty_body_204():
    exc = web.HTTPNoContent()
    resp = exc.build_response()
    assert resp.body is None


def test_empty_body_205():
    exc = web.HTTPNoContent()
    resp = exc.build_response()
    assert resp.body is None


def test_empty_body_304():
    exc = web.HTTPNoContent()
    resp = exc.build_response()
    resp.body is None


def test_link_header_451(buf, request):
    exc = web.HTTPUnavailableForLegalReasons(link='http://warning.or.kr/')
    assert 'http://warning.or.kr/' == exc.link
    resp = exc.build_response()
    assert '<http://warning.or.kr/>; rel="blocked-by"' == resp.headers['Link']
