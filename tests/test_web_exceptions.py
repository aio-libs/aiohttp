import asyncio
import collections
import re
from unittest import mock

import pytest

from aiohttp import signals, web
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

    def append(data):
        buf.extend(data)
    writer.write.side_effect = append
    app = mock.Mock()
    app._debug = False
    app.on_response_prepare = signals.Signal(app)
    req = make_mocked_request(method, path, app=app, writer=writer)
    return req


def test_all_http_exceptions_exported():
    assert 'HTTPException' in web.__all__
    for name in dir(web):
        if name.startswith('_'):
            continue
        obj = getattr(web, name)
        if isinstance(obj, type) and issubclass(obj, web.HTTPException):
            assert name in web.__all__


@asyncio.coroutine
def test_HTTPOk(buf, request):
    resp = web.HTTPOk()
    yield from resp.prepare(request)
    yield from resp.write_eof()
    txt = buf.decode('utf8')
    assert re.match(('HTTP/1.1 200 OK\r\n'
                     'Content-Type: text/plain; charset=utf-8\r\n'
                     'Content-Length: 7\r\n'
                     'Date: .+\r\n'
                     'Server: .+\r\n\r\n'
                     '200: OK'), txt)


def test_terminal_classes_has_status_code():
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
        assert cls.status_code is not None
    codes = collections.Counter(cls.status_code for cls in terminals)
    assert None not in codes
    assert 1 == codes.most_common(1)[0][1]


@asyncio.coroutine
def test_HTTPFound(buf, request):
    resp = web.HTTPFound(location='/redirect')
    assert '/redirect' == resp.location
    assert '/redirect' == resp.headers['location']
    yield from resp.prepare(request)
    yield from resp.write_eof()
    txt = buf.decode('utf8')
    assert re.match('HTTP/1.1 302 Found\r\n'
                    'Content-Type: text/plain; charset=utf-8\r\n'
                    'Content-Length: 10\r\n'
                    'Location: /redirect\r\n'
                    'Date: .+\r\n'
                    'Server: .+\r\n\r\n'
                    '302: Found', txt)


def test_HTTPFound_empty_location():
    with pytest.raises(ValueError):
        web.HTTPFound(location='')

    with pytest.raises(ValueError):
        web.HTTPFound(location=None)


@asyncio.coroutine
def test_HTTPMethodNotAllowed(buf, request):
    resp = web.HTTPMethodNotAllowed('get', ['POST', 'PUT'])
    assert 'GET' == resp.method
    assert ['POST', 'PUT'] == resp.allowed_methods
    assert 'POST,PUT' == resp.headers['allow']
    yield from resp.prepare(request)
    yield from resp.write_eof()
    txt = buf.decode('utf8')
    assert re.match('HTTP/1.1 405 Method Not Allowed\r\n'
                    'Content-Type: text/plain; charset=utf-8\r\n'
                    'Content-Length: 23\r\n'
                    'Allow: POST,PUT\r\n'
                    'Date: .+\r\n'
                    'Server: .+\r\n\r\n'
                    '405: Method Not Allowed', txt)


def test_override_body_with_text():
    resp = web.HTTPNotFound(text="Page not found")
    assert 404 == resp.status
    assert "Page not found".encode('utf-8') == resp.body
    assert "Page not found" == resp.text
    assert "text/plain" == resp.content_type
    assert "utf-8" == resp.charset


def test_override_body_with_binary():
    txt = "<html><body>Page not found</body></html>"
    resp = web.HTTPNotFound(body=txt.encode('utf-8'),
                            content_type="text/html")
    assert 404 == resp.status
    assert txt.encode('utf-8') == resp.body
    assert txt == resp.text
    assert "text/html" == resp.content_type
    assert resp.charset is None


def test_default_body():
    resp = web.HTTPOk()
    assert b'200: OK' == resp.body


def test_empty_body_204():
    resp = web.HTTPNoContent()
    assert resp.body is None


def test_empty_body_205():
    resp = web.HTTPNoContent()
    assert resp.body is None


def test_empty_body_304():
    resp = web.HTTPNoContent()
    resp.body is None


def test_link_header_451(buf, request):
    resp = web.HTTPUnavailableForLegalReasons(link='http://warning.or.kr/')

    assert 'http://warning.or.kr/' == resp.link
    assert '<http://warning.or.kr/>; rel="blocked-by"' == resp.headers['Link']
