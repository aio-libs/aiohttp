import collections
from traceback import format_exception

import pytest
from yarl import URL

from aiohttp import web


def test_all_http_exceptions_exported() -> None:
    assert 'HTTPException' in web.__all__
    for name in dir(web):
        if name.startswith('_'):
            continue
        obj = getattr(web, name)
        if isinstance(obj, type) and issubclass(obj, web.HTTPException):
            assert name in web.__all__


async def test_ctor() -> None:
    resp = web.HTTPOk()
    assert resp.text == "200: OK"
    assert resp.headers == {'Content-Type': 'text/plain'}
    assert resp.reason == "OK"
    assert resp.status == 200
    assert bool(resp)


async def test_ctor_with_headers() -> None:
    resp = web.HTTPOk(headers={"X-Custom": "value"})
    assert resp.text == "200: OK"
    assert resp.headers == {'Content-Type': 'text/plain', "X-Custom": "value"}
    assert resp.reason == "OK"
    assert resp.status == 200


async def test_ctor_content_type() -> None:
    with pytest.warns(DeprecationWarning):
        resp = web.HTTPOk(content_type="custom")
    assert resp.text == "200: OK"
    assert resp.headers == {'Content-Type': 'custom'}
    assert resp.reason == "OK"
    assert resp.status == 200
    assert bool(resp)


async def test_ctor_text_for_empty_body() -> None:
    with pytest.warns(DeprecationWarning):
        resp = web.HTTPResetContent(text="text")
    assert resp.text == "text"
    assert resp.headers == {'Content-Type': 'text/plain'}
    assert resp.reason == "Reset Content"
    assert resp.status == 205


def test_terminal_classes_has_status_code() -> None:
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


async def test_HTTPOk(aiohttp_client) -> None:

    async def handler(request):
        raise web.HTTPOk()

    app = web.Application()
    app.router.add_get('/', handler)
    cli = await aiohttp_client(app)

    resp = await cli.get('/')
    assert 200 == resp.status
    txt = await resp.text()
    assert "200: OK" == txt


async def test_HTTPFound(aiohttp_client) -> None:

    async def handler(request):
        raise web.HTTPFound(location='/redirect')

    app = web.Application()
    app.router.add_get('/', handler)
    cli = await aiohttp_client(app)

    resp = await cli.get('/', allow_redirects=False)
    assert 302 == resp.status
    txt = await resp.text()
    assert "302: Found" == txt
    assert '/redirect' == resp.headers['location']


def test_HTTPFound_location_str() -> None:
    exc = web.HTTPFound(location='/redirect')
    assert exc.location == URL('/redirect')
    assert exc.headers['Location'] == '/redirect'


def test_HTTPFound_location_url() -> None:
    exc = web.HTTPFound(location=URL('/redirect'))
    assert exc.location == URL('/redirect')
    assert exc.headers['Location'] == '/redirect'


def test_HTTPFound_empty_location() -> None:
    with pytest.raises(ValueError):
        web.HTTPFound(location='')

    with pytest.raises(ValueError):
        web.HTTPFound(location=None)


async def test_HTTPMethodNotAllowed() -> None:
    exc = web.HTTPMethodNotAllowed('GET', ['POST', 'PUT'])
    assert 'GET' == exc.method
    assert {'POST', 'PUT'} == exc.allowed_methods
    assert 'POST,PUT' == exc.headers['allow']
    assert '405: Method Not Allowed' == exc.text


def test_with_text() -> None:
    resp = web.HTTPNotFound(text="Page not found")
    assert 404 == resp.status
    assert "Page not found" == resp.text
    assert "text/plain" == resp.headers['Content-Type']


def test_default_text() -> None:
    resp = web.HTTPOk()
    assert '200: OK' == resp.text


def test_empty_text_204() -> None:
    resp = web.HTTPNoContent()
    assert resp.text is None


def test_empty_text_205() -> None:
    resp = web.HTTPNoContent()
    assert resp.text is None


def test_empty_text_304() -> None:
    resp = web.HTTPNoContent()
    resp.text is None


def test_link_header_451() -> None:
    resp = web.HTTPUnavailableForLegalReasons(link='http://warning.or.kr/')

    assert URL('http://warning.or.kr/') == resp.link
    assert '<http://warning.or.kr/>; rel="blocked-by"' == resp.headers['Link']


def test_HTTPException_retains_cause() -> None:
    with pytest.raises(web.HTTPException) as ei:
        try:
            raise Exception('CustomException')
        except Exception as exc:
            raise web.HTTPException() from exc
    tb = ''.join(format_exception(ei.type, ei.value, ei.tb))
    assert 'CustomException' in tb
    assert 'direct cause' in tb
