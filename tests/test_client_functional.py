"""HTTP client functional tests against aiohttp.web server"""

import asyncio
import http.cookies
import io
import json
import pathlib
import socket
import ssl
from unittest import mock

import pytest
from multidict import MultiDict

import aiohttp
from aiohttp import Fingerprint, ServerFingerprintMismatch, hdrs, web
from aiohttp.abc import AbstractResolver
from aiohttp.test_utils import unused_port


@pytest.fixture
def here():
    return pathlib.Path(__file__).parent


@pytest.fixture
def ssl_ctx(here):
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    ssl_ctx.load_cert_chain(
        str(here / 'sample.crt'),
        str(here / 'sample.key'))
    return ssl_ctx


@pytest.fixture
def fname(here):
    return here / 'sample.key'


def ceil(val):
    return val


async def test_keepalive_two_requests_success(loop, test_client):
    async def handler(request):
        body = await request.read()
        assert b'' == body
        return web.Response(body=b'OK')

    app = web.Application()
    app.router.add_route('GET', '/', handler)

    connector = aiohttp.TCPConnector(loop=loop, limit=1)
    client = await test_client(app, connector=connector)

    resp1 = await client.get('/')
    await resp1.read()
    resp2 = await client.get('/')
    await resp2.read()

    assert 1 == len(client._session.connector._conns)


async def test_keepalive_response_released(loop, test_client):
    async def handler(request):
        body = await request.read()
        assert b'' == body
        return web.Response(body=b'OK')

    app = web.Application()
    app.router.add_route('GET', '/', handler)

    connector = aiohttp.TCPConnector(loop=loop, limit=1)
    client = await test_client(app, connector=connector)

    resp1 = await client.get('/')
    resp1.release()
    resp2 = await client.get('/')
    resp2.release()

    assert 1 == len(client._session.connector._conns)


async def test_keepalive_server_force_close_connection(loop, test_client):
    async def handler(request):
        body = await request.read()
        assert b'' == body
        response = web.Response(body=b'OK')
        response.force_close()
        return response

    app = web.Application()
    app.router.add_route('GET', '/', handler)

    connector = aiohttp.TCPConnector(loop=loop, limit=1)
    client = await test_client(app, connector=connector)

    resp1 = await client.get('/')
    resp1.close()
    resp2 = await client.get('/')
    resp2.close()

    assert 0 == len(client._session.connector._conns)


async def test_release_early(loop, test_client):
    async def handler(request):
        await request.read()
        return web.Response(body=b'OK')

    app = web.Application()
    app.router.add_route('GET', '/', handler)

    client = await test_client(app)
    resp = await client.get('/')
    assert resp.closed
    assert 1 == len(client._session.connector._conns)


async def test_HTTP_304(loop, test_client):
    async def handler(request):
        body = await request.read()
        assert b'' == body
        return web.Response(status=304)

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await test_client(app)

    resp = await client.get('/')
    assert resp.status == 304
    content = await resp.read()
    assert content == b''


async def test_HTTP_304_WITH_BODY(loop, test_client):
    async def handler(request):
        body = await request.read()
        assert b'' == body
        return web.Response(body=b'test', status=304)

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await test_client(app)

    resp = await client.get('/')
    assert resp.status == 304
    content = await resp.read()
    assert content == b''


async def test_auto_header_user_agent(loop, test_client):
    async def handler(request):
        assert 'aiohttp' in request.headers['user-agent']
        return web.Response()

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await test_client(app)

    resp = await client.get('/')
    assert 200, resp.status


async def test_skip_auto_headers_user_agent(loop, test_client):
    async def handler(request):
        assert hdrs.USER_AGENT not in request.headers
        return web.Response()

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await test_client(app)

    resp = await client.get('/', skip_auto_headers=['user-agent'])
    assert 200 == resp.status


async def test_skip_default_auto_headers_user_agent(loop, test_client):
    async def handler(request):
        assert hdrs.USER_AGENT not in request.headers
        return web.Response()

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await test_client(app, skip_auto_headers=['user-agent'])

    resp = await client.get('/')
    assert 200 == resp.status


async def test_skip_auto_headers_content_type(loop, test_client):
    async def handler(request):
        assert hdrs.CONTENT_TYPE not in request.headers
        return web.Response()

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await test_client(app)

    resp = await client.get('/', skip_auto_headers=['content-type'])
    assert 200 == resp.status


async def test_post_data_bytesio(loop, test_client):
    data = b'some buffer'

    async def handler(request):
        assert len(data) == request.content_length
        val = await request.read()
        assert data == val
        return web.Response()

    app = web.Application()
    app.router.add_route('POST', '/', handler)
    client = await test_client(app)

    resp = await client.post('/', data=io.BytesIO(data))
    assert 200 == resp.status


async def test_post_data_with_bytesio_file(loop, test_client):
    data = b'some buffer'

    async def handler(request):
        post_data = await request.post()
        assert ['file'] == list(post_data.keys())
        assert data == post_data['file'].file.read()
        return web.Response()

    app = web.Application()
    app.router.add_route('POST', '/', handler)
    client = await test_client(app)

    resp = await client.post('/', data={'file': io.BytesIO(data)})
    assert 200 == resp.status


async def test_post_data_stringio(loop, test_client):
    data = 'some buffer'

    async def handler(request):
        assert len(data) == request.content_length
        assert request.headers['CONTENT-TYPE'] == 'text/plain; charset=utf-8'
        val = await request.text()
        assert data == val
        return web.Response()

    app = web.Application()
    app.router.add_route('POST', '/', handler)
    client = await test_client(app)

    resp = await client.post('/', data=io.StringIO(data))
    assert 200 == resp.status


async def test_post_data_textio_encoding(loop, test_client):
    data = 'текст'

    async def handler(request):
        assert request.headers['CONTENT-TYPE'] == 'text/plain; charset=koi8-r'
        val = await request.text()
        assert data == val
        return web.Response()

    app = web.Application()
    app.router.add_route('POST', '/', handler)
    client = await test_client(app)

    pl = aiohttp.TextIOPayload(io.StringIO(data), encoding='koi8-r')
    resp = await client.post('/', data=pl)
    assert 200 == resp.status


async def test_client_ssl(loop, ssl_ctx, test_server, test_client):
    connector = aiohttp.TCPConnector(ssl=False, loop=loop)

    async def handler(request):
        return web.Response(text='Test message')

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    server = await test_server(app, ssl=ssl_ctx)
    client = await test_client(server, connector=connector)

    resp = await client.get('/')
    assert 200 == resp.status
    txt = await resp.text()
    assert txt == 'Test message'


async def test_tcp_connector_fingerprint_ok(test_server, test_client,
                                            loop, ssl_ctx):

    fingerprint = (b'0\x9a\xc9D\x83\xdc\x91\'\x88\x91\x11\xa1d\x97\xfd'
                   b'\xcb~7U\x14D@L'
                   b'\x11\xab\x99\xa8\xae\xb7\x14\xee\x8b')

    async def handler(request):
        return web.Response(text='Test message')

    connector = aiohttp.TCPConnector(loop=loop, ssl=Fingerprint(fingerprint))
    app = web.Application()
    app.router.add_route('GET', '/', handler)
    server = await test_server(app, ssl=ssl_ctx)
    client = await test_client(server, connector=connector)

    resp = await client.get('/')
    assert resp.status == 200
    resp.close()


async def test_tcp_connector_fingerprint_fail(test_server, test_client,
                                              loop, ssl_ctx):

    fingerprint = (b'0\x9a\xc9D\x83\xdc\x91\'\x88\x91\x11\xa1d\x97\xfd'
                   b'\xcb~7U\x14D@L'
                   b'\x11\xab\x99\xa8\xae\xb7\x14\xee\x8b')

    async def handler(request):
        return web.Response(text='Test message')

    bad_fingerprint = b'\x00' * len(fingerprint)

    connector = aiohttp.TCPConnector(loop=loop,
                                     ssl=Fingerprint(bad_fingerprint))

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    server = await test_server(app, ssl=ssl_ctx)
    client = await test_client(server, connector=connector)

    with pytest.raises(ServerFingerprintMismatch) as cm:
        await client.get('/')
    exc = cm.value
    assert exc.expected == bad_fingerprint
    assert exc.got == fingerprint


async def test_format_task_get(test_server, loop):

    async def handler(request):
        return web.Response(body=b'OK')

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    server = await test_server(app)
    client = aiohttp.ClientSession(loop=loop)
    task = loop.create_task(client.get(server.make_url('/')))
    assert "{}".format(task).startswith("<Task pending")
    resp = await task
    resp.close()
    await client.close()


async def test_str_params(loop, test_client):

    async def handler(request):
        assert 'q=t est' in request.rel_url.query_string
        return web.Response()

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await test_client(app)

    resp = await client.get('/', params='q=t+est')
    assert 200 == resp.status


async def test_drop_params_on_redirect(loop, test_client):

    async def handler_redirect(request):
        return web.Response(status=301, headers={'Location': '/ok?a=redirect'})

    async def handler_ok(request):
        assert request.rel_url.query_string == 'a=redirect'
        return web.Response(status=200)

    app = web.Application()
    app.router.add_route('GET', '/ok', handler_ok)
    app.router.add_route('GET', '/redirect', handler_redirect)
    client = await test_client(app)

    resp = await client.get('/redirect', params={'a': 'initial'})
    assert resp.status == 200


async def test_drop_fragment_on_redirect(loop, test_client):

    async def handler_redirect(request):
        return web.Response(status=301, headers={'Location': '/ok#fragment'})

    async def handler_ok(request):
        return web.Response(status=200)

    app = web.Application()
    app.router.add_route('GET', '/ok', handler_ok)
    app.router.add_route('GET', '/redirect', handler_redirect)
    client = await test_client(app)

    resp = await client.get('/redirect')
    assert resp.status == 200
    assert resp.url.path == '/ok'


async def test_drop_fragment(loop, test_client):

    async def handler_ok(request):
        return web.Response(status=200)

    app = web.Application()
    app.router.add_route('GET', '/ok', handler_ok)
    client = await test_client(app)

    resp = await client.get('/ok#fragment')
    assert resp.status == 200
    assert resp.url.path == '/ok'


async def test_history(loop, test_client):
    async def handler_redirect(request):
        return web.Response(status=301, headers={'Location': '/ok'})

    async def handler_ok(request):
        return web.Response(status=200)

    app = web.Application()
    app.router.add_route('GET', '/ok', handler_ok)
    app.router.add_route('GET', '/redirect', handler_redirect)
    client = await test_client(app)

    resp = await client.get('/ok')
    assert len(resp.history) == 0
    assert resp.status == 200

    resp_redirect = await client.get('/redirect')
    assert len(resp_redirect.history) == 1
    assert resp_redirect.history[0].status == 301
    assert resp_redirect.status == 200


async def test_keepalive_closed_by_server(loop, test_client):
    async def handler(request):
        body = await request.read()
        assert b'' == body
        resp = web.Response(body=b'OK')
        resp.force_close()
        return resp

    app = web.Application()
    app.router.add_route('GET', '/', handler)

    connector = aiohttp.TCPConnector(loop=loop, limit=1)
    client = await test_client(app, connector=connector)

    resp1 = await client.get('/')
    val1 = await resp1.read()
    assert val1 == b'OK'
    resp2 = await client.get('/')
    val2 = await resp2.read()
    assert val2 == b'OK'

    assert 0 == len(client._session.connector._conns)


async def test_wait_for(loop, test_client):
    async def handler(request):
        return web.Response(body=b'OK')

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await test_client(app)

    resp = await asyncio.wait_for(client.get('/'), 10, loop=loop)
    assert resp.status == 200
    txt = await resp.text()
    assert txt == 'OK'


async def test_raw_headers(loop, test_client):
    async def handler(request):
        return web.Response()

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await test_client(app)
    resp = await client.get('/')
    assert resp.status == 200

    raw_headers = tuple((bytes(h), bytes(v)) for h, v in resp.raw_headers)
    assert raw_headers == ((b'Content-Length', b'0'),
                           (b'Content-Type', b'application/octet-stream'),
                           (b'Date', mock.ANY),
                           (b'Server', mock.ANY))
    resp.close()


async def test_204_with_gzipped_content_encoding(loop, test_client):
    async def handler(request):
        resp = web.StreamResponse(status=204)
        resp.content_length = 0
        resp.content_type = 'application/json'
        # resp.enable_compression(web.ContentCoding.gzip)
        resp.headers['Content-Encoding'] = 'gzip'
        await resp.prepare(request)
        return resp

    app = web.Application()
    app.router.add_route('DELETE', '/', handler)
    client = await test_client(app)

    resp = await client.delete('/')
    assert resp.status == 204
    assert resp.closed


async def test_timeout_on_reading_headers(loop, test_client, mocker):
    mocker.patch('aiohttp.helpers.ceil').side_effect = ceil

    async def handler(request):
        resp = web.StreamResponse()
        await asyncio.sleep(0.1, loop=loop)
        await resp.prepare(request)
        return resp

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await test_client(app)

    with pytest.raises(asyncio.TimeoutError):
        await client.get('/', timeout=0.01)


async def test_timeout_on_conn_reading_headers(loop, test_client, mocker):
    # tests case where user did not set a connection timeout

    mocker.patch('aiohttp.helpers.ceil').side_effect = ceil

    async def handler(request):
        resp = web.StreamResponse()
        await asyncio.sleep(0.1, loop=loop)
        await resp.prepare(request)
        return resp

    app = web.Application()
    app.router.add_route('GET', '/', handler)

    conn = aiohttp.TCPConnector(loop=loop)
    client = await test_client(app, connector=conn)

    with pytest.raises(asyncio.TimeoutError):
        await client.get('/', timeout=0.01)


async def test_timeout_on_session_read_timeout(loop, test_client, mocker):
    mocker.patch('aiohttp.helpers.ceil').side_effect = ceil

    async def handler(request):
        resp = web.StreamResponse()
        await asyncio.sleep(0.1, loop=loop)
        await resp.prepare(request)
        return resp

    app = web.Application()
    app.router.add_route('GET', '/', handler)

    conn = aiohttp.TCPConnector(loop=loop)
    client = await test_client(app, connector=conn, read_timeout=0.01)

    with pytest.raises(asyncio.TimeoutError):
        await client.get('/')


async def test_timeout_on_reading_data(loop, test_client, mocker):
    mocker.patch('aiohttp.helpers.ceil').side_effect = ceil
    fut = loop.create_future()

    async def handler(request):
        resp = web.StreamResponse(headers={'content-length': '100'})
        await resp.prepare(request)
        fut.set_result(None)
        await asyncio.sleep(0.2, loop=loop)
        return resp

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await test_client(app)

    resp = await client.get('/', timeout=1)
    await fut

    with pytest.raises(asyncio.TimeoutError):
        await resp.read()


async def test_timeout_none(loop, test_client, mocker):
    mocker.patch('aiohttp.helpers.ceil').side_effect = ceil

    async def handler(request):
        resp = web.StreamResponse()
        await resp.prepare(request)
        return resp

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await test_client(app)

    resp = await client.get('/', timeout=None)
    assert resp.status == 200


async def test_readline_error_on_conn_close(loop, test_client):

    async def handler(request):
        resp_ = web.StreamResponse()
        await resp_.prepare(request)

        # make sure connection is closed by client.
        with pytest.raises(aiohttp.ServerDisconnectedError):
            for _ in range(10):
                await resp_.write(b'data\n')
                await asyncio.sleep(0.5, loop=loop)
            return resp_

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    server = await test_client(app)

    session = aiohttp.ClientSession(loop=loop)
    try:
        timer_started = False
        url, headers = server.make_url('/'), {'Connection': 'Keep-alive'}
        resp = await session.get(url, headers=headers)
        with pytest.raises(aiohttp.ClientConnectionError):
            while True:
                data = await resp.content.readline()
                data = data.strip()
                if not data:
                    break
                assert data == b'data'
                if not timer_started:
                    def do_release():
                        loop.create_task(resp.release())
                    loop.call_later(1.0, do_release)
                    timer_started = True
    finally:
        await session.close()


async def test_no_error_on_conn_close_if_eof(loop, test_client):

    async def handler(request):
        resp_ = web.StreamResponse()
        await resp_.prepare(request)
        await resp_.write(b'data\n')
        await asyncio.sleep(0.5, loop=loop)
        return resp_

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    server = await test_client(app)

    session = aiohttp.ClientSession(loop=loop)
    try:
        url, headers = server.make_url('/'), {'Connection': 'Keep-alive'}
        resp = await session.get(url, headers=headers)
        while True:
            data = await resp.content.readline()
            data = data.strip()
            if not data:
                break
            assert data == b'data'

        assert resp.content.exception() is None
    finally:
        await session.close()


async def test_error_not_overwrote_on_conn_close(loop, test_client):

    async def handler(request):
        resp_ = web.StreamResponse()
        await resp_.prepare(request)
        return resp_

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    server = await test_client(app)

    session = aiohttp.ClientSession(loop=loop)
    try:
        url, headers = server.make_url('/'), {'Connection': 'Keep-alive'}
        resp = await session.get(url, headers=headers)
        resp.content.set_exception(ValueError())
    finally:
        await session.close()

    assert isinstance(resp.content.exception(), ValueError)


async def test_HTTP_200_OK_METHOD(loop, test_client):

    async def handler(request):
        return web.Response(text=request.method)

    app = web.Application()
    for meth in ('get', 'post', 'put', 'delete', 'head', 'patch', 'options'):
        app.router.add_route(meth.upper(), '/', handler)

    client = await test_client(app)
    for meth in ('get', 'post', 'put', 'delete', 'head', 'patch', 'options'):
        resp = await client.request(meth, '/')
        assert resp.status == 200
        assert len(resp.history) == 0

        content1 = await resp.read()
        content2 = await resp.read()
        assert content1 == content2
        content = await resp.text()

        if meth == 'head':
            assert b'' == content1
        else:
            assert meth.upper() == content


async def test_HTTP_200_OK_METHOD_connector(loop, test_client):

    async def handler(request):
        return web.Response(text=request.method)

    conn = aiohttp.TCPConnector(loop=loop)
    conn.clear_dns_cache()

    app = web.Application()
    for meth in ('get', 'post', 'put', 'delete', 'head'):
        app.router.add_route(meth.upper(), '/', handler)
    client = await test_client(app, connector=conn, conn_timeout=0.2)

    for meth in ('get', 'post', 'put', 'delete', 'head'):
        resp = await client.request(meth, '/')

        content1 = await resp.read()
        content2 = await resp.read()
        assert content1 == content2
        content = await resp.text()

        assert resp.status == 200
        if meth == 'head':
            assert b'' == content1
        else:
            assert meth.upper() == content


async def test_HTTP_302_REDIRECT_GET(loop, test_client):

    async def handler(request):
        return web.Response(text=request.method)

    async def redirect(request):
        raise web.HTTPFound(location='/')

    app = web.Application()
    app.router.add_get('/', handler)
    app.router.add_get('/redirect', redirect)
    client = await test_client(app)

    resp = await client.get('/redirect')
    assert 200 == resp.status
    assert 1 == len(resp.history)
    resp.close()


async def test_HTTP_302_REDIRECT_HEAD(loop, test_client):

    async def handler(request):
        return web.Response(text=request.method)

    async def redirect(request):
        raise web.HTTPFound(location='/')

    app = web.Application()
    app.router.add_get('/', handler)
    app.router.add_get('/redirect', redirect)
    app.router.add_head('/', handler)
    app.router.add_head('/redirect', redirect)
    client = await test_client(app)

    resp = await client.request('head', '/redirect')
    assert 200 == resp.status
    assert 1 == len(resp.history)
    assert resp.method == 'HEAD'
    resp.close()


async def test_HTTP_302_REDIRECT_NON_HTTP(loop, test_client):

    async def redirect(request):
        raise web.HTTPFound(location='ftp://127.0.0.1/test/')

    app = web.Application()
    app.router.add_get('/redirect', redirect)
    client = await test_client(app)

    with pytest.raises(ValueError):
        await client.get('/redirect')


async def test_HTTP_302_REDIRECT_POST(loop, test_client):

    async def handler(request):
        return web.Response(text=request.method)

    async def redirect(request):
        raise web.HTTPFound(location='/')

    app = web.Application()
    app.router.add_get('/', handler)
    app.router.add_post('/redirect', redirect)
    client = await test_client(app)

    resp = await client.post('/redirect')
    assert 200 == resp.status
    assert 1 == len(resp.history)
    txt = await resp.text()
    assert txt == 'GET'
    resp.close()


async def test_HTTP_302_REDIRECT_POST_with_content_length_header(loop,
                                                                 test_client):

    async def handler(request):
        return web.Response(text=request.method)

    async def redirect(request):
        await request.read()
        raise web.HTTPFound(location='/')

    data = json.dumps({'some': 'data'})
    app = web.Application(debug=True)
    app.router.add_get('/', handler)
    app.router.add_post('/redirect', redirect)
    client = await test_client(app)

    resp = await client.post(
        '/redirect',
        data=data,
        headers={'Content-Length': str(len(data))}
    )
    assert 200 == resp.status
    assert 1 == len(resp.history)
    txt = await resp.text()
    assert txt == 'GET'
    resp.close()


async def test_HTTP_307_REDIRECT_POST(loop, test_client):

    async def handler(request):
        return web.Response(text=request.method)

    async def redirect(request):
        await request.read()
        raise web.HTTPTemporaryRedirect(location='/')

    app = web.Application()
    app.router.add_post('/', handler)
    app.router.add_post('/redirect', redirect)
    client = await test_client(app)

    resp = await client.post('/redirect', data={'some': 'data'})
    assert 200 == resp.status
    assert 1 == len(resp.history)
    txt = await resp.text()
    assert txt == 'POST'
    resp.close()


async def test_HTTP_308_PERMANENT_REDIRECT_POST(loop, test_client):

    async def handler(request):
        return web.Response(text=request.method)

    async def redirect(request):
        await request.read()
        raise web.HTTPPermanentRedirect(location='/')

    app = web.Application()
    app.router.add_post('/', handler)
    app.router.add_post('/redirect', redirect)
    client = await test_client(app)

    resp = await client.post('/redirect', data={'some': 'data'})
    assert 200 == resp.status
    assert 1 == len(resp.history)
    txt = await resp.text()
    assert txt == 'POST'
    resp.close()


async def test_HTTP_302_max_redirects(loop, test_client):

    async def handler(request):
        return web.Response(text=request.method)

    async def redirect(request):
        count = int(request.match_info['count'])
        if count:
            raise web.HTTPFound(location='/redirect/{}'.format(count-1))
        else:
            raise web.HTTPFound(location='/')

    app = web.Application()
    app.router.add_get('/', handler)
    app.router.add_get(r'/redirect/{count:\d+}', redirect)
    client = await test_client(app)

    resp = await client.get('/redirect/5', max_redirects=2)
    assert 302 == resp.status
    assert 2 == len(resp.history)
    resp.close()


async def test_HTTP_200_GET_WITH_PARAMS(loop, test_client):

    async def handler(request):
        return web.Response(text='&'.join(
            k+'='+v for k, v in request.query.items()))

    app = web.Application()
    app.router.add_get('/', handler)
    client = await test_client(app)

    resp = await client.get('/', params={'q': 'test'})
    assert 200 == resp.status
    txt = await resp.text()
    assert txt == 'q=test'
    resp.close()


async def test_HTTP_200_GET_WITH_MultiDict_PARAMS(loop, test_client):

    async def handler(request):
        return web.Response(text='&'.join(
            k+'='+v for k, v in request.query.items()))

    app = web.Application()
    app.router.add_get('/', handler)
    client = await test_client(app)

    resp = await client.get('/', params=MultiDict([('q', 'test'),
                                                   ('q', 'test2')]))
    assert 200 == resp.status
    txt = await resp.text()
    assert txt == 'q=test&q=test2'
    resp.close()


async def test_HTTP_200_GET_WITH_MIXED_PARAMS(loop, test_client):

    async def handler(request):
        return web.Response(text='&'.join(
            k+'='+v for k, v in request.query.items()))

    app = web.Application()
    app.router.add_get('/', handler)
    client = await test_client(app)

    resp = await client.get('/?test=true', params={'q': 'test'})
    assert 200 == resp.status
    txt = await resp.text()
    assert txt == 'test=true&q=test'
    resp.close()


async def test_POST_DATA(loop, test_client):

    async def handler(request):
        data = await request.post()
        return web.json_response(dict(data))

    app = web.Application()
    app.router.add_post('/', handler)
    client = await test_client(app)

    resp = await client.post('/', data={'some': 'data'})
    assert 200 == resp.status
    content = await resp.json()
    assert content == {'some': 'data'}
    resp.close()


async def test_POST_DATA_with_explicit_formdata(loop, test_client):

    async def handler(request):
        data = await request.post()
        return web.json_response(dict(data))

    app = web.Application()
    app.router.add_post('/', handler)
    client = await test_client(app)

    form = aiohttp.FormData()
    form.add_field('name', 'text')

    resp = await client.post('/', data=form)
    assert 200 == resp.status
    content = await resp.json()
    assert content == {'name': 'text'}
    resp.close()


async def test_POST_DATA_with_charset(loop, test_client):

    async def handler(request):
        mp = await request.multipart()
        part = await mp.next()
        text = await part.text()
        return web.Response(text=text)

    app = web.Application()
    app.router.add_post('/', handler)
    client = await test_client(app)

    form = aiohttp.FormData()
    form.add_field('name', 'текст', content_type='text/plain; charset=koi8-r')

    resp = await client.post('/', data=form)
    assert 200 == resp.status
    content = await resp.text()
    assert content == 'текст'
    resp.close()


async def test_POST_DATA_formdats_with_charset(loop, test_client):

    async def handler(request):
        mp = await request.post()
        assert 'name' in mp
        return web.Response(text=mp['name'])

    app = web.Application()
    app.router.add_post('/', handler)
    client = await test_client(app)

    form = aiohttp.FormData(charset='koi8-r')
    form.add_field('name', 'текст')

    resp = await client.post('/', data=form)
    assert 200 == resp.status
    content = await resp.text()
    assert content == 'текст'
    resp.close()


async def test_POST_DATA_with_charset_post(loop, test_client):

    async def handler(request):
        data = await request.post()
        return web.Response(text=data['name'])

    app = web.Application()
    app.router.add_post('/', handler)
    client = await test_client(app)

    form = aiohttp.FormData()
    form.add_field('name', 'текст', content_type='text/plain; charset=koi8-r')

    resp = await client.post('/', data=form)
    assert 200 == resp.status
    content = await resp.text()
    assert content == 'текст'
    resp.close()


async def test_POST_DATA_with_context_transfer_encoding(loop, test_client):

    async def handler(request):
        data = await request.post()
        assert data['name'] == 'text'
        return web.Response(text=data['name'])

    app = web.Application()
    app.router.add_post('/', handler)
    client = await test_client(app)

    form = aiohttp.FormData()
    form.add_field('name', 'text', content_transfer_encoding='base64')

    resp = await client.post('/', data=form)
    assert 200 == resp.status
    content = await resp.text()
    assert content == 'text'
    resp.close()


async def test_POST_DATA_with_content_type_context_transfer_encoding(
        loop, test_client):

    async def handler(request):
        data = await request.post()
        assert data['name'] == 'text'
        return web.Response(body=data['name'])

    app = web.Application()
    app.router.add_post('/', handler)
    client = await test_client(app)

    form = aiohttp.FormData()
    form.add_field('name', 'text',
                   content_type='text/plain',
                   content_transfer_encoding='base64')

    resp = await client.post('/', data=form)
    assert 200 == resp.status
    content = await resp.text()
    assert content == 'text'
    resp.close()


async def test_POST_MultiDict(loop, test_client):

    async def handler(request):
        data = await request.post()
        assert data == MultiDict([('q', 'test1'), ('q', 'test2')])
        return web.Response()

    app = web.Application()
    app.router.add_post('/', handler)
    client = await test_client(app)

    resp = await client.post('/', data=MultiDict(
        [('q', 'test1'), ('q', 'test2')]))
    assert 200 == resp.status
    resp.close()


async def test_POST_DATA_DEFLATE(loop, test_client):

    async def handler(request):
        data = await request.post()
        return web.json_response(dict(data))

    app = web.Application()
    app.router.add_post('/', handler)
    client = await test_client(app)

    resp = await client.post('/', data={'some': 'data'}, compress=True)
    assert 200 == resp.status
    content = await resp.json()
    assert content == {'some': 'data'}
    resp.close()


async def test_POST_FILES(loop, test_client, fname):

    async def handler(request):
        data = await request.post()
        assert data['some'].filename == fname.name
        with fname.open('rb') as f:
            content1 = f.read()
        content2 = data['some'].file.read()
        assert content1 == content2
        assert data['test'].file.read() == b'data'
        return web.Response()

    app = web.Application()
    app.router.add_post('/', handler)
    client = await test_client(app)

    with fname.open() as f:
        resp = await client.post(
            '/', data={'some': f, 'test': b'data'}, chunked=True)
        assert 200 == resp.status
        resp.close()


async def test_POST_FILES_DEFLATE(loop, test_client, fname):

    async def handler(request):
        data = await request.post()
        assert data['some'].filename == fname.name
        with fname.open('rb') as f:
            content1 = f.read()
        content2 = data['some'].file.read()
        assert content1 == content2
        return web.Response()

    app = web.Application()
    app.router.add_post('/', handler)
    client = await test_client(app)

    with fname.open() as f:
        resp = await client.post(
            '/',
            data={'some': f},
            chunked=True,
            compress='deflate'
        )
        assert 200 == resp.status
        resp.close()


async def test_POST_bytes(loop, test_client):
    body = b'0' * 12345

    async def handler(request):
        data = await request.read()
        assert body == data
        return web.Response()

    app = web.Application()
    app.router.add_post('/', handler)
    client = await test_client(app)

    resp = await client.post('/', data=body)
    assert 200 == resp.status
    resp.close()


async def test_POST_bytes_too_large(loop, test_client):
    body = b'0' * (2 ** 20 + 1)

    async def handler(request):
        data = await request.content.read()
        assert body == data
        return web.Response()

    app = web.Application()
    app.router.add_post('/', handler)
    client = await test_client(app)

    with pytest.warns(ResourceWarning):
        resp = await client.post('/', data=body)

    assert 200 == resp.status
    resp.close()


async def test_POST_FILES_STR(loop, test_client, fname):

    async def handler(request):
        data = await request.post()
        with fname.open() as f:
            content1 = f.read()
        content2 = data['some']
        assert content1 == content2
        return web.Response()

    app = web.Application()
    app.router.add_post('/', handler)
    client = await test_client(app)

    with fname.open() as f:
        resp = await client.post('/', data={'some': f.read()})
        assert 200 == resp.status
        resp.close()


async def test_POST_FILES_STR_SIMPLE(loop, test_client, fname):

    async def handler(request):
        data = await request.read()
        with fname.open('rb') as f:
            content = f.read()
        assert content == data
        return web.Response()

    app = web.Application()
    app.router.add_post('/', handler)
    client = await test_client(app)

    with fname.open() as f:
        resp = await client.post('/', data=f.read())
        assert 200 == resp.status
        resp.close()


async def test_POST_FILES_LIST(loop, test_client, fname):

    async def handler(request):
        data = await request.post()
        assert fname.name == data['some'].filename
        with fname.open('rb') as f:
            content = f.read()
        assert content == data['some'].file.read()
        return web.Response()

    app = web.Application()
    app.router.add_post('/', handler)
    client = await test_client(app)

    with fname.open() as f:
        resp = await client.post('/', data=[('some', f)])
        assert 200 == resp.status
        resp.close()


async def test_POST_FILES_CT(loop, test_client, fname):

    async def handler(request):
        data = await request.post()
        assert fname.name == data['some'].filename
        assert 'text/plain' == data['some'].content_type
        with fname.open('rb') as f:
            content = f.read()
        assert content == data['some'].file.read()
        return web.Response()

    app = web.Application()
    app.router.add_post('/', handler)
    client = await test_client(app)

    with fname.open() as f:
        form = aiohttp.FormData()
        form.add_field('some', f, content_type='text/plain')
        resp = await client.post('/', data=form)
        assert 200 == resp.status
        resp.close()


async def test_POST_FILES_SINGLE(loop, test_client, fname):

    async def handler(request):
        data = await request.text()
        with fname.open('r') as f:
            content = f.read()
            assert content == data
            # if system cannot determine 'application/pgp-keys' MIME type
            # then use 'application/octet-stream' default
        assert request.content_type in ['application/pgp-keys',
                                        'text/plain',
                                        'application/octet-stream']
        assert 'content-disposition' not in request.headers

        return web.Response()

    app = web.Application()
    app.router.add_post('/', handler)
    client = await test_client(app)

    with fname.open() as f:
        resp = await client.post('/', data=f)
        assert 200 == resp.status
        resp.close()


async def test_POST_FILES_SINGLE_content_disposition(loop, test_client, fname):

    async def handler(request):
        data = await request.text()
        with fname.open('r') as f:
            content = f.read()
            assert content == data
            # if system cannot determine 'application/pgp-keys' MIME type
            # then use 'application/octet-stream' default
        assert request.content_type in ['application/pgp-keys',
                                        'text/plain',
                                        'application/octet-stream']
        assert request.headers['content-disposition'] == (
            "inline; filename=\"sample.key\"; filename*=utf-8''sample.key")

        return web.Response()

    app = web.Application()
    app.router.add_post('/', handler)
    client = await test_client(app)

    with fname.open() as f:
        resp = await client.post(
            '/', data=aiohttp.get_payload(f, disposition='inline'))
        assert 200 == resp.status
        resp.close()


async def test_POST_FILES_SINGLE_BINARY(loop, test_client, fname):

    async def handler(request):
        data = await request.read()
        with fname.open('rb') as f:
            content = f.read()
        assert content == data
        # if system cannot determine 'application/pgp-keys' MIME type
        # then use 'application/octet-stream' default
        assert request.content_type in ['application/pgp-keys',
                                        'text/plain',
                                        'application/octet-stream']
        return web.Response()

    app = web.Application()
    app.router.add_post('/', handler)
    client = await test_client(app)

    with fname.open('rb') as f:
        resp = await client.post('/', data=f)
        assert 200 == resp.status
        resp.close()


async def test_POST_FILES_IO(loop, test_client):

    async def handler(request):
        data = await request.post()
        assert b'data' == data['unknown'].file.read()
        assert data['unknown'].content_type == 'application/octet-stream'
        assert data['unknown'].filename == 'unknown'
        return web.Response()

    app = web.Application()
    app.router.add_post('/', handler)
    client = await test_client(app)

    data = io.BytesIO(b'data')
    resp = await client.post('/', data=[data])
    assert 200 == resp.status
    resp.close()


async def test_POST_FILES_IO_WITH_PARAMS(loop, test_client):

    async def handler(request):
        data = await request.post()
        assert data['test'] == 'true'
        assert data['unknown'].content_type == 'application/octet-stream'
        assert data['unknown'].filename == 'unknown'
        assert data['unknown'].file.read() == b'data'
        assert data.getall('q') == ['t1', 't2']

        return web.Response()

    app = web.Application()
    app.router.add_post('/', handler)
    client = await test_client(app)

    data = io.BytesIO(b'data')
    resp = await client.post(
        '/',
        data=(('test', 'true'),
              MultiDict([('q', 't1'), ('q', 't2')]), data)
    )
    assert 200 == resp.status
    resp.close()


async def test_POST_FILES_WITH_DATA(loop, test_client, fname):

    async def handler(request):
        data = await request.post()
        assert data['test'] == 'true'
        assert data['some'].content_type in ['application/pgp-keys',
                                             'text/plain; charset=utf-8',
                                             'application/octet-stream']
        assert data['some'].filename == fname.name
        with fname.open('rb') as f:
            assert data['some'].file.read() == f.read()

        return web.Response()

    app = web.Application()
    app.router.add_post('/', handler)
    client = await test_client(app)

    with fname.open() as f:
        resp = await client.post('/', data={'test': 'true', 'some': f})
        assert 200 == resp.status
        resp.close()


async def test_POST_STREAM_DATA(loop, test_client, fname):

    async def handler(request):
        assert request.content_type == 'application/octet-stream'
        content = await request.read()
        with fname.open('rb') as f:
            expected = f.read()
            assert request.content_length == len(expected)
            assert content == expected

        return web.Response()

    app = web.Application()
    app.router.add_post('/', handler)
    client = await test_client(app)

    with fname.open('rb') as f:
        data_size = len(f.read())

    @aiohttp.streamer
    async def stream(writer, fname):
        with fname.open('rb') as f:
            data = f.read(100)
            while data:
                await writer.write(data)
                data = f.read(100)

    resp = await client.post(
        '/', data=stream(fname), headers={'Content-Length': str(data_size)})
    assert 200 == resp.status
    resp.close()


async def test_POST_STREAM_DATA_no_params(loop, test_client, fname):

    async def handler(request):
        assert request.content_type == 'application/octet-stream'
        content = await request.read()
        with fname.open('rb') as f:
            expected = f.read()
            assert request.content_length == len(expected)
            assert content == expected

        return web.Response()

    app = web.Application()
    app.router.add_post('/', handler)
    client = await test_client(app)

    with fname.open('rb') as f:
        data_size = len(f.read())

    @aiohttp.streamer
    async def stream(writer):
        with fname.open('rb') as f:
            data = f.read(100)
            while data:
                await writer.write(data)
                data = f.read(100)

    resp = await client.post(
        '/', data=stream, headers={'Content-Length': str(data_size)})
    assert 200 == resp.status
    resp.close()


async def test_json(loop, test_client):

    async def handler(request):
        assert request.content_type == 'application/json'
        data = await request.json()
        return web.Response(body=aiohttp.JsonPayload(data))

    app = web.Application()
    app.router.add_post('/', handler)
    client = await test_client(app)

    resp = await client.post('/', json={'some': 'data'})
    assert 200 == resp.status
    content = await resp.json()
    assert content == {'some': 'data'}
    resp.close()

    with pytest.raises(ValueError):
        await client.post('/', data="some data", json={'some': 'data'})


async def test_json_custom(loop, test_client):

    async def handler(request):
        assert request.content_type == 'application/json'
        data = await request.json()
        return web.Response(body=aiohttp.JsonPayload(data))

    used = False

    def dumps(obj):
        nonlocal used
        used = True
        return json.dumps(obj)

    app = web.Application()
    app.router.add_post('/', handler)
    client = await test_client(app, json_serialize=dumps)

    resp = await client.post('/', json={'some': 'data'})
    assert 200 == resp.status
    assert used
    content = await resp.json()
    assert content == {'some': 'data'}
    resp.close()

    with pytest.raises(ValueError):
        await client.post('/', data="some data", json={'some': 'data'})


async def test_expect_continue(loop, test_client):
    expect_called = False

    async def handler(request):
        data = await request.post()
        assert data == {'some': 'data'}
        return web.Response()

    async def expect_handler(request):
        nonlocal expect_called
        expect = request.headers.get(hdrs.EXPECT)
        if expect.lower() == "100-continue":
            request.transport.write(b"HTTP/1.1 100 Continue\r\n\r\n")
            expect_called = True

    app = web.Application()
    app.router.add_post('/', handler, expect_handler=expect_handler)
    client = await test_client(app)

    resp = await client.post('/', data={'some': 'data'}, expect100=True)
    assert 200 == resp.status
    resp.close()
    assert expect_called


async def test_encoding_deflate(loop, test_client):

    async def handler(request):
        resp = web.Response(text='text')
        resp.enable_chunked_encoding()
        resp.enable_compression(web.ContentCoding.deflate)
        return resp

    app = web.Application()
    app.router.add_get('/', handler)
    client = await test_client(app)

    resp = await client.get('/')
    assert 200 == resp.status
    txt = await resp.text()
    assert txt == 'text'
    resp.close()


async def test_encoding_deflate_nochunk(loop, test_client):

    async def handler(request):
        resp = web.Response(text='text')
        resp.enable_compression(web.ContentCoding.deflate)
        return resp

    app = web.Application()
    app.router.add_get('/', handler)
    client = await test_client(app)

    resp = await client.get('/')
    assert 200 == resp.status
    txt = await resp.text()
    assert txt == 'text'
    resp.close()


async def test_encoding_gzip(loop, test_client):

    async def handler(request):
        resp = web.Response(text='text')
        resp.enable_chunked_encoding()
        resp.enable_compression(web.ContentCoding.gzip)
        return resp

    app = web.Application()
    app.router.add_get('/', handler)
    client = await test_client(app)

    resp = await client.get('/')
    assert 200 == resp.status
    txt = await resp.text()
    assert txt == 'text'
    resp.close()


async def test_encoding_gzip_write_by_chunks(loop, test_client):

    async def handler(request):
        resp = web.StreamResponse()
        resp.enable_compression(web.ContentCoding.gzip)
        await resp.prepare(request)
        await resp.write(b'0')
        await resp.write(b'0')
        return resp

    app = web.Application()
    app.router.add_get('/', handler)
    client = await test_client(app)

    resp = await client.get('/')
    assert 200 == resp.status
    txt = await resp.text()
    assert txt == '00'
    resp.close()


async def test_encoding_gzip_nochunk(loop, test_client):

    async def handler(request):
        resp = web.Response(text='text')
        resp.enable_compression(web.ContentCoding.gzip)
        return resp

    app = web.Application()
    app.router.add_get('/', handler)
    client = await test_client(app)

    resp = await client.get('/')
    assert 200 == resp.status
    txt = await resp.text()
    assert txt == 'text'
    resp.close()


async def test_bad_payload_compression(loop, test_client):

    async def handler(request):
        resp = web.Response(text='text')
        resp.headers['Content-Encoding'] = 'gzip'
        return resp

    app = web.Application()
    app.router.add_get('/', handler)
    client = await test_client(app)

    resp = await client.get('/')
    assert 200 == resp.status

    with pytest.raises(aiohttp.ClientPayloadError):
        await resp.read()

    resp.close()


async def test_bad_payload_chunked_encoding(loop, test_client):

    async def handler(request):
        resp = web.StreamResponse()
        resp.force_close()
        resp._length_check = False
        resp.headers['Transfer-Encoding'] = 'chunked'
        writer = await resp.prepare(request)
        await writer.write(b'9\r\n\r\n')
        await writer.write_eof()
        return resp

    app = web.Application()
    app.router.add_get('/', handler)
    client = await test_client(app)

    resp = await client.get('/')
    assert 200 == resp.status

    with pytest.raises(aiohttp.ClientPayloadError):
        await resp.read()

    resp.close()


async def test_bad_payload_content_length(loop, test_client):

    async def handler(request):
        resp = web.Response(text='text')
        resp.headers['Content-Length'] = '10000'
        resp.force_close()
        return resp

    app = web.Application()
    app.router.add_get('/', handler)
    client = await test_client(app)

    resp = await client.get('/')
    assert 200 == resp.status

    with pytest.raises(aiohttp.ClientPayloadError):
        await resp.read()

    resp.close()


async def test_payload_content_length_by_chunks(loop, test_client):

    async def handler(request):
        resp = web.StreamResponse(headers={'content-length': '3'})
        await resp.prepare(request)
        await resp.write(b'answer')
        await resp.write(b'two')
        request.transport.close()
        return resp

    app = web.Application()
    app.router.add_get('/', handler)
    client = await test_client(app)

    resp = await client.get('/')
    data = await resp.read()
    assert data == b'ans'
    resp.close()


async def test_chunked(loop, test_client):

    async def handler(request):
        resp = web.Response(text='text')
        resp.enable_chunked_encoding()
        return resp

    app = web.Application()
    app.router.add_get('/', handler)
    client = await test_client(app)

    resp = await client.get('/')
    assert 200 == resp.status
    assert resp.headers['Transfer-Encoding'] == 'chunked'
    txt = await resp.text()
    assert txt == 'text'
    resp.close()


async def test_shortcuts(test_client, loop):

    async def handler(request):
        return web.Response(text=request.method)

    app = web.Application()
    for meth in ('get', 'post', 'put', 'delete', 'head', 'patch', 'options'):
        app.router.add_route(meth.upper(), '/', handler)
    client = await test_client(lambda loop: app)

    for meth in ('get', 'post', 'put', 'delete', 'head', 'patch', 'options'):
        coro = getattr(client.session, meth)
        resp = await coro(client.make_url('/'))

        assert resp.status == 200
        assert len(resp.history) == 0

        content1 = await resp.read()
        content2 = await resp.read()
        assert content1 == content2
        content = await resp.text()

        if meth == 'head':
            assert b'' == content1
        else:
            assert meth.upper() == content


async def test_cookies(test_client, loop):

    async def handler(request):
        assert request.cookies.keys() == {'test1', 'test3'}
        assert request.cookies['test1'] == '123'
        assert request.cookies['test3'] == '456'
        return web.Response()

    c = http.cookies.Morsel()
    c.set('test3', '456', '456')

    app = web.Application()
    app.router.add_get('/', handler)
    client = await test_client(
        app, cookies={'test1': '123', 'test2': c})

    resp = await client.get('/')
    assert 200 == resp.status
    resp.close()


async def test_morsel_with_attributes(test_client, loop):
    # A comment from original test:
    #
    # No cookie attribute should pass here
    # they are only used as filters
    # whether to send particular cookie or not.
    # E.g. if cookie expires it just becomes thrown away.
    # Server who sent the cookie with some attributes
    # already knows them, no need to send this back again and again

    async def handler(request):
        assert request.cookies.keys() == {'test3'}
        assert request.cookies['test3'] == '456'
        return web.Response()

    c = http.cookies.Morsel()
    c.set('test3', '456', '456')
    c['httponly'] = True
    c['secure'] = True
    c['max-age'] = 1000

    app = web.Application()
    app.router.add_get('/', handler)
    client = await test_client(app, cookies={'test2': c})

    resp = await client.get('/')
    assert 200 == resp.status
    resp.close()


async def test_set_cookies(test_client, loop):

    async def handler(request):
        ret = web.Response()
        ret.set_cookie('c1', 'cookie1')
        ret.set_cookie('c2', 'cookie2')
        ret.headers.add('Set-Cookie',
                        'ISAWPLB{A7F52349-3531-4DA9-8776-F74BC6F4F1BB}='
                        '{925EC0B8-CB17-4BEB-8A35-1033813B0523}; '
                        'HttpOnly; Path=/')
        return ret

    app = web.Application()
    app.router.add_get('/', handler)
    client = await test_client(lambda loop: app)

    with mock.patch('aiohttp.client_reqrep.client_logger') as m_log:
        resp = await client.get('/')
        assert 200 == resp.status
        cookie_names = {c.key for c in client.session.cookie_jar}
        assert cookie_names == {'c1', 'c2'}
        resp.close()

        m_log.warning.assert_called_with('Can not load response cookies: %s',
                                         mock.ANY)


async def test_request_conn_error(loop):
    client = aiohttp.ClientSession(loop=loop)
    with pytest.raises(aiohttp.ClientConnectionError):
        await client.get('http://0.0.0.0:1')
    await client.close()


@pytest.mark.xfail
async def test_broken_connection(loop, test_client):

    async def handler(request):
        request.transport.close()
        return web.Response(text='answer'*1000)

    app = web.Application()
    app.router.add_get('/', handler)
    client = await test_client(app)

    with pytest.raises(aiohttp.ClientResponseError):
        await client.get('/')


async def test_broken_connection_2(loop, test_client):

    async def handler(request):
        resp = web.StreamResponse(headers={'content-length': '1000'})
        await resp.prepare(request)
        await resp.write(b'answer')
        request.transport.close()
        return resp

    app = web.Application()
    app.router.add_get('/', handler)
    client = await test_client(app)

    resp = await client.get('/')
    with pytest.raises(aiohttp.ClientPayloadError):
        await resp.read()
    resp.close()


async def test_custom_headers(loop, test_client):

    async def handler(request):
        assert request.headers["x-api-key"] == "foo"
        return web.Response()

    app = web.Application()
    app.router.add_post('/', handler)
    client = await test_client(lambda loop: app)

    resp = await client.post('/', headers={
        "Content-Type": "application/json",
        "x-api-key": "foo"})
    assert resp.status == 200


async def test_redirect_to_absolute_url(loop, test_client):

    async def handler(request):
        return web.Response(text=request.method)

    async def redirect(request):
        raise web.HTTPFound(location=client.make_url('/'))

    app = web.Application()
    app.router.add_get('/', handler)
    app.router.add_get('/redirect', redirect)

    client = await test_client(app)
    resp = await client.get('/redirect')
    assert 200 == resp.status
    resp.close()


async def test_redirect_without_location_header(loop, test_client):
    body = b'redirect'

    async def handler_redirect(request):
        return web.Response(status=301, body=body)

    app = web.Application()
    app.router.add_route('GET', '/redirect', handler_redirect)
    client = await test_client(app)

    resp = await client.get('/redirect')
    data = await resp.read()
    assert data == body


async def test_chunked_deprecated(loop, test_client):

    async def handler_redirect(request):
        return web.Response(status=301)

    app = web.Application()
    app.router.add_route('GET', '/redirect', handler_redirect)
    client = await test_client(app)

    with pytest.warns(DeprecationWarning):
        await client.post('/', chunked=1024)


async def test_raise_for_status(loop, test_client):

    async def handler_redirect(request):
        raise web.HTTPBadRequest()

    app = web.Application()
    app.router.add_route('GET', '/', handler_redirect)
    client = await test_client(app, raise_for_status=True)

    with pytest.raises(aiohttp.ClientResponseError):
        await client.get('/')


async def test_invalid_idna(loop):
    session = aiohttp.ClientSession(loop=loop)
    try:
        with pytest.raises(aiohttp.InvalidURL):
            await session.get('http://\u2061owhefopw.com')
    finally:
        await session.close()


async def test_creds_in_auth_and_url(loop):
    session = aiohttp.ClientSession(loop=loop)
    try:
        with pytest.raises(ValueError):
            await session.get('http://user:pass@example.com',
                              auth=aiohttp.BasicAuth('user2', 'pass2'))
    finally:
        await session.close()


async def test_drop_auth_on_redirect_to_other_host(test_server, loop):

    async def srv1(request):
        assert request.host == 'host1.com'
        assert request.headers['Authorization'] == 'Basic dXNlcjpwYXNz'
        raise web.HTTPFound('http://host2.com/path2')

    async def srv2(request):
        assert request.host == 'host2.com'
        assert 'Authorization' not in request.headers
        return web.Response()

    app = web.Application()
    app.router.add_route('GET', '/path1', srv1)
    app.router.add_route('GET', '/path2', srv2)

    server = await test_server(app)

    class FakeResolver(AbstractResolver):

        async def resolve(self, host, port=0, family=socket.AF_INET):
            return [{'hostname': host,
                     'host': server.host,
                     'port': server.port,
                     'family': socket.AF_INET,
                     'proto': 0,
                     'flags': socket.AI_NUMERICHOST}]

        async def close(self):
            pass

    connector = aiohttp.TCPConnector(loop=loop, resolver=FakeResolver())
    async with aiohttp.ClientSession(connector=connector) as client:
        resp = await client.get(
            'http://host1.com/path1',
            auth=aiohttp.BasicAuth('user', 'pass')
        )
        assert resp.status == 200
        resp = await client.get(
            'http://host1.com/path1',
            headers={'Authorization': 'Basic dXNlcjpwYXNz'}
        )
        assert resp.status == 200


async def test_async_with_session(loop):
    with pytest.warns(None) as cm:
        async with aiohttp.ClientSession(loop=loop) as session:
            pass
    assert len(cm.list) == 0

    assert session.closed


async def test_session_close_awaitable(loop):
    session = aiohttp.ClientSession(loop=loop)
    with pytest.warns(None) as cm:
        await session.close()
    assert len(cm.list) == 0

    assert session.closed


def test_close_run_until_complete_not_deprecated(loop):
    session = aiohttp.ClientSession(loop=loop)

    with pytest.warns(None) as cm:
        loop.run_until_complete(session.close())

    assert len(cm.list) == 0


async def test_close_resp_on_error_async_with_session(loop, test_server):
    async def handler(request):
        resp = web.StreamResponse(headers={'content-length': '100'})
        await resp.prepare(request)
        await asyncio.sleep(0.1, loop=request.app.loop)
        return resp

    app = web.Application()
    app.router.add_get('/', handler)
    server = await test_server(app)

    async with aiohttp.ClientSession(loop=loop) as session:
        with pytest.raises(RuntimeError):
            async with session.get(server.make_url('/')) as resp:
                resp.content.set_exception(RuntimeError())
                await resp.read()

        assert len(session._connector._conns) == 0


async def test_release_resp_on_normal_exit_from_cm(loop, test_server):
    async def handler(request):
        return web.Response()

    app = web.Application()
    app.router.add_get('/', handler)
    server = await test_server(app)

    async with aiohttp.ClientSession(loop=loop) as session:
        async with session.get(server.make_url('/')) as resp:
            await resp.read()

        assert len(session._connector._conns) == 1


async def test_non_close_detached_session_on_error_cm(loop, test_server):
    async def handler(request):
        resp = web.StreamResponse(headers={'content-length': '100'})
        await resp.prepare(request)
        await asyncio.sleep(0.1, loop=request.app.loop)
        return resp

    app = web.Application()
    app.router.add_get('/', handler)
    server = await test_server(app)

    session = aiohttp.ClientSession(loop=loop)
    cm = session.get(server.make_url('/'))
    assert not session.closed
    with pytest.raises(RuntimeError):
        async with cm as resp:
            resp.content.set_exception(RuntimeError())
            await resp.read()
    assert not session.closed


async def test_close_detached_session_on_non_existing_addr(loop):
    class FakeResolver(AbstractResolver):
        async def resolve(host, port=0, family=socket.AF_INET):
            return {}

        async def close(self):
            pass

    connector = aiohttp.TCPConnector(resolver=FakeResolver(),
                                     loop=loop)

    session = aiohttp.ClientSession(connector=connector)

    async with session:
        cm = session.get('http://non-existing.example.com')
        assert not session.closed
        with pytest.raises(Exception):
            await cm

    assert session.closed


async def test_aiohttp_request_context_manager(loop, test_server):
    async def handler(request):
        return web.Response()

    app = web.Application()
    app.router.add_get('/', handler)
    server = await test_server(app)

    async with aiohttp.request('GET', server.make_url('/'), loop=loop) as resp:
        await resp.read()
        assert resp.status == 200


async def test_aiohttp_request_ctx_manager_not_found(loop):

    with pytest.raises(aiohttp.ClientConnectionError):
        async with aiohttp.request('GET', 'http://wrong-dns-name.com',
                                   loop=loop):
            assert False, "never executed"  # pragma: no cover


async def test_aiohttp_request_coroutine(loop, test_server):
    async def handler(request):
        return web.Response()

    app = web.Application()
    app.router.add_get('/', handler)
    server = await test_server(app)

    with pytest.raises(TypeError):
        await aiohttp.request('GET', server.make_url('/'), loop=loop)


@asyncio.coroutine
def test_yield_from_in_session_request(test_client):
    # a test for backward compatibility with yield from syntax
    async def handler(request):
        return web.Response()

    app = web.Application()
    app.router.add_get('/', handler)

    client = yield from test_client(app)
    resp = yield from client.get('/')
    assert resp.status == 200


@asyncio.coroutine
def test_close_context_manager(test_client):
    # a test for backward compatibility with yield from syntax
    async def handler(request):
        return web.Response()

    app = web.Application()
    app.router.add_get('/', handler)

    client = yield from test_client(app)
    ctx = client.get('/')
    ctx.close()
    assert not ctx._coro.cr_running


async def test_session_auth(test_client):
    async def handler(request):
        return web.json_response({'headers': dict(request.headers)})

    app = web.Application()
    app.router.add_get('/', handler)

    client = await test_client(app, auth=aiohttp.BasicAuth("login", "pass"))

    r = await client.get('/')
    assert r.status == 200
    content = await r.json()
    assert content['headers']["Authorization"] == "Basic bG9naW46cGFzcw=="


async def test_session_auth_override(test_client):
    async def handler(request):
        return web.json_response({'headers': dict(request.headers)})

    app = web.Application()
    app.router.add_get('/', handler)

    client = await test_client(app, auth=aiohttp.BasicAuth("login", "pass"))

    r = await client.get('/', auth=aiohttp.BasicAuth("other_login", "pass"))
    assert r.status == 200
    content = await r.json()
    val = content['headers']["Authorization"]
    assert val == "Basic b3RoZXJfbG9naW46cGFzcw=="


async def test_session_auth_header_conflict(test_client):
    async def handler(request):
        return web.Response()

    app = web.Application()
    app.router.add_get('/', handler)

    client = await test_client(app, auth=aiohttp.BasicAuth("login", "pass"))
    headers = {'Authorization': "Basic b3RoZXJfbG9naW46cGFzcw=="}
    with pytest.raises(ValueError):
        await client.get('/', headers=headers)


async def test_session_headers(test_client):
    async def handler(request):
        return web.json_response({'headers': dict(request.headers)})

    app = web.Application()
    app.router.add_get('/', handler)

    client = await test_client(app, headers={"X-Real-IP": "192.168.0.1"})

    r = await client.get('/')
    assert r.status == 200
    content = await r.json()
    assert content['headers']["X-Real-IP"] == "192.168.0.1"


async def test_session_headers_merge(test_client):
    async def handler(request):
        return web.json_response({'headers': dict(request.headers)})

    app = web.Application()
    app.router.add_get('/', handler)

    client = await test_client(app, headers=[
        ("X-Real-IP", "192.168.0.1"),
        ("X-Sent-By", "requests")])

    r = await client.get('/', headers={"X-Sent-By": "aiohttp"})
    assert r.status == 200
    content = await r.json()
    assert content['headers']["X-Real-IP"] == "192.168.0.1"
    assert content['headers']["X-Sent-By"] == "aiohttp"


async def test_multidict_headers(test_client):
    async def handler(request):
        assert await request.read() == data
        return web.Response()

    app = web.Application()
    app.router.add_post('/', handler)

    client = await test_client(app)

    data = b'sample data'

    r = await client.post('/', data=data,
                          headers=MultiDict(
                              {'Content-Length': str(len(data))}))
    assert r.status == 200


async def test_request_conn_closed(test_client):
    async def handler(request):
        request.transport.close()
        return web.Response()

    app = web.Application()
    app.router.add_get('/', handler)

    client = await test_client(app)
    with pytest.raises(aiohttp.ServerDisconnectedError):
        resp = await client.get('/')
        await resp.read()


async def test_dont_close_explicit_connector(test_client):
    async def handler(request):
        return web.Response()

    app = web.Application()
    app.router.add_get('/', handler)

    client = await test_client(app)
    r = await client.get('/')
    await r.read()

    assert 1 == len(client.session.connector._conns)


async def test_server_close_keepalive_connection(loop):

    class Proto(asyncio.Protocol):

        def connection_made(self, transport):
            self.transp = transport
            self.data = b''

        def data_received(self, data):
            self.data += data
            if data.endswith(b'\r\n\r\n'):
                self.transp.write(
                    b'HTTP/1.1 200 OK\r\n'
                    b'CONTENT-LENGTH: 2\r\n'
                    b'CONNECTION: close\r\n'
                    b'\r\n'
                    b'ok')
                self.transp.close()

        def connection_lost(self, exc):
            self.transp = None

    server = await loop.create_server(
        Proto, '127.0.0.1', unused_port())

    addr = server.sockets[0].getsockname()

    connector = aiohttp.TCPConnector(loop=loop, limit=1)
    session = aiohttp.ClientSession(loop=loop, connector=connector)

    url = 'http://{}:{}/'.format(*addr)
    for i in range(2):
        r = await session.request('GET', url)
        await r.read()
        assert 0 == len(connector._conns)
    await session.close()
    connector.close()
    server.close()
    await server.wait_closed()


async def test_handle_keepalive_on_closed_connection(loop):

    class Proto(asyncio.Protocol):

        def connection_made(self, transport):
            self.transp = transport
            self.data = b''

        def data_received(self, data):
            self.data += data
            if data.endswith(b'\r\n\r\n'):
                self.transp.write(
                    b'HTTP/1.1 200 OK\r\n'
                    b'CONTENT-LENGTH: 2\r\n'
                    b'\r\n'
                    b'ok')
                self.transp.close()

        def connection_lost(self, exc):
            self.transp = None

    server = await loop.create_server(
        Proto, '127.0.0.1', unused_port())

    addr = server.sockets[0].getsockname()

    connector = aiohttp.TCPConnector(loop=loop, limit=1)
    session = aiohttp.ClientSession(loop=loop, connector=connector)

    url = 'http://{}:{}/'.format(*addr)

    r = await session.request('GET', url)
    await r.read()
    assert 1 == len(connector._conns)

    with pytest.raises(aiohttp.ClientConnectionError):
        await session.request('GET', url)
    assert 0 == len(connector._conns)

    await session.close()
    connector.close()
    server.close()
    await server.wait_closed()


async def test_error_in_performing_request(loop, ssl_ctx,
                                           test_client, test_server):
    async def handler(request):
        return web.Response()

    def exception_handler(loop, context):
        # skip log messages about destroyed but pending tasks
        pass

    loop.set_exception_handler(exception_handler)

    app = web.Application()
    app.router.add_route('GET', '/', handler)

    server = await test_server(app, ssl=ssl_ctx)

    conn = aiohttp.TCPConnector(limit=1, loop=loop)
    client = await test_client(server, connector=conn)

    with pytest.raises(aiohttp.ClientConnectionError):
        await client.get('/')

    # second try should not hang
    with pytest.raises(aiohttp.ClientConnectionError):
        await client.get('/')


async def test_await_after_cancelling(loop, test_client):

    async def handler(request):
        return web.Response()

    app = web.Application()
    app.router.add_route('GET', '/', handler)

    client = await test_client(app)

    fut1 = loop.create_future()
    fut2 = loop.create_future()

    async def fetch1():
        resp = await client.get('/')
        assert resp.status == 200
        fut1.set_result(None)
        with pytest.raises(asyncio.CancelledError):
            await fut2
        resp.release()

    async def fetch2():
        await fut1
        resp = await client.get('/')
        assert resp.status == 200

    async def canceller():
        await fut1
        fut2.cancel()

    await asyncio.gather(fetch1(), fetch2(), canceller(), loop=loop)
