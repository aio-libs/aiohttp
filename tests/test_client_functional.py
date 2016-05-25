"""HTTP client functional tests against aiohttp.web server"""

import aiohttp
import asyncio
import io
import os
import os.path
import pytest
import ssl
from unittest import mock

from aiohttp import hdrs, web
from aiohttp.errors import FingerprintMismatch


@pytest.fixture
def ssl_ctx():
    here = os.path.dirname(__file__)
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    ssl_ctx.load_cert_chain(
        os.path.join(here, 'sample.crt'),
        os.path.join(here, 'sample.key'))
    return ssl_ctx


@pytest.mark.run_loop
def test_keepalive_two_requests_success(create_app_and_client):
    @asyncio.coroutine
    def handler(request):
        body = yield from request.read()
        assert b'' == body
        return web.Response(body=b'OK')

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)
    resp1 = yield from client.get('/')
    yield from resp1.read()
    resp2 = yield from client.get('/')
    yield from resp2.read()

    assert 1 == len(client._session.connector._conns)


@pytest.mark.run_loop
def test_keepalive_response_released(create_app_and_client):
    @asyncio.coroutine
    def handler(request):
        body = yield from request.read()
        assert b'' == body
        return web.Response(body=b'OK')

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)

    resp1 = yield from client.get('/')
    yield from resp1.release()
    resp2 = yield from client.get('/')
    yield from resp2.release()

    assert 1 == len(client._session.connector._conns)


@pytest.mark.run_loop
def test_keepalive_server_force_close_connection(create_app_and_client):
    @asyncio.coroutine
    def handler(request):
        body = yield from request.read()
        assert b'' == body
        response = web.Response(body=b'OK')
        response.force_close()
        return response

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)

    resp1 = yield from client.get('/')
    resp1.close()
    resp2 = yield from client.get('/')
    resp2.close()

    assert 0 == len(client._session.connector._conns)


@pytest.mark.run_loop
def test_HTTP_304(create_app_and_client):
    @asyncio.coroutine
    def handler(request):
        body = yield from request.read()
        assert b'' == body
        return web.Response(status=304)

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)

    resp = yield from client.get('/')
    assert resp.status == 304
    content = yield from resp.read()
    assert content == b''


@pytest.mark.run_loop
def test_HTTP_304_WITH_BODY(create_app_and_client):
    @asyncio.coroutine
    def handler(request):
        body = yield from request.read()
        assert b'' == body
        return web.Response(body=b'test', status=304)

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)

    resp = yield from client.get('/')
    assert resp.status == 304
    content = yield from resp.read()
    assert content == b''


@pytest.mark.run_loop
def test_auto_header_user_agent(create_app_and_client):
    @asyncio.coroutine
    def handler(request):
        assert 'aiohttp' in request.headers['user-agent']
        return web.Response()

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)

    resp = yield from client.get('/')
    try:
        assert 200, resp.status
    finally:
        yield from resp.release()


@pytest.mark.run_loop
def test_skip_auto_headers_user_agent(create_app_and_client):
    @asyncio.coroutine
    def handler(request):
        assert hdrs.USER_AGENT not in request.headers
        return web.Response()

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)

    resp = yield from client.get('/',
                                 skip_auto_headers=['user-agent'])
    try:
        assert 200 == resp.status
    finally:
        yield from resp.release()


@pytest.mark.run_loop
def test_skip_default_auto_headers_user_agent(create_app_and_client):
    @asyncio.coroutine
    def handler(request):
        assert hdrs.USER_AGENT not in request.headers
        return web.Response()

    app, client = yield from create_app_and_client(client_params=dict(
        skip_auto_headers=['user-agent']))
    app.router.add_route('GET', '/', handler)

    resp = yield from client.get('/')
    try:
        assert 200 == resp.status
    finally:
        yield from resp.release()


@pytest.mark.run_loop
def test_skip_auto_headers_content_type(create_app_and_client):
    @asyncio.coroutine
    def handler(request):
        assert hdrs.CONTENT_TYPE not in request.headers
        return web.Response()

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)

    resp = yield from client.get('/',
                                 skip_auto_headers=['content-type'])
    try:
        assert 200 == resp.status
    finally:
        yield from resp.release()


@pytest.mark.run_loop
def test_post_data_bytesio(create_app_and_client):
    data = b'some buffer'

    @asyncio.coroutine
    def handler(request):
        assert len(data) == request.content_length
        val = yield from request.read()
        assert data == val
        return web.Response()

    app, client = yield from create_app_and_client()
    app.router.add_route('POST', '/', handler)

    resp = yield from client.post('/', data=io.BytesIO(data))
    try:
        assert 200 == resp.status
    finally:
        yield from resp.release()


@pytest.mark.run_loop
def test_post_data_with_bytesio_file(create_app_and_client):
    data = b'some buffer'

    @asyncio.coroutine
    def handler(request):
        post_data = yield from request.post()
        assert ['file'] == list(post_data.keys())
        assert data == post_data['file'].file.read()
        return web.Response()

    app, client = yield from create_app_and_client()
    app.router.add_route('POST', '/', handler)

    resp = yield from client.post('/', data={'file': io.BytesIO(data)})
    try:
        assert 200 == resp.status
    finally:
        yield from resp.release()


@pytest.mark.run_loop
def test_client_ssl(create_app_and_client, loop, ssl_ctx):
    connector = aiohttp.TCPConnector(verify_ssl=False, loop=loop)

    @asyncio.coroutine
    def handler(request):
        return web.HTTPOk(text='Test message')

    app, client = yield from create_app_and_client(
        server_params=dict(ssl_ctx=ssl_ctx),
        client_params=dict(connector=connector))
    app.router.add_route('GET', '/', handler)

    resp = yield from client.get('/')
    try:
        assert 200 == resp.status
        txt = yield from resp.text()
        assert txt == 'Test message'
    finally:
        yield from resp.release()


@pytest.mark.parametrize('fingerprint', [
    b'\xa2\x06G\xad\xaa\xf5\xd8\\J\x99^by;\x06=',
    b's\x93\xfd:\xed\x08\x1do\xa9\xaeq9\x1a\xe3\xc5\x7f\x89\xe7l\xf9',
    b'0\x9a\xc9D\x83\xdc\x91\'\x88\x91\x11\xa1d\x97\xfd\xcb~7U\x14D@L'
    b'\x11\xab\x99\xa8\xae\xb7\x14\xee\x8b'],
    ids=['md5', 'sha1', 'sha256'])
@pytest.mark.run_loop
def test_tcp_connector_fingerprint_ok(create_app_and_client,
                                      loop, ssl_ctx, fingerprint):
    @asyncio.coroutine
    def handler(request):
        return web.HTTPOk(text='Test message')

    connector = aiohttp.TCPConnector(loop=loop, verify_ssl=False,
                                     fingerprint=fingerprint)
    app, client = yield from create_app_and_client(
        server_params=dict(ssl_ctx=ssl_ctx),
        client_params=dict(connector=connector))
    app.router.add_route('GET', '/', handler)

    resp = yield from client.get('/')
    assert resp.status == 200
    resp.close()


@pytest.mark.parametrize('fingerprint', [
    b'\xa2\x06G\xad\xaa\xf5\xd8\\J\x99^by;\x06=',
    b's\x93\xfd:\xed\x08\x1do\xa9\xaeq9\x1a\xe3\xc5\x7f\x89\xe7l\xf9',
    b'0\x9a\xc9D\x83\xdc\x91\'\x88\x91\x11\xa1d\x97\xfd\xcb~7U\x14D@L'
    b'\x11\xab\x99\xa8\xae\xb7\x14\xee\x8b'],
    ids=['md5', 'sha1', 'sha256'])
@pytest.mark.run_loop
def test_tcp_connector_fingerprint_fail(create_app_and_client,
                                        loop, ssl_ctx, fingerprint):
    @asyncio.coroutine
    def handler(request):
        return web.HTTPOk(text='Test message')

    bad_fingerprint = b'\x00' * len(fingerprint)

    connector = aiohttp.TCPConnector(loop=loop, verify_ssl=False,
                                     fingerprint=bad_fingerprint)
    app, client = yield from create_app_and_client(
        server_params=dict(ssl_ctx=ssl_ctx),
        client_params=dict(connector=connector))
    app.router.add_route('GET', '/', handler)

    with pytest.raises(FingerprintMismatch) as cm:
        yield from client.get('/')
    exc = cm.value
    assert exc.expected == bad_fingerprint
    assert exc.got == fingerprint


@pytest.mark.run_loop
def test_format_task_get(create_server, loop):

    @asyncio.coroutine
    def handler(request):
        return web.Response(body=b'OK')

    app, url = yield from create_server()
    app.router.add_route('GET', '/', handler)
    client = aiohttp.ClientSession(loop=loop)
    task = loop.create_task(client.get(url))
    assert "{}".format(task)[:18] == "<Task pending coro"
    resp = yield from task
    resp.close()
    client.close()


@pytest.mark.run_loop
def test_str_params(create_app_and_client):
    @asyncio.coroutine
    def handler(request):
        assert 'q=t+est' in request.query_string
        return web.Response()

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)

    resp = yield from client.get('/', params='q=t+est')
    try:
        assert 200 == resp.status
    finally:
        yield from resp.release()


@pytest.mark.run_loop
def test_drop_params_on_redirect(create_app_and_client):
    @asyncio.coroutine
    def handler_redirect(request):
        return web.Response(status=301, headers={'Location': '/ok?a=redirect'})

    @asyncio.coroutine
    def handler_ok(request):
        assert request.query_string == 'a=redirect'
        return web.Response(status=200)

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/ok', handler_ok)
    app.router.add_route('GET', '/redirect', handler_redirect)

    resp = yield from client.get('/redirect', params={'a': 'initial'})
    try:
        assert resp.status == 200
    finally:
        yield from resp.release()


@pytest.mark.run_loop
def test_history(create_app_and_client):
    @asyncio.coroutine
    def handler_redirect(request):
        return web.Response(status=301, headers={'Location': '/ok'})

    @asyncio.coroutine
    def handler_ok(request):
        return web.Response(status=200)

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/ok', handler_ok)
    app.router.add_route('GET', '/redirect', handler_redirect)

    resp = yield from client.get('/ok')
    try:
        assert len(resp.history) == 0
        assert resp.status == 200
    finally:
        yield from resp.release()

    resp_redirect = yield from client.get('/redirect')
    try:
        assert len(resp_redirect.history) == 1
        assert resp_redirect.history[0].status == 301
        assert resp_redirect.status == 200
    finally:
        yield from resp_redirect.release()


@pytest.mark.run_loop
def test_keepalive_closed_by_server(create_app_and_client):
    @asyncio.coroutine
    def handler(request):
        body = yield from request.read()
        assert b'' == body
        resp = web.Response(body=b'OK')
        resp.force_close()
        return resp

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)
    resp1 = yield from client.get('/')
    val1 = yield from resp1.read()
    assert val1 == b'OK'
    resp2 = yield from client.get('/')
    val2 = yield from resp2.read()
    assert val2 == b'OK'

    assert 0 == len(client._session.connector._conns)


@pytest.mark.run_loop
def test_wait_for(create_app_and_client, loop):
    @asyncio.coroutine
    def handler(request):
        return web.Response(body=b'OK')

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)
    resp = yield from asyncio.wait_for(client.get('/'), 10, loop=loop)
    assert resp.status == 200
    txt = yield from resp.text()
    assert txt == 'OK'


@pytest.mark.run_loop
def test_raw_headers(create_app_and_client, loop):
    @asyncio.coroutine
    def handler(request):
        return web.Response()

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)
    resp = yield from client.get('/')
    assert resp.status == 200
    assert resp.raw_headers == ((b'CONTENT-LENGTH', b'0'),
                                (b'DATE', mock.ANY),
                                (b'SERVER', mock.ANY))
    resp.close()


@pytest.mark.run_loop
def test_http_request_with_version(create_app_and_client, loop, warning):
    @asyncio.coroutine
    def handler(request):
        return web.Response()

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)
    with warning(DeprecationWarning):
        resp = yield from client.get('/', version=aiohttp.HttpVersion11)
        assert resp.status == 200
        resp.close()


@pytest.mark.run_loop
def test_204_with_gzipped_content_encoding(create_app_and_client):
    @asyncio.coroutine
    def handler(request):
        resp = web.StreamResponse(status=204)
        resp.content_length = 0
        resp.content_type = 'application/json'
        # resp.enable_compression(web.ContentCoding.gzip)
        resp.headers['Content-Encoding'] = 'gzip'
        yield from resp.prepare(request)
        return resp

    app, client = yield from create_app_and_client()
    app.router.add_route('DELETE', '/', handler)
    resp = yield from client.delete('/')
    assert resp.status == 204
    yield from resp.release()
