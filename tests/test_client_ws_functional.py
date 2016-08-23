import asyncio

import pytest

import aiohttp
from aiohttp import hdrs, helpers, web


@asyncio.coroutine
def test_send_recv_text(create_app_and_client):

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        msg = yield from ws.receive_str()
        ws.send_str(msg+'/answer')
        yield from ws.close()
        return ws

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)
    resp = yield from client.ws_connect('/')
    resp.send_str('ask')

    data = yield from resp.receive_str()
    assert data == 'ask/answer'
    yield from resp.close()


@asyncio.coroutine
def test_send_recv_bytes_bad_type(create_app_and_client):

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        msg = yield from ws.receive_str()
        ws.send_str(msg+'/answer')
        yield from ws.close()
        return ws

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)
    resp = yield from client.ws_connect('/')
    resp.send_str('ask')

    with pytest.raises(TypeError):
        yield from resp.receive_bytes()
    yield from resp.close()


@asyncio.coroutine
def test_send_recv_bytes(create_app_and_client):

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        msg = yield from ws.receive_bytes()
        ws.send_bytes(msg+b'/answer')
        yield from ws.close()
        return ws

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)
    resp = yield from client.ws_connect('/')

    resp.send_bytes(b'ask')

    data = yield from resp.receive_bytes()
    assert data == b'ask/answer'

    yield from resp.close()


@asyncio.coroutine
def test_send_recv_text_bad_type(create_app_and_client):

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        msg = yield from ws.receive_bytes()
        ws.send_bytes(msg+b'/answer')
        yield from ws.close()
        return ws

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)
    resp = yield from client.ws_connect('/')

    resp.send_bytes(b'ask')

    with pytest.raises(TypeError):
        yield from resp.receive_str()

    yield from resp.close()


@asyncio.coroutine
def test_send_recv_json(create_app_and_client):

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        data = yield from ws.receive_json()
        ws.send_json({'response': data['request']})
        yield from ws.close()
        return ws

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)
    resp = yield from client.ws_connect('/')
    payload = {'request': 'test'}
    resp.send_json(payload)

    data = yield from resp.receive_json()
    assert data['response'] == payload['request']
    yield from resp.close()


@asyncio.coroutine
def test_ping_pong(create_app_and_client, loop):

    closed = helpers.create_future(loop)

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        msg = yield from ws.receive_bytes()
        ws.ping()
        ws.send_bytes(msg+b'/answer')
        try:
            yield from ws.close()
        finally:
            closed.set_result(1)
        return ws

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)
    resp = yield from client.ws_connect('/')

    resp.ping()
    resp.send_bytes(b'ask')

    msg = yield from resp.receive()
    assert msg.type == aiohttp.WSMsgType.BINARY
    assert msg.data == b'ask/answer'

    msg = yield from resp.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE

    yield from resp.close()
    yield from closed


@asyncio.coroutine
def test_ping_pong_manual(create_app_and_client, loop):

    closed = helpers.create_future(loop)

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        msg = yield from ws.receive_bytes()
        ws.ping()
        ws.send_bytes(msg+b'/answer')
        try:
            yield from ws.close()
        finally:
            closed.set_result(1)
        return ws

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)
    resp = yield from client.ws_connect('/', autoping=False)

    resp.ping()
    resp.send_bytes(b'ask')

    msg = yield from resp.receive()
    assert msg.type == aiohttp.WSMsgType.PONG

    msg = yield from resp.receive()
    assert msg.type == aiohttp.WSMsgType.PING
    resp.pong()

    msg = yield from resp.receive()
    assert msg.data == b'ask/answer'

    msg = yield from resp.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE

    yield from closed


@asyncio.coroutine
def test_close(create_app_and_client):

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        yield from ws.receive_bytes()
        ws.send_str('test')

        yield from ws.receive()
        return ws

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)
    resp = yield from client.ws_connect('/')

    resp.send_bytes(b'ask')

    closed = yield from resp.close()
    assert closed
    assert resp.closed
    assert resp.close_code == 1000

    msg = yield from resp.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSED


@asyncio.coroutine
def test_close_from_server(create_app_and_client, loop):

    closed = helpers.create_future(loop)

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        try:
            yield from ws.receive_bytes()
            yield from ws.close()
        finally:
            closed.set_result(1)
        return ws

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)
    resp = yield from client.ws_connect('/')

    resp.send_bytes(b'ask')

    msg = yield from resp.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE
    assert resp.closed

    msg = yield from resp.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSED

    yield from closed


@asyncio.coroutine
def test_close_manual(create_app_and_client, loop):

    closed = helpers.create_future(loop)

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        yield from ws.receive_bytes()
        ws.send_str('test')

        try:
            yield from ws.close()
        finally:
            closed.set_result(1)
        return ws

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)
    resp = yield from client.ws_connect('/', autoclose=False)
    resp.send_bytes(b'ask')

    msg = yield from resp.receive()
    assert msg.data == 'test'

    msg = yield from resp.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE
    assert msg.data == 1000
    assert msg.extra == ''
    assert not resp.closed

    yield from resp.close()
    yield from closed
    assert resp.closed


@asyncio.coroutine
def test_close_timeout(create_app_and_client, loop):

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)
        yield from ws.receive_bytes()
        ws.send_str('test')
        yield from asyncio.sleep(10, loop=loop)

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)
    resp = yield from client.ws_connect('/', timeout=0.2, autoclose=False)

    resp.send_bytes(b'ask')

    msg = yield from resp.receive()
    assert msg.data == 'test'
    assert msg.type == aiohttp.WSMsgType.TEXT

    msg = yield from resp.close()
    assert resp.closed
    assert isinstance(resp.exception(), asyncio.TimeoutError)


@asyncio.coroutine
def test_close_cancel(create_app_and_client, loop):

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)
        yield from ws.receive_bytes()
        ws.send_str('test')
        yield from asyncio.sleep(10, loop=loop)

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)
    resp = yield from client.ws_connect('/', autoclose=False)

    resp.send_bytes(b'ask')

    text = yield from resp.receive()
    assert text.data == 'test'

    t = loop.create_task(resp.close())
    yield from asyncio.sleep(0.1, loop=loop)
    t.cancel()
    yield from asyncio.sleep(0.1, loop=loop)
    assert resp.closed
    assert resp.exception() is None


@asyncio.coroutine
def test_override_default_headers(create_app_and_client, loop):

    @asyncio.coroutine
    def handler(request):
        assert request.headers[hdrs.SEC_WEBSOCKET_VERSION] == '8'
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        ws.send_str('answer')
        yield from ws.close()
        return ws

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)
    headers = {hdrs.SEC_WEBSOCKET_VERSION: '8'}
    resp = yield from client.ws_connect('/', headers=headers)
    msg = yield from resp.receive()
    assert msg.data == 'answer'
    yield from resp.close()


@asyncio.coroutine
def test_additional_headers(create_app_and_client, loop):

    @asyncio.coroutine
    def handler(request):
        assert request.headers['x-hdr'] == 'xtra'
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        ws.send_str('answer')
        yield from ws.close()
        return ws

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)
    resp = yield from client.ws_connect('/', headers={'x-hdr': 'xtra'})
    msg = yield from resp.receive()
    assert msg.data == 'answer'
    yield from resp.close()


@asyncio.coroutine
def test_recv_protocol_error(create_app_and_client):

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        yield from ws.receive_str()
        ws._writer.writer.write(b'01234' * 100)
        yield from ws.close()
        return ws

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)
    resp = yield from client.ws_connect('/')
    resp.send_str('ask')

    msg = yield from resp.receive()
    assert msg.type == aiohttp.WSMsgType.ERROR
    assert type(msg.data) is aiohttp.WebSocketError
    assert msg.data.args[0] == 'Received frame with non-zero reserved bits'
    assert msg.extra is None
    yield from resp.close()


@asyncio.coroutine
def test_recv_timeout(create_app_and_client):

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        yield from ws.receive_str()

        yield from asyncio.sleep(0.1, loop=request.app.loop)

        yield from ws.close()
        return ws

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)
    resp = yield from client.ws_connect('/')
    resp.send_str('ask')

    with pytest.raises(asyncio.TimeoutError):
        with aiohttp.Timeout(0.01, loop=app.loop):
            yield from resp.receive()

    yield from resp.close()
