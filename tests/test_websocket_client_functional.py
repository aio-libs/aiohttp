import aiohttp
import asyncio
import pytest
from aiohttp import helpers, hdrs, web


@pytest.mark.run_loop
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

    msg = yield from resp.receive()
    assert msg.data == 'ask/answer'
    yield from resp.close()


@pytest.mark.run_loop
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

    msg = yield from resp.receive()
    assert msg.data == b'ask/answer'

    yield from resp.close()


@pytest.mark.run_loop
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
    assert msg.tp == aiohttp.MsgType.binary
    assert msg.data == b'ask/answer'

    msg = yield from resp.receive()
    assert msg.tp == aiohttp.MsgType.close

    yield from resp.close()
    yield from closed


@pytest.mark.run_loop
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
    assert msg.tp == aiohttp.MsgType.pong

    msg = yield from resp.receive()
    assert msg.tp == aiohttp.MsgType.ping
    resp.pong()

    msg = yield from resp.receive()
    assert msg.data == b'ask/answer'

    msg = yield from resp.receive()
    assert msg.tp == aiohttp.MsgType.close

    yield from closed


@pytest.mark.run_loop
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
    assert msg.tp == aiohttp.MsgType.closed


@pytest.mark.run_loop
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
    assert msg.tp == aiohttp.MsgType.close
    assert resp.closed

    msg = yield from resp.receive()
    assert msg.tp == aiohttp.MsgType.closed

    yield from closed


@pytest.mark.run_loop
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
    assert msg.tp == aiohttp.MsgType.close
    assert msg.data == 1000
    assert msg.extra == ''
    assert not resp.closed

    yield from resp.close()
    yield from closed
    assert resp.closed


@pytest.mark.run_loop
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
    assert msg.tp == aiohttp.MsgType.text

    msg = yield from resp.close()
    assert resp.closed
    assert isinstance(resp.exception(), asyncio.TimeoutError)


@pytest.mark.run_loop
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


@pytest.mark.run_loop
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


@pytest.mark.run_loop
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
