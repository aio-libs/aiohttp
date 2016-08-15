"""HTTP websocket server functional tests"""

import asyncio

import pytest

import aiohttp
from aiohttp import helpers, web


@pytest.mark.run_loop
def test_websocket_json(create_app_and_client):
    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)
        msg = yield from ws.receive()

        msg_json = msg.json()
        answer = msg_json['test']
        ws.send_str(answer)

        yield from ws.close()
        return ws

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)

    ws = yield from client.ws_connect('/')
    expected_value = 'value'
    payload = '{"test": "%s"}' % expected_value
    ws.send_str(payload)

    resp = yield from ws.receive()
    assert resp.data == expected_value


@pytest.mark.run_loop
def test_websocket_json_invalid_message(create_app_and_client):
    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)
        try:
            yield from ws.receive_json()
        except ValueError:
            ws.send_str('ValueError was raised')
        else:
            raise Exception('No Exception')
        finally:
            yield from ws.close()
        return ws

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)

    ws = yield from client.ws_connect('/')
    payload = 'NOT A VALID JSON STRING'
    ws.send_str(payload)

    data = yield from ws.receive_str()
    assert 'ValueError was raised' in data


@pytest.mark.run_loop
def test_websocket_send_json(create_app_and_client):
    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        data = yield from ws.receive_json()
        ws.send_json(data)

        yield from ws.close()
        return ws

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)

    ws = yield from client.ws_connect('/')
    expected_value = 'value'
    ws.send_json({'test': expected_value})

    data = yield from ws.receive_json()
    assert data['test'] == expected_value


@pytest.mark.run_loop
def test_websocket_receive_json(create_app_and_client):
    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        data = yield from ws.receive_json()
        answer = data['test']
        ws.send_str(answer)

        yield from ws.close()
        return ws

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)

    ws = yield from client.ws_connect('/')
    expected_value = 'value'
    payload = '{"test": "%s"}' % expected_value
    ws.send_str(payload)

    resp = yield from ws.receive()
    assert resp.data == expected_value


@pytest.mark.run_loop
def test_send_recv_text(create_app_and_client, loop):

    closed = helpers.create_future(loop)

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)
        msg = yield from ws.receive_str()
        ws.send_str(msg+'/answer')
        yield from ws.close()
        closed.set_result(1)
        return ws

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)

    ws = yield from client.ws_connect('/')
    ws.send_str('ask')
    msg = yield from ws.receive()
    assert msg.type == aiohttp.WSMsgType.TEXT
    assert 'ask/answer' == msg.data

    msg = yield from ws.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE
    assert msg.data == 1000
    assert msg.extra == ''

    assert ws.closed
    assert ws.close_code == 1000

    yield from closed


@pytest.mark.run_loop
def test_send_recv_bytes(create_app_and_client, loop):

    closed = helpers.create_future(loop)

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        msg = yield from ws.receive_bytes()
        ws.send_bytes(msg+b'/answer')
        yield from ws.close()
        closed.set_result(1)
        return ws

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)

    ws = yield from client.ws_connect('/')
    ws.send_bytes(b'ask')
    msg = yield from ws.receive()
    assert msg.type == aiohttp.WSMsgType.BINARY
    assert b'ask/answer' == msg.data

    msg = yield from ws.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE
    assert msg.data == 1000
    assert msg.extra == ''

    assert ws.closed
    assert ws.close_code == 1000

    yield from closed


@pytest.mark.run_loop
def test_send_recv_json(create_app_and_client, loop):
    closed = helpers.create_future(loop)

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)
        data = yield from ws.receive_json()
        ws.send_json({'response': data['request']})
        yield from ws.close()
        closed.set_result(1)
        return ws

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)

    ws = yield from client.ws_connect('/')

    ws.send_str('{"request": "test"}')
    msg = yield from ws.receive()
    data = msg.json()
    assert msg.type == aiohttp.WSMsgType.TEXT
    assert data['response'] == 'test'

    msg = yield from ws.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE
    assert msg.data == 1000
    assert msg.extra == ''

    yield from ws.close()

    yield from closed
