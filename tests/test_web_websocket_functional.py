"""HTTP websocket server functional tests"""

import asyncio
import pytest
from aiohttp import helpers, web, websocket


WS_KEY = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


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
    assert msg.tp == websocket.MSG_TEXT  # import
    assert 'ask/answer' == msg.data

    msg = yield from ws.receive()
    assert msg.tp == websocket.MSG_CLOSE  # import
    assert msg.data == 1000
    assert msg.extra == ''

    # yield from closed  FIXME

    # TODO: add receive_str(), receive_bytes() and receive_json()


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
        msg = yield from ws.receive()

        try:
            msg.json()
        except ValueError:
            ws.send_str("ValueError raised: '%s'" % msg.data)
        else:
            raise Exception("No ValueError was raised")
        finally:
            yield from ws.close()
        return ws

    app, client = yield from create_app_and_client()
    app.router.add_route('GET', '/', handler)

    ws = yield from client.ws_connect('/')
    payload = 'NOT A VALID JSON STRING'
    ws.send_str(payload)

    resp = yield from ws.receive()
    assert payload in resp.data


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
