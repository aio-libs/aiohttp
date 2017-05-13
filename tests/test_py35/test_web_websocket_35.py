import aiohttp
from aiohttp import helpers, web
from aiohttp.http import WSMsgType


async def test_server_ws_async_for(loop, test_server):
    closed = helpers.create_future(loop)

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        async for msg in ws:
            assert msg.type == aiohttp.WSMsgType.TEXT
            s = msg.data
            await ws.send_str(s + '/answer')
        await ws.close()
        closed.set_result(1)
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    server = await test_server(app)

    async with aiohttp.ClientSession(loop=loop) as sm:
        async with sm.ws_connect(server.make_url('/')) as resp:

            items = ['q1', 'q2', 'q3']
            for item in items:
                resp.send_str(item)
                msg = await resp.receive()
                assert msg.type == aiohttp.WSMsgType.TEXT
                assert item + '/answer' == msg.data

            await resp.close()
            await closed


async def test_closed_async_for(loop, test_client):

    closed = helpers.create_future(loop)

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        messages = []
        async for msg in ws:
            messages.append(msg)
            if 'stop' == msg.data:
                await ws.send_str('stopping')
                await ws.close()

        assert 1 == len(messages)
        assert messages[0].type == WSMsgType.TEXT
        assert messages[0].data == 'stop'

        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get('/', handler)
    client = await test_client(app)

    ws = await client.ws_connect('/')
    await ws.send_str('stop')
    msg = await ws.receive()
    assert msg.type == WSMsgType.TEXT
    assert msg.data == 'stopping'

    await ws.close()
    await closed
