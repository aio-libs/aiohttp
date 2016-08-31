import aiohttp
from aiohttp import helpers, web

async def test_server_ws_async_for(loop, create_server):
    closed = helpers.create_future(loop)

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        async for msg in ws:
            assert msg.type == aiohttp.MsgType.TEXT
            s = msg.data
            ws.send_str(s + '/answer')
        await ws.close()
        closed.set_result(1)
        return ws

    app, url = await create_server(proto='ws')
    app.router.add_route('GET', '/', handler)
    resp = await aiohttp.ws_connect(url, loop=loop)

    items = ['q1', 'q2', 'q3']
    for item in items:
        resp.send_str(item)
        msg = await resp.receive()
        assert msg.type == aiohttp.MsgType.TEXT
        assert item + '/answer' == msg.data

    await resp.close()
    await closed
