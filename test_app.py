import asyncio
import pprint

import aiohttp
from aiohttp import test_utils, web


async def websocket_handler(request):
    ws = web.WebSocketResponse(heartbeat=5, compress=False)
    pprint.pprint("websocket_handler enter")
    await ws.prepare(request)
    await ws.send_str("hi")
    try:
        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                if msg.data == "close":
                    break
                await ws.send_str(msg)
    except (Exception, asyncio.CancelledError):
        pass
    finally:
        await ws.close(code=aiohttp.WSCloseCode.GOING_AWAY)
    return ws


async def run():
    app = web.Application(client_max_size=1024**10)
    app.add_routes([web.get("/land/websocket-tunnel", websocket_handler)])
    server = test_utils.TestServer(app, port=8888, scheme="http", host="127.0.0.1")
    await server.start_server()

    client = test_utils.TestClient(server)
    websession = client.session

    try:
        await run_test(websession, server)
    finally:
        await websession.close()
        await server.close()


async def run_test(
    websession: aiohttp.ClientSession, server: test_utils.TestServer
) -> None:
    pprint.pprint("run_test enter")
    url = f"{server.scheme}://{server.host}:{server.port}"
    conn = await websession.ws_connect(f"{url}/land/websocket-tunnel")

    pprint.pprint("run_test send_str hello")
    await conn.send_str("hello")
    pprint.pprint("run_test receive")
    msg = await conn.receive()
    assert msg.type == aiohttp.WSMsgType.TEXT
    pprint.pprint("run_test send_str close")
    await conn.send_str("close")
    pprint.pprint("run_test close")
    await conn.close()


if __name__ == "__main__":
    asyncio.run(run())
