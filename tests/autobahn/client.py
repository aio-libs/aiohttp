#!/usr/bin/env python3

import asyncio

import aiohttp


async def client(loop, url, name):
    ws = await aiohttp.ws_connect(url + "/getCaseCount")
    num_tests = int((await ws.receive()).data)
    print("running %d cases" % num_tests)
    await ws.close()

    for i in range(1, num_tests + 1):
        print("running test case:", i)
        text_url = url + "/runCase?case=%d&agent=%s" % (i, name)
        ws = await aiohttp.ws_connect(text_url)
        while True:
            msg = await ws.receive()

            if msg.type == aiohttp.WSMsgType.text:
                await ws.send_str(msg.data)
            elif msg.type == aiohttp.WSMsgType.binary:
                await ws.send_bytes(msg.data)
            elif msg.type == aiohttp.WSMsgType.close:
                await ws.close()
                break
            else:
                break

    url = url + "/updateReports?agent=%s" % name
    ws = await aiohttp.ws_connect(url)
    await ws.close()


async def run(loop, url, name):
    try:
        await client(loop, url, name)
    except Exception:
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(run(loop, "http://localhost:9001", "aiohttp"))
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()
