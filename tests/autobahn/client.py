#!/usr/bin/env python3

import asyncio

import aiohttp


async def client(loop, url, name):
    async with aiohttp.ClientSession() as session:
        async with session.ws_connect(url + "/getCaseCount") as ws:
            num_tests = int((await ws.receive()).data)
            print("running %d cases" % num_tests)

        for i in range(1, num_tests + 1):
            print("running test case:", i)
            text_url = url + "/runCase?case=%d&agent=%s" % (i, name)
            async with session.ws_connect(text_url) as ws:
                async for msg in ws:
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        await ws.send_str(msg.data)
                    elif msg.type == aiohttp.WSMsgType.BINARY:
                        await ws.send_bytes(msg.data)
                    else:
                        break

        url = url + "/updateReports?agent=%s" % name
        async with session.ws_connect(url) as ws:
            print("finally requesting %s" % url)


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
