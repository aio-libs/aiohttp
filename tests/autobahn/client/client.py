#!/usr/bin/env python3

import asyncio

import aiohttp


async def client(url: str, name: str) -> None:
    async with aiohttp.ClientSession() as session:
        async with session.ws_connect(url + "/getCaseCount") as ws:
            msg = await ws.receive()
            assert msg.type is aiohttp.WSMsgType.TEXT
            num_tests = int(msg.data)
            print("running %d cases" % num_tests)

        for i in range(1, num_tests + 1):
            print("running test case:", i)
            text_url = url + "/runCase?case=%d&agent=%s" % (i, name)
            async with session.ws_connect(text_url) as ws:
                async for msg in ws:
                    if msg.type is aiohttp.WSMsgType.TEXT:
                        await ws.send_str(msg.data)
                    elif msg.type is aiohttp.WSMsgType.BINARY:
                        await ws.send_bytes(msg.data)
                    else:
                        break

        url = url + "/updateReports?agent=%s" % name
        async with session.ws_connect(url) as ws:
            print("finally requesting %s" % url)


async def run(url: str, name: str) -> None:
    try:
        await client(url, name)
    except Exception:
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(run("http://localhost:9001", "aiohttp"))
