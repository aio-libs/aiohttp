#!/usr/bin/env python3

import asyncio

from aiohttp import ClientSession, WSMsgType


async def client(url: str, name: str) -> None:
    async with ClientSession(base_url=url) as session:
        async with session.ws_connect("/getCaseCount") as ws:
            msg = await ws.receive()
            assert msg.type is WSMsgType.TEXT
            num_tests = int(msg.data)

        for i in range(1, num_tests + 1):
            async with session.ws_connect(
                "/runCase", params={"case": i, "agent": name}
            ) as ws:
                async for msg in ws:
                    if msg.type is WSMsgType.TEXT:
                        await ws.send_str(msg.data)
                    elif msg.type is WSMsgType.BINARY:
                        await ws.send_bytes(msg.data)
                    else:
                        break

        async with session.ws_connect("/updateReports", params={"agent": name}) as ws:
            pass


if __name__ == "__main__":  # pragma: no branch
    asyncio.run(client("http://localhost:9001", "aiohttp"))
