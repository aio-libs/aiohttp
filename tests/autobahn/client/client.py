#!/usr/bin/env python3

import asyncio

from aiohttp import ClientConnectionError, ClientSession, WSMsgType


async def get_case_count(session: ClientSession) -> int:
    # Docker publishes the fuzzingserver's port before wstest starts accepting
    # connections, so the first attempt can be dropped mid-handshake. Retry
    # until the server is actually ready.
    for _ in range(30):
        try:
            async with session.ws_connect("/getCaseCount") as ws:
                msg = await ws.receive()
                assert msg.type is WSMsgType.TEXT
                return int(msg.data)
        except ClientConnectionError:
            await asyncio.sleep(0.5)
    raise RuntimeError("autobahn fuzzingserver did not become ready in time")


async def client(url: str, name: str) -> None:
    async with ClientSession(base_url=url) as session:
        num_tests = await get_case_count(session)

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
