#!/usr/bin/env python3
import asyncio

import aiohttp


async def fetch(session: aiohttp.ClientSession) -> None:
    print("Query http://httpbin.org/get")
    async with session.get("http://httpbin.org/get") as resp:
        print(resp.status)
        data = await resp.json()
        print(data)


async def go() -> None:
    async with aiohttp.ClientSession() as session:
        await fetch(session)


loop = asyncio.get_event_loop()
loop.run_until_complete(go())
loop.close()
