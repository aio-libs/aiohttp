#!/usr/bin/env python3
import asyncio

import aiohttp


async def fetch(session: aiohttp.ClientSession) -> None:
    print("Query http://httpbin.org/basic-auth/andrew/password")
    async with session.get("http://httpbin.org/basic-auth/andrew/password") as resp:
        print(resp.status)
        body = await resp.text()
        print(body)


async def go() -> None:
    async with aiohttp.ClientSession(
        auth=aiohttp.BasicAuth("andrew", "password")
    ) as session:
        await fetch(session)


loop = asyncio.get_event_loop()
loop.run_until_complete(go())
