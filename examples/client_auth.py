#!/usr/bin/env python3
import asyncio

import aiohttp

DEFAULT_URL = "http://httpbin.org/basic-auth/andrew/password"


async def fetch(session: aiohttp.ClientSession, url: str = DEFAULT_URL) -> str:
    print(f"Query {url}")
    async with session.get(url) as resp:
        print(resp.status)
        body = await resp.text()
        print(body)
        return body


async def go(url: str = DEFAULT_URL) -> str:
    async with aiohttp.ClientSession(
        auth=aiohttp.BasicAuth("andrew", "password")
    ) as session:
        return await fetch(session, url)


if __name__ == "__main__":
    asyncio.run(go())
