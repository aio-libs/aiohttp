#!/usr/bin/env python3
import asyncio
from typing import Any

import aiohttp

DEFAULT_URL = "http://httpbin.org/get"


async def fetch(
    session: aiohttp.ClientSession, url: str = DEFAULT_URL
) -> dict[str, Any]:
    print(f"Query {url}")
    async with session.get(url) as resp:
        print(resp.status)
        data: dict[str, Any] = await resp.json()
        print(data)
        return data


async def go(url: str = DEFAULT_URL) -> dict[str, Any]:
    async with aiohttp.ClientSession() as session:
        return await fetch(session, url)


if __name__ == "__main__":
    asyncio.run(go())
