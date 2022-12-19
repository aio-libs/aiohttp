import asyncio

import aiohttp as aiohttp


async def main():
    conn = aiohttp.TCPConnector()
    async with aiohttp.ClientSession(connector=conn) as session:
        async with session.get("http://50.50.50.50/get") as resp:
            print(resp.status)
            print(await resp.text())


asyncio.run(main())
