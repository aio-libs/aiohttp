import asyncio

import aiohttp


async def fetch(session):
    print('Query http://httpbin.org/get')
    async with session.get(
            'http://httpbin.org/get') as resp:
        print(resp.status)
        data = await resp.json()
        print(data)


async def go(loop):
    async with aiohttp.ClientSession(loop=loop) as session:
        await fetch(session)


loop = asyncio.get_event_loop()
loop.run_until_complete(go(loop))
loop.close()
