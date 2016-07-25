import aiohttp
import asyncio


async def fetch(session):
    print('Query http://httpbin.org/basic-auth/andrew/password')
    async with session.get(
            'http://httpbin.org/basic-auth/andrew/password') as resp:
        print(resp.status)
        body = yield from resp.text()
        print(body)


async def go(loop):
    async with aiohttp.ClientSession(
            auth=aiohttp.BasicAuth('andrew', 'password'),
            loop=loop) as session:
        await go(session)


loop = asyncio.get_event_loop()
loop.run_until_complete(go())
