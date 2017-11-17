import asyncio
import aiohttp

async def fetch():
    async with aiohttp.ClientSession() as session:
        await session.get('https://雜草工作室.香港')

asyncio.get_event_loop().run_until_complete(fetch())
