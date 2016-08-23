import aiohttp

async def test_async_with_session(loop):
    async with aiohttp.ClientSession(loop=loop) as session:
        pass

    assert session.closed
