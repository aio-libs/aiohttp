import pytest

import aiohttp


@pytest.mark.run_loop
async def test_async_with_session(loop):
    async with aiohttp.ClientSession(loop=loop) as session:
        pass

    assert session.closed
