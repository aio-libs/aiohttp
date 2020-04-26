import asyncio
import time
import typing
import warnings
from datetime import datetime

import pytest

import aiohttp

last_warning: typing.Optional[str] = None


def print_warnings(message, category, filename, lineno, file=None, line=None):
    global last_warning
    text = f'{datetime.now()} | ' \
           f'{filename}:{lineno} {category.__name__:s}:{message}'
    print(text)
    # These are warnings in the 4.0a and prevent execution of the test
    if "RuntimeWarning:coroutine 'noop' was never awaited" in text:
        return None
    last_warning = text


@pytest.fixture()
def warning_setup():
    # setup warning
    old_func = warnings.showwarning
    warnings.showwarning = print_warnings
    warnings.simplefilter('default')

    yield

    warnings.showwarning = old_func


async def _test_warning():
    timeout = 480

    client = aiohttp.ClientSession()

    request_interval = 120
    request_increase = 5
    next_request = 0

    end = time.time() + timeout
    while True:
        now = time.time()
        if now > end:
            break

        if now > next_request:
            async with client.get('https://heise.de') as resp:
                status = resp.status
                await resp.text()

            request_interval += request_increase
            next_request = now + request_interval
            print(f'{datetime.now()} | '
                  f'Status: {status}, next request in {request_interval}s')

        await asyncio.sleep(1)
        if last_warning:
            await client.close()
            raise ResourceWarning(last_warning)

    await client.close()
    return None


def test_ressource_warning(warning_setup):
    loop = asyncio.get_event_loop()
    loop.run_until_complete(_test_warning())


if __name__ == '__main__':
    warnings.showwarning = print_warnings
    warnings.simplefilter('default')

    loop = asyncio.get_event_loop()
    loop.run_until_complete(_test_warning())
