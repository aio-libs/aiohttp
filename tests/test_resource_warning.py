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
    # These are warnings in the 4.0a and these prevent execution of the test
    if "RuntimeWarning:coroutine 'noop' was never awaited" in text:
        return None
    last_warning = text


@pytest.fixture()
def warning_setup(monkeypatch):
    # setup warning
    monkeypatch.setattr(warnings, 'showwarning', print_warnings)
    warnings.simplefilter('default')


async def test_resource_warning(warning_setup):
    timeout = 5 * 60

    client = aiohttp.ClientSession()

    request_interval = 30
    request_increase = 15
    next_request = 0

    end = time.time() + timeout
    while last_warning is None:
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

        await asyncio.sleep(5)

    await client.close()
    assert last_warning is None, last_warning
