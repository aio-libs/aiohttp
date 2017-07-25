import asyncio
import platform
import threading

import pytest


@pytest.mark.skipif(platform.system() == "Windows",
                    reason="the test is not valid for Windows")
@asyncio.coroutine
def test_subprocess_co(loop):
    assert isinstance(threading.current_thread(), threading._MainThread)
    proc = yield from asyncio.create_subprocess_shell(
        "exit 0", loop=loop, stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
    yield from proc.wait()
