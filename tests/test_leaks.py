import pathlib
import platform
import subprocess
import sys

import pytest

IS_PYPY = platform.python_implementation() == "PyPy"


@pytest.mark.skipif(IS_PYPY, reason="gc.DEBUG_LEAK not available on PyPy")
@pytest.mark.parametrize(
    ("script", "message"),
    [
        (
            # Test that ClientResponse is collected after server disconnects.
            # https://github.com/aio-libs/aiohttp/issues/10535
            "check_for_client_response_leak.py",
            "ClientResponse leaked",
        ),
        (
            # Test that Request object is collected when the handler raises.
            # https://github.com/aio-libs/aiohttp/issues/10548
            "check_for_request_leak.py",
            "Request leaked",
        ),
    ],
)
def test_leak(script: str, message: str) -> None:
    """Run isolated leak test script and check for leaks."""
    leak_test_script = pathlib.Path(__file__).parent.joinpath("isolated", script)

    with subprocess.Popen(
        [sys.executable, "-u", str(leak_test_script)],
        stdout=subprocess.PIPE,
    ) as proc:
        assert proc.wait() == 0, message
