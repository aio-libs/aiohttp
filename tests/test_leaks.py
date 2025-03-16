import pathlib
import platform
import subprocess
import sys

import pytest

IS_PYPY = platform.python_implementation() == "PyPy"


@pytest.mark.skipif(IS_PYPY, reason="gc.DEBUG_LEAK not available on PyPy")
def test_client_response_does_not_leak_on_server_disconnected_error() -> None:
    """Test that ClientResponse is collected after server disconnects.

    https://github.com/aio-libs/aiohttp/issues/10535
    """
    leak_test_script = pathlib.Path(__file__).parent.joinpath(
        "isolated", "check_for_client_response_leak.py"
    )

    with subprocess.Popen(
        [sys.executable, "-u", str(leak_test_script)],
        stdout=subprocess.PIPE,
    ) as proc:
        buff: list[str] = []
        for line in proc.stdout:  # type: ignore[union-attr]
            buff.append(line.decode("utf-8"))
        assert proc.wait() == 0, "".join(buff)
