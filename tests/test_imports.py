import platform
import sys

import pytest


def test___all__(pytester: pytest.Pytester) -> None:
    """See https://github.com/aio-libs/aiohttp/issues/6197"""
    pytester.makepyfile(
        test_a="""
            from aiohttp import *
        """
    )
    result = pytester.runpytest("-vv")
    result.assert_outcomes(passed=0, errors=0)


def test_web___all__(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        test_b="""
            from aiohttp.web import *
        """
    )
    result = pytester.runpytest("-vv")
    result.assert_outcomes(passed=0, errors=0)


@pytest.mark.skipif(
    not sys.platform.startswith("linux") or platform.python_implementation() == "PyPy",
    reason="Timing is less reliable on other platforms",
)
def test_import_time(pytester: pytest.Pytester) -> None:
    """Check that importing aiohttp doesn't take too long.

    Obviously, the time may vary on different machines and may need to be adjusted
    from time to time, but this should provide an early warning if something is
    added that significantly increases import time.
    """
    r = pytester.run(sys.executable, "-We", "-c", "import aiohttp", timeout=0.45)

    assert not r.stdout.str()
    assert not r.stderr.str()
