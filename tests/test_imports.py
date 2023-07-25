import os
import platform
import sys
from pathlib import Path

import pytest


def test___all__(pytester: pytest.Pytester) -> None:
    """See https://github.com/aio-libs/aiohttp/issues/6197"""
    pytester.makepyfile(
        test_a="""
            from aiohttp import *
            assert 'GunicornWebWorker' in globals()
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
    reason="Timing is more reliable on Linux",
)
def test_import_time(pytester: pytest.Pytester) -> None:
    """Check that importing aiohttp doesn't take too long.

    Obviously, the time may vary on different machines and may need to be adjusted
    from time to time, but this should provide an early warning if something is
    added that significantly increases import time.
    """
    root = Path(__file__).parent.parent
    old_path = os.environ.get("PYTHONPATH")
    os.environ["PYTHONPATH"] = os.pathsep.join([str(root)] + sys.path)

    best_time_ms = 1000
    cmd = "import timeit; print(int(timeit.timeit('import aiohttp', number=1) * 1000))"
    try:
        for _ in range(3):
            r = pytester.run(sys.executable, "-We", "-c", cmd)

            assert not r.stderr.str()
            runtime_ms = int(r.stdout.str())
            if runtime_ms < best_time_ms:
                best_time_ms = runtime_ms
    finally:
        if old_path is None:
            os.environ.pop("PYTHONPATH")
        else:
            os.environ["PYTHONPATH"] = old_path

    assert best_time_ms < 200
