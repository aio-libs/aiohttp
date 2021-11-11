from typing import Any


def test___all__(pytester: Any) -> None:
    """See https://github.com/aio-libs/aiohttp/issues/6197"""
    pytester.makepyfile(
        test_a="""
            from aiohttp import *
        """
    )
    result = pytester.runpytest("-vv")
    result.assert_outcomes(passed=0, errors=0)


def test_web___all__(pytester: Any) -> None:
    pytester.makepyfile(
        test_b="""
            from aiohttp.web import *
        """
    )
    result = pytester.runpytest("-vv")
    result.assert_outcomes(passed=0, errors=0)
