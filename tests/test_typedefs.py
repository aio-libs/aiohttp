"""Test aiohttp.typedefs."""
from typing import TYPE_CHECKING, Awaitable, Callable

from aiohttp.typedefs import Handler, Middleware

if TYPE_CHECKING:
    from aiohttp.web import Request, StreamResponse


def test_middleware() -> None:
    """Test aiohttp.typedefs.Middleware."""
    assert Middleware == Callable[["Request", Handler], Awaitable["StreamResponse"]]
