"""Client middleware support."""

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, TypeVar

from .client_reqrep import ClientRequest, ClientResponse

if TYPE_CHECKING:
    pass

__all__ = ("client_middleware",)

_T = TypeVar("_T")

# Type for client middleware - similar to server but uses ClientRequest/ClientResponse
ClientMiddleware = Callable[
    [ClientRequest, Callable[..., Awaitable[ClientResponse]]], Awaitable[ClientResponse]
]


def client_middleware(f: _T) -> _T:
    """
    Decorator to mark client middleware.

    Currently just returns the function as-is, but allows for future extensions.
    """
    return f


def build_client_middlewares(
    handler: Callable[..., Awaitable[ClientResponse]],
    middlewares: tuple[ClientMiddleware, ...],
) -> Callable[..., Awaitable[ClientResponse]]:
    """
    Apply middlewares to request handler.

    The middlewares are applied in reverse order, so the first middleware
    in the list wraps all subsequent middlewares and the handler.

    This implementation avoids using partial/update_wrapper to minimize overhead
    and doesn't cache to avoid holding references to stateful middleware.
    """
    if not middlewares:
        return handler

    # Optimize for single middleware case
    if len(middlewares) == 1:
        middleware = middlewares[0]

        async def single_middleware_handler(req: ClientRequest) -> ClientResponse:
            return await middleware(req, handler)

        return single_middleware_handler

    # Build the chain for multiple middlewares
    current_handler = handler

    for middleware in reversed(middlewares):
        # Create a new closure that captures the current state
        def make_wrapper(
            mw: ClientMiddleware, next_h: Callable[..., Awaitable[ClientResponse]]
        ) -> Callable[..., Awaitable[ClientResponse]]:
            async def wrapped(req: ClientRequest) -> ClientResponse:
                return await mw(req, next_h)

            return wrapped

        current_handler = make_wrapper(middleware, current_handler)

    return current_handler
