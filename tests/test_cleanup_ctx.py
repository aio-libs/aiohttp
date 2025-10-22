from contextlib import asynccontextmanager
from typing import AsyncIterator

from aiohttp.web_app import Application


async def test_cleanup_ctx_with_async_generator() -> None:
    entered = []

    async def ctx(app: Application) -> AsyncIterator[None]:
        entered.append("enter")
        try:
            yield
        finally:
            entered.append("exit")

    app = Application()
    app.cleanup_ctx.append(ctx)

    await app._cleanup_ctx._on_startup(app)
    assert entered == ["enter"]

    await app._cleanup_ctx._on_cleanup(app)
    assert entered == ["enter", "exit"]


async def test_cleanup_ctx_with_asynccontextmanager() -> None:
    entered = []

    @asynccontextmanager
    async def ctx(app: Application) -> AsyncIterator[None]:
        entered.append("enter")
        try:
            yield
        finally:
            entered.append("exit")

    app = Application()
    app.cleanup_ctx.append(ctx)

    await app._cleanup_ctx._on_startup(app)
    assert entered == ["enter"]

    await app._cleanup_ctx._on_cleanup(app)
    assert entered == ["enter", "exit"]


async def test_adapter_exit_path() -> None:
    """Explicitly exercise the adapter exit path to increase coverage."""
    entered = []

    @asynccontextmanager
    async def ctx(app: Application) -> AsyncIterator[None]:
        entered.append("enter")
        try:
            yield
        finally:
            entered.append("exit")

    app = Application()
    # append the context manager itself (not the generator)
    app.cleanup_ctx.append(ctx)

    await app._cleanup_ctx._on_startup(app)
    assert entered == ["enter"]

    await app._cleanup_ctx._on_cleanup(app)
    assert entered == ["enter", "exit"]
