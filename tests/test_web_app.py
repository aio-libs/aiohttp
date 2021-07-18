import asyncio
from typing import Any, AsyncIterator, Callable, Dict, NoReturn, TypedDict
from unittest import mock

import pytest

from aiohttp import log, web
from aiohttp.test_utils import make_mocked_coro
from aiohttp.typedefs import Handler


class EmptyDict(TypedDict):
    pass


_EmptyApplication = web.Application[EmptyDict]


async def test_app_ctor() -> None:
    app: _EmptyApplication = web.Application()
    assert app.logger is log.web_logger


def test_app_call() -> None:
    app: _EmptyApplication = web.Application()
    assert app is app()


async def test_app_register_on_finish() -> None:
    app: _EmptyApplication = web.Application()
    cb1 = make_mocked_coro(None)
    cb2 = make_mocked_coro(None)
    app.on_cleanup.append(cb1)
    app.on_cleanup.append(cb2)
    app.freeze()
    await app.cleanup()
    cb1.assert_called_once_with(app)
    cb2.assert_called_once_with(app)


async def test_app_register_coro() -> None:
    app: _EmptyApplication = web.Application()
    fut = asyncio.get_event_loop().create_future()

    async def cb(app: _EmptyApplication) -> None:
        await asyncio.sleep(0.001)
        fut.set_result(123)

    app.on_cleanup.append(cb)
    app.freeze()
    await app.cleanup()
    assert fut.done()
    assert 123 == fut.result()


def test_logging() -> None:
    logger = mock.Mock()
    app: _EmptyApplication = web.Application()
    app.logger = logger
    assert app.logger is logger


async def test_on_shutdown() -> None:
    app: _EmptyApplication = web.Application()
    called = False

    async def on_shutdown(app_param: _EmptyApplication) -> None:
        nonlocal called
        assert app is app_param
        called = True

    app.on_shutdown.append(on_shutdown)
    app.freeze()
    await app.shutdown()
    assert called


async def test_on_startup() -> None:
    app: _EmptyApplication = web.Application()

    long_running1_called = False
    long_running2_called = False
    all_long_running_called = False

    async def long_running1(app_param: _EmptyApplication) -> None:
        nonlocal long_running1_called
        assert app is app_param
        long_running1_called = True

    async def long_running2(app_param: _EmptyApplication) -> None:
        nonlocal long_running2_called
        assert app is app_param
        long_running2_called = True

    async def on_startup_all_long_running(app_param: _EmptyApplication) -> None:
        nonlocal all_long_running_called
        assert app is app_param
        all_long_running_called = True
        await asyncio.gather(long_running1(app_param), long_running2(app_param))

    app.on_startup.append(on_startup_all_long_running)
    app.freeze()

    await app.startup()
    assert long_running1_called
    assert long_running2_called
    assert all_long_running_called


def test_app_delitem() -> None:
    app: web.Application[Dict[str, str]] = web.Application()
    app.state["key"] = "value"
    assert len(app.state) == 1
    del app.state["key"]
    assert len(app.state) == 0


def test_app_freeze() -> None:
    app: _EmptyApplication = web.Application()
    subapp = mock.Mock()
    subapp._middlewares = ()
    app._subapps.append(subapp)

    app.freeze()
    assert subapp.freeze.called

    app.freeze()
    assert len(subapp.freeze.call_args_list) == 1


def test_equality() -> None:
    app1: _EmptyApplication = web.Application()
    app2: _EmptyApplication = web.Application()

    assert app1 == app1
    assert app1 != app2


def test_app_run_middlewares() -> None:

    root: _EmptyApplication = web.Application()
    sub: _EmptyApplication = web.Application()
    root.add_subapp("/sub", sub)
    root.freeze()
    assert root._run_middlewares is False

    async def middleware(
        request: web.Request[EmptyDict], handler: Handler
    ) -> web.StreamResponse:
        return await handler(request)

    root = web.Application(middlewares=[middleware])
    sub = web.Application()
    root.add_subapp("/sub", sub)
    root.freeze()
    assert root._run_middlewares is True

    root = web.Application()
    sub = web.Application(middlewares=[middleware])
    root.add_subapp("/sub", sub)
    root.freeze()
    assert root._run_middlewares is True


def test_subapp_pre_frozen_after_adding() -> None:
    app: _EmptyApplication = web.Application()
    subapp: _EmptyApplication = web.Application()

    app.add_subapp("/prefix", subapp)
    assert subapp.pre_frozen
    assert not subapp.frozen


def test_app_inheritance() -> None:
    with pytest.raises(TypeError):

        class A(web.Application[Any]):  # type: ignore[misc]
            pass


def test_app_custom_attr() -> None:
    app: _EmptyApplication = web.Application()
    with pytest.raises(AttributeError):
        app.custom = None  # type: ignore[attr-defined]


async def test_cleanup_ctx() -> None:
    app: _EmptyApplication = web.Application()
    out = []

    def f(num: int) -> Callable[[_EmptyApplication], AsyncIterator[None]]:
        async def inner(app: _EmptyApplication) -> AsyncIterator[None]:
            out.append("pre_" + str(num))
            yield None
            out.append("post_" + str(num))

        return inner

    app.cleanup_ctx.append(f(1))
    app.cleanup_ctx.append(f(2))
    app.freeze()
    await app.startup()
    assert out == ["pre_1", "pre_2"]
    await app.cleanup()
    assert out == ["pre_1", "pre_2", "post_2", "post_1"]


async def test_cleanup_ctx_exception_on_startup() -> None:
    app: _EmptyApplication = web.Application()
    out = []

    exc = Exception("fail")

    def f(
        num: int, fail: bool = False
    ) -> Callable[[_EmptyApplication], AsyncIterator[None]]:
        async def inner(app: _EmptyApplication) -> AsyncIterator[None]:
            out.append("pre_" + str(num))
            if fail:
                raise exc
            yield None
            out.append("post_" + str(num))

        return inner

    app.cleanup_ctx.append(f(1))
    app.cleanup_ctx.append(f(2, True))
    app.cleanup_ctx.append(f(3))
    app.freeze()
    with pytest.raises(Exception) as ctx:
        await app.startup()
    assert ctx.value is exc
    assert out == ["pre_1", "pre_2"]
    await app.cleanup()
    assert out == ["pre_1", "pre_2", "post_1"]


async def test_cleanup_ctx_exception_on_cleanup() -> None:
    app: _EmptyApplication = web.Application()
    out = []

    exc = Exception("fail")

    def f(
        num: int, fail: bool = False
    ) -> Callable[[_EmptyApplication], AsyncIterator[None]]:
        async def inner(app: _EmptyApplication) -> AsyncIterator[None]:
            out.append("pre_" + str(num))
            yield None
            out.append("post_" + str(num))
            if fail:
                raise exc

        return inner

    app.cleanup_ctx.append(f(1))
    app.cleanup_ctx.append(f(2, True))
    app.cleanup_ctx.append(f(3))
    app.freeze()
    await app.startup()
    assert out == ["pre_1", "pre_2", "pre_3"]
    with pytest.raises(Exception) as ctx:
        await app.cleanup()
    assert ctx.value is exc
    assert out == ["pre_1", "pre_2", "pre_3", "post_3", "post_2", "post_1"]


async def test_cleanup_ctx_cleanup_after_exception() -> None:
    app: _EmptyApplication = web.Application()
    ctx_state = None

    async def success_ctx(app: _EmptyApplication) -> AsyncIterator[None]:
        nonlocal ctx_state
        ctx_state = "START"
        yield
        ctx_state = "CLEAN"

    async def fail_ctx(app: _EmptyApplication) -> AsyncIterator[NoReturn]:
        raise Exception()
        yield

    app.cleanup_ctx.append(success_ctx)
    app.cleanup_ctx.append(fail_ctx)
    runner = web.AppRunner(app)
    try:
        with pytest.raises(Exception):
            await runner.setup()
    finally:
        await runner.cleanup()

    assert ctx_state == "CLEAN"


async def test_cleanup_ctx_exception_on_cleanup_multiple() -> None:
    app: _EmptyApplication = web.Application()
    out = []

    def f(
        num: int, fail: bool = False
    ) -> Callable[[_EmptyApplication], AsyncIterator[None]]:
        async def inner(app: _EmptyApplication) -> AsyncIterator[None]:
            out.append("pre_" + str(num))
            yield None
            out.append("post_" + str(num))
            if fail:
                raise Exception("fail_" + str(num))

        return inner

    app.cleanup_ctx.append(f(1))
    app.cleanup_ctx.append(f(2, True))
    app.cleanup_ctx.append(f(3, True))
    app.freeze()
    await app.startup()
    assert out == ["pre_1", "pre_2", "pre_3"]
    with pytest.raises(web.CleanupError) as ctx:
        await app.cleanup()
    exc = ctx.value
    assert len(exc.exceptions) == 2
    assert str(exc.exceptions[0]) == "fail_3"
    assert str(exc.exceptions[1]) == "fail_2"
    assert out == ["pre_1", "pre_2", "pre_3", "post_3", "post_2", "post_1"]


async def test_cleanup_ctx_multiple_yields() -> None:
    app: _EmptyApplication = web.Application()
    out = []

    def f(num: int) -> Callable[[_EmptyApplication], AsyncIterator[None]]:
        async def inner(app: _EmptyApplication) -> AsyncIterator[None]:
            out.append("pre_" + str(num))
            yield None
            out.append("post_" + str(num))
            yield None

        return inner

    app.cleanup_ctx.append(f(1))
    app.freeze()
    await app.startup()
    assert out == ["pre_1"]
    with pytest.raises(RuntimeError) as ctx:
        await app.cleanup()
    assert "has more than one 'yield'" in str(ctx.value)
    assert out == ["pre_1", "post_1"]


async def test_subapp_chained_config_dict_visibility(aiohttp_client: Any) -> None:
    async def main_handler(request: web.Request[Dict[str, str]]) -> web.Response:
        assert request.config_dict["key1"] == "val1"
        assert "key2" not in request.config_dict
        return web.Response(status=200)

    root: web.Application[Dict[str, str]] = web.Application()
    root.state["key1"] = "val1"
    root.add_routes([web.get("/", main_handler)])

    async def sub_handler(request: web.Request[Dict[str, str]]) -> web.Response:
        assert request.config_dict["key1"] == "val1"
        assert request.config_dict["key2"] == "val2"
        return web.Response(status=201)

    sub: web.Application[Dict[str, str]] = web.Application()
    sub.state["key2"] = "val2"
    sub.add_routes([web.get("/", sub_handler)])
    root.add_subapp("/sub", sub)

    client = await aiohttp_client(root)

    resp = await client.get("/")
    assert resp.status == 200
    resp = await client.get("/sub/")
    assert resp.status == 201


async def test_subapp_chained_config_dict_overriding(aiohttp_client: Any) -> None:
    async def main_handler(request: web.Request[Dict[str, str]]) -> web.Response:
        assert request.config_dict["key"] == "val1"
        return web.Response(status=200)

    root: web.Application[Dict[str, str]] = web.Application()
    root.state["key"] = "val1"
    root.add_routes([web.get("/", main_handler)])

    async def sub_handler(request: web.Request[Dict[str, str]]) -> web.Response:
        assert request.config_dict["key"] == "val2"
        return web.Response(status=201)

    sub: web.Application[Dict[str, str]] = web.Application()
    sub.state["key"] = "val2"
    sub.add_routes([web.get("/", sub_handler)])
    root.add_subapp("/sub", sub)

    client = await aiohttp_client(root)

    resp = await client.get("/")
    assert resp.status == 200
    resp = await client.get("/sub/")
    assert resp.status == 201


async def test_subapp_on_startup(aiohttp_client: Any) -> None:
    subapp: web.Application[Dict[str, bool]] = web.Application()

    startup_called = False

    async def on_startup(app: web.Application[Dict[str, bool]]) -> None:
        nonlocal startup_called
        startup_called = True
        app.state["startup"] = True

    subapp.on_startup.append(on_startup)

    ctx_pre_called = False
    ctx_post_called = False

    async def cleanup_ctx(app: web.Application[Dict[str, bool]]) -> AsyncIterator[None]:
        nonlocal ctx_pre_called, ctx_post_called
        ctx_pre_called = True
        app.state["cleanup"] = True
        yield None
        ctx_post_called = True

    subapp.cleanup_ctx.append(cleanup_ctx)

    shutdown_called = False

    async def on_shutdown(app: web.Application[Dict[str, bool]]) -> None:
        nonlocal shutdown_called
        shutdown_called = True

    subapp.on_shutdown.append(on_shutdown)

    cleanup_called = False

    async def on_cleanup(app: web.Application[Dict[str, bool]]) -> None:
        nonlocal cleanup_called
        cleanup_called = True

    subapp.on_cleanup.append(on_cleanup)

    app: web.Application[Dict[str, bool]] = web.Application()

    app.add_subapp("/subapp", subapp)

    assert not startup_called
    assert not ctx_pre_called
    assert not ctx_post_called
    assert not shutdown_called
    assert not cleanup_called

    assert subapp.on_startup.frozen
    assert subapp.cleanup_ctx.frozen
    assert subapp.on_shutdown.frozen
    assert subapp.on_cleanup.frozen
    assert subapp.router.frozen

    client = await aiohttp_client(app)

    assert startup_called
    assert ctx_pre_called
    assert not ctx_post_called
    assert not shutdown_called
    assert not cleanup_called

    await client.close()

    assert startup_called
    assert ctx_pre_called
    assert ctx_post_called
    assert shutdown_called
    assert cleanup_called


def test_app_iter() -> None:
    app: web.Application[Dict[str, str]] = web.Application()
    app.state["a"] = "1"
    app.state["b"] = "2"
    assert sorted(list(app.state)) == ["a", "b"]


def test_app_forbid_nonslot_attr() -> None:
    app: _EmptyApplication = web.Application()
    with pytest.raises(AttributeError):
        app.unknow_attr  # type: ignore[attr-defined]
    with pytest.raises(AttributeError):
        app.unknow_attr = 1  # type: ignore[attr-defined]


def test_forbid_changing_frozen_app() -> None:
    app: web.Application[Dict[str, str]] = web.Application()
    app.freeze()
    with pytest.raises(RuntimeError):
        app.state["key"] = "value"


def test_app_boolean() -> None:
    app: _EmptyApplication = web.Application()
    assert app
