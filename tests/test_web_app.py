import asyncio
from typing import AsyncIterator, Callable, Iterator, NoReturn, Type
from unittest import mock

import pytest

from aiohttp import log, web
from aiohttp.pytest_plugin import AiohttpClient
from aiohttp.test_utils import make_mocked_coro
from aiohttp.typedefs import Handler


async def test_app_ctor() -> None:
    app = web.Application()
    assert app.logger is log.web_logger


def test_app_call() -> None:
    app = web.Application()
    assert app is app()


async def test_app_register_on_finish() -> None:
    app = web.Application()
    cb1 = make_mocked_coro(None)
    cb2 = make_mocked_coro(None)
    app.on_cleanup.append(cb1)
    app.on_cleanup.append(cb2)
    app.freeze()
    await app.cleanup()
    cb1.assert_called_once_with(app)
    cb2.assert_called_once_with(app)


async def test_app_register_coro() -> None:
    app = web.Application()
    fut = asyncio.get_event_loop().create_future()

    async def cb(app: web.Application) -> None:
        await asyncio.sleep(0.001)
        fut.set_result(123)

    app.on_cleanup.append(cb)
    app.freeze()
    await app.cleanup()
    assert fut.done()
    assert 123 == fut.result()


def test_logging() -> None:
    logger = mock.Mock()
    app = web.Application()
    app.logger = logger
    assert app.logger is logger


async def test_on_shutdown() -> None:
    app = web.Application()
    called = False

    async def on_shutdown(app_param: web.Application) -> None:
        nonlocal called
        assert app is app_param
        called = True

    app.on_shutdown.append(on_shutdown)
    app.freeze()
    await app.shutdown()
    assert called


async def test_on_startup() -> None:
    app = web.Application()

    long_running1_called = False
    long_running2_called = False
    all_long_running_called = False

    async def long_running1(app_param: web.Application) -> None:
        nonlocal long_running1_called
        assert app is app_param
        long_running1_called = True

    async def long_running2(app_param: web.Application) -> None:
        nonlocal long_running2_called
        assert app is app_param
        long_running2_called = True

    async def on_startup_all_long_running(app_param: web.Application) -> None:
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


def test_appkey() -> None:
    key = web.AppKey("key", str)
    app = web.Application()
    app[key] = "value"
    assert app[key] == "value"
    assert len(app) == 1
    del app[key]
    assert len(app) == 0


def test_appkey_repr_concrete() -> None:
    key = web.AppKey("key", int)
    assert repr(key) in (
        "<AppKey(__channelexec__.key, type=int)>",  # pytest-xdist
        "<AppKey(__main__.key, type=int)>",
    )
    key2 = web.AppKey("key", web.Request)
    assert repr(key2) in (
        # pytest-xdist:
        "<AppKey(__channelexec__.key, type=aiohttp.web_request.Request)>",
        "<AppKey(__main__.key, type=aiohttp.web_request.Request)>",
    )


def test_appkey_repr_nonconcrete() -> None:
    key = web.AppKey("key", Iterator[int])
    assert repr(key) in (
        # pytest-xdist:
        "<AppKey(__channelexec__.key, type=typing.Iterator[int])>",
        "<AppKey(__main__.key, type=typing.Iterator[int])>",
    )


def test_appkey_repr_annotated() -> None:
    key = web.AppKey[Iterator[int]]("key")
    assert repr(key) in (
        # pytest-xdist:
        "<AppKey(__channelexec__.key, type=typing.Iterator[int])>",
        "<AppKey(__main__.key, type=typing.Iterator[int])>",
    )


def test_app_str_keys() -> None:
    app = web.Application()
    with pytest.warns(
        UserWarning, match=r"web_advanced\.html#application-s-config"
    ) as checker:
        app["key"] = "value"
        # Check that the error is emitted at the call site (stacklevel=2)
        assert checker[0].filename == __file__
    assert app["key"] == "value"


def test_app_get() -> None:
    key = web.AppKey("key", int)
    app = web.Application()
    assert app.get(key, "foo") == "foo"
    app[key] = 5
    assert app.get(key, "foo") == 5


def test_app_freeze() -> None:
    app = web.Application()
    subapp = mock.Mock()
    subapp._middlewares = ()
    app._subapps.append(subapp)

    app.freeze()
    assert subapp.freeze.called

    app.freeze()
    assert len(subapp.freeze.call_args_list) == 1


def test_equality() -> None:
    app1 = web.Application()
    app2 = web.Application()

    assert app1 == app1
    assert app1 != app2


def test_app_run_middlewares() -> None:
    root = web.Application()
    sub = web.Application()
    root.add_subapp("/sub", sub)
    root.freeze()
    assert root._run_middlewares is False

    async def middleware(request: web.Request, handler: Handler) -> web.StreamResponse:
        return await handler(request)  # pragma: no cover

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
    app = web.Application()
    subapp = web.Application()

    app.add_subapp("/prefix", subapp)
    assert subapp.pre_frozen
    assert not subapp.frozen


def test_app_inheritance() -> None:
    with pytest.raises(TypeError):

        class A(web.Application):  # type: ignore[misc]
            pass


def test_app_custom_attr() -> None:
    app = web.Application()
    with pytest.raises(AttributeError):
        app.custom = None  # type: ignore[attr-defined]


async def test_cleanup_ctx() -> None:
    app = web.Application()
    out = []

    def f(num: int) -> Callable[[web.Application], AsyncIterator[None]]:
        async def inner(app: web.Application) -> AsyncIterator[None]:
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
    app = web.Application()
    out = []

    exc = Exception("fail")

    def f(
        num: int, fail: bool = False
    ) -> Callable[[web.Application], AsyncIterator[None]]:
        async def inner(app: web.Application) -> AsyncIterator[None]:
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
    app = web.Application()
    out = []

    exc = Exception("fail")

    def f(
        num: int, fail: bool = False
    ) -> Callable[[web.Application], AsyncIterator[None]]:
        async def inner(app: web.Application) -> AsyncIterator[None]:
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
    app = web.Application()
    ctx_state = None

    async def success_ctx(app: web.Application) -> AsyncIterator[None]:
        nonlocal ctx_state
        ctx_state = "START"
        yield
        ctx_state = "CLEAN"

    async def fail_ctx(app: web.Application) -> AsyncIterator[NoReturn]:
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


@pytest.mark.parametrize("exc_cls", (Exception, asyncio.CancelledError))
async def test_cleanup_ctx_exception_on_cleanup_multiple(
    exc_cls: Type[BaseException],
) -> None:
    app = web.Application()
    out = []

    def f(
        num: int, fail: bool = False
    ) -> Callable[[web.Application], AsyncIterator[None]]:
        async def inner(app: web.Application) -> AsyncIterator[None]:
            out.append("pre_" + str(num))
            yield None
            out.append("post_" + str(num))
            if fail:
                raise exc_cls("fail_" + str(num))

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
    app = web.Application()
    out = []

    def f(num: int) -> Callable[[web.Application], AsyncIterator[None]]:
        async def inner(app: web.Application) -> AsyncIterator[None]:
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


async def test_subapp_chained_config_dict_visibility(
    aiohttp_client: AiohttpClient,
) -> None:
    key1 = web.AppKey("key1", str)
    key2 = web.AppKey("key2", str)

    async def main_handler(request: web.Request) -> web.Response:
        assert request.config_dict[key1] == "val1"
        assert key2 not in request.config_dict
        return web.Response(status=200)

    root = web.Application()
    root[key1] = "val1"
    root.add_routes([web.get("/", main_handler)])

    async def sub_handler(request: web.Request) -> web.Response:
        assert request.config_dict[key1] == "val1"
        assert request.config_dict[key2] == "val2"
        return web.Response(status=201)

    sub = web.Application()
    sub[key2] = "val2"
    sub.add_routes([web.get("/", sub_handler)])
    root.add_subapp("/sub", sub)

    client = await aiohttp_client(root)

    resp = await client.get("/")
    assert resp.status == 200
    resp = await client.get("/sub/")
    assert resp.status == 201


async def test_subapp_chained_config_dict_overriding(
    aiohttp_client: AiohttpClient,
) -> None:
    key = web.AppKey("key", str)

    async def main_handler(request: web.Request) -> web.Response:
        assert request.config_dict[key] == "val1"
        return web.Response(status=200)

    root = web.Application()
    root[key] = "val1"
    root.add_routes([web.get("/", main_handler)])

    async def sub_handler(request: web.Request) -> web.Response:
        assert request.config_dict[key] == "val2"
        return web.Response(status=201)

    sub = web.Application()
    sub[key] = "val2"
    sub.add_routes([web.get("/", sub_handler)])
    root.add_subapp("/sub", sub)

    client = await aiohttp_client(root)

    resp = await client.get("/")
    assert resp.status == 200
    resp = await client.get("/sub/")
    assert resp.status == 201


async def test_subapp_on_startup(aiohttp_client: AiohttpClient) -> None:
    subapp = web.Application()
    startup = web.AppKey("startup", bool)
    cleanup = web.AppKey("cleanup", bool)

    startup_called = False

    async def on_startup(app: web.Application) -> None:
        nonlocal startup_called
        startup_called = True
        app[startup] = True

    subapp.on_startup.append(on_startup)

    ctx_pre_called = False
    ctx_post_called = False

    async def cleanup_ctx(app: web.Application) -> AsyncIterator[None]:
        nonlocal ctx_pre_called, ctx_post_called
        ctx_pre_called = True
        app[cleanup] = True
        yield None
        ctx_post_called = True

    subapp.cleanup_ctx.append(cleanup_ctx)

    shutdown_called = False

    async def on_shutdown(app: web.Application) -> None:
        nonlocal shutdown_called
        shutdown_called = True

    subapp.on_shutdown.append(on_shutdown)

    cleanup_called = False

    async def on_cleanup(app: web.Application) -> None:
        nonlocal cleanup_called
        cleanup_called = True

    subapp.on_cleanup.append(on_cleanup)

    app = web.Application()

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


@pytest.mark.filterwarnings(r"ignore:.*web\.AppKey:UserWarning")
def test_app_iter() -> None:
    app = web.Application()
    b = web.AppKey("b", str)
    c = web.AppKey("c", str)
    app["a"] = "0"
    app[b] = "1"
    app[c] = "2"
    app["d"] = "4"
    assert sorted(list(app)) == [b, c, "a", "d"]


def test_app_forbid_nonslot_attr() -> None:
    app = web.Application()
    with pytest.raises(AttributeError):
        app.unknow_attr  # type: ignore[attr-defined]
    with pytest.raises(AttributeError):
        app.unknow_attr = 1  # type: ignore[attr-defined]


def test_forbid_changing_frozen_app() -> None:
    app = web.Application()
    app.freeze()
    with pytest.raises(RuntimeError):
        app["key"] = "value"


def test_app_boolean() -> None:
    app = web.Application()
    assert app
