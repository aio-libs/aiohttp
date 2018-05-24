import asyncio
from unittest import mock

import pytest
from async_generator import async_generator, yield_

from aiohttp import log, web
from aiohttp.abc import AbstractAccessLogger, AbstractRouter
from aiohttp.helpers import DEBUG, PY_36
from aiohttp.test_utils import make_mocked_coro


def test_app_ctor(loop):
    with pytest.warns(DeprecationWarning):
        app = web.Application(loop=loop)
    assert loop is app.loop
    assert app.logger is log.web_logger


def test_app_call():
    app = web.Application()
    assert app is app()


def test_app_default_loop():
    app = web.Application()
    assert app.loop is None


def test_set_loop(loop):
    app = web.Application()
    app._set_loop(loop)
    assert app.loop is loop


def test_set_loop_default_loop(loop):
    asyncio.set_event_loop(loop)
    app = web.Application()
    app._set_loop(None)
    assert app.loop is loop


def test_set_loop_with_different_loops(loop):
    app = web.Application()
    app._set_loop(loop)
    assert app.loop is loop

    with pytest.raises(RuntimeError):
        app._set_loop(loop=object())


@pytest.mark.parametrize('debug', [True, False])
def test_app_make_handler_debug_exc(loop, mocker, debug):
    app = web.Application(debug=debug)
    srv = mocker.patch('aiohttp.web_app.Server')

    app._make_handler(loop=loop)
    srv.assert_called_with(app._handle,
                           request_factory=app._make_request,
                           access_log_class=mock.ANY,
                           loop=loop,
                           debug=debug)


def test_app_make_handler_args(loop, mocker):
    app = web.Application(handler_args={'test': True})
    srv = mocker.patch('aiohttp.web_app.Server')

    app._make_handler(loop=loop)
    srv.assert_called_with(app._handle,
                           request_factory=app._make_request,
                           access_log_class=mock.ANY,
                           loop=loop, debug=mock.ANY, test=True)


def test_app_make_handler_access_log_class(loop, mocker):
    class Logger:
        pass

    app = web.Application()

    with pytest.raises(TypeError):
        app._make_handler(access_log_class=Logger, loop=loop)

    class Logger(AbstractAccessLogger):

        def log(self, request, response, time):
            self.logger.info('msg')

    srv = mocker.patch('aiohttp.web_app.Server')

    app._make_handler(access_log_class=Logger, loop=loop)
    srv.assert_called_with(app._handle,
                           access_log_class=Logger,
                           request_factory=app._make_request,
                           loop=loop, debug=mock.ANY)


def test_app_make_handler_raises_deprecation_warning(loop):
    app = web.Application()

    with pytest.warns(DeprecationWarning):
        app.make_handler(loop=loop)


async def test_app_register_on_finish():
    app = web.Application()
    cb1 = make_mocked_coro(None)
    cb2 = make_mocked_coro(None)
    app.on_cleanup.append(cb1)
    app.on_cleanup.append(cb2)
    app.freeze()
    await app.cleanup()
    cb1.assert_called_once_with(app)
    cb2.assert_called_once_with(app)


async def test_app_register_coro(loop):
    app = web.Application()
    fut = loop.create_future()

    async def cb(app):
        await asyncio.sleep(0.001, loop=loop)
        fut.set_result(123)

    app.on_cleanup.append(cb)
    app.freeze()
    await app.cleanup()
    assert fut.done()
    assert 123 == fut.result()


def test_non_default_router():
    router = mock.Mock(spec=AbstractRouter)
    with pytest.warns(DeprecationWarning):
        app = web.Application(router=router)
    assert router is app.router


def test_logging():
    logger = mock.Mock()
    app = web.Application()
    app.logger = logger
    assert app.logger is logger


async def test_on_shutdown():
    app = web.Application()
    called = False

    async def on_shutdown(app_param):
        nonlocal called
        assert app is app_param
        called = True

    app.on_shutdown.append(on_shutdown)
    app.freeze()
    await app.shutdown()
    assert called


async def test_on_startup(loop):
    app = web.Application()
    app._set_loop(loop)

    long_running1_called = False
    long_running2_called = False
    all_long_running_called = False

    async def long_running1(app_param):
        nonlocal long_running1_called
        assert app is app_param
        long_running1_called = True

    async def long_running2(app_param):
        nonlocal long_running2_called
        assert app is app_param
        long_running2_called = True

    async def on_startup_all_long_running(app_param):
        nonlocal all_long_running_called
        assert app is app_param
        all_long_running_called = True
        return await asyncio.gather(long_running1(app_param),
                                    long_running2(app_param),
                                    loop=app_param.loop)

    app.on_startup.append(on_startup_all_long_running)
    app.freeze()

    await app.startup()
    assert long_running1_called
    assert long_running2_called
    assert all_long_running_called


def test_app_delitem():
    app = web.Application()
    app['key'] = 'value'
    assert len(app) == 1
    del app['key']
    assert len(app) == 0


def test_app_freeze():
    app = web.Application()
    subapp = mock.Mock()
    subapp._middlewares = ()
    app._subapps.append(subapp)

    app.freeze()
    assert subapp.freeze.called

    app.freeze()
    assert len(subapp.freeze.call_args_list) == 1


def test_equality():
    app1 = web.Application()
    app2 = web.Application()

    assert app1 == app1
    assert app1 != app2


def test_app_run_middlewares():

    root = web.Application()
    sub = web.Application()
    root.add_subapp('/sub', sub)
    root.freeze()
    assert root._run_middlewares is False

    @web.middleware
    async def middleware(request, handler):
        return await handler(request)

    root = web.Application(middlewares=[middleware])
    sub = web.Application()
    root.add_subapp('/sub', sub)
    root.freeze()
    assert root._run_middlewares is True

    root = web.Application()
    sub = web.Application(middlewares=[middleware])
    root.add_subapp('/sub', sub)
    root.freeze()
    assert root._run_middlewares is True


def test_subapp_frozen_after_adding():
    app = web.Application()
    subapp = web.Application()

    app.add_subapp('/prefix', subapp)
    assert subapp.frozen


@pytest.mark.skipif(not PY_36,
                    reason="Python 3.6+ required")
def test_app_inheritance():
    with pytest.warns(DeprecationWarning):
        class A(web.Application):
            pass


@pytest.mark.skipif(not DEBUG,
                    reason="The check is applied in DEBUG mode only")
def test_app_custom_attr():
    app = web.Application()
    with pytest.warns(DeprecationWarning):
        app.custom = None


async def test_cleanup_ctx():
    app = web.Application()
    out = []

    def f(num):
        @async_generator
        async def inner(app):
            out.append('pre_' + str(num))
            await yield_(None)
            out.append('post_' + str(num))
        return inner

    app.cleanup_ctx.append(f(1))
    app.cleanup_ctx.append(f(2))
    app.freeze()
    await app.startup()
    assert out == ['pre_1', 'pre_2']
    await app.cleanup()
    assert out == ['pre_1', 'pre_2', 'post_2', 'post_1']


async def test_cleanup_ctx_exception_on_startup():
    app = web.Application()
    out = []

    exc = Exception('fail')

    def f(num, fail=False):
        @async_generator
        async def inner(app):
            out.append('pre_' + str(num))
            if fail:
                raise exc
            await yield_(None)
            out.append('post_' + str(num))
        return inner

    app.cleanup_ctx.append(f(1))
    app.cleanup_ctx.append(f(2, True))
    app.cleanup_ctx.append(f(3))
    app.freeze()
    with pytest.raises(Exception) as ctx:
        await app.startup()
    assert ctx.value is exc
    assert out == ['pre_1', 'pre_2']
    await app.cleanup()
    assert out == ['pre_1', 'pre_2', 'post_1']


async def test_cleanup_ctx_exception_on_cleanup():
    app = web.Application()
    out = []

    exc = Exception('fail')

    def f(num, fail=False):
        @async_generator
        async def inner(app):
            out.append('pre_' + str(num))
            await yield_(None)
            out.append('post_' + str(num))
            if fail:
                raise exc
        return inner

    app.cleanup_ctx.append(f(1))
    app.cleanup_ctx.append(f(2, True))
    app.cleanup_ctx.append(f(3))
    app.freeze()
    await app.startup()
    assert out == ['pre_1', 'pre_2', 'pre_3']
    with pytest.raises(Exception) as ctx:
        await app.cleanup()
    assert ctx.value is exc
    assert out == ['pre_1', 'pre_2', 'pre_3', 'post_3', 'post_2', 'post_1']


async def test_cleanup_ctx_exception_on_cleanup_multiple():
    app = web.Application()
    out = []

    def f(num, fail=False):
        @async_generator
        async def inner(app):
            out.append('pre_' + str(num))
            await yield_(None)
            out.append('post_' + str(num))
            if fail:
                raise Exception('fail_' + str(num))
        return inner

    app.cleanup_ctx.append(f(1))
    app.cleanup_ctx.append(f(2, True))
    app.cleanup_ctx.append(f(3, True))
    app.freeze()
    await app.startup()
    assert out == ['pre_1', 'pre_2', 'pre_3']
    with pytest.raises(web.CleanupError) as ctx:
        await app.cleanup()
    exc = ctx.value
    assert len(exc.exceptions) == 2
    assert str(exc.exceptions[0]) == 'fail_3'
    assert str(exc.exceptions[1]) == 'fail_2'
    assert out == ['pre_1', 'pre_2', 'pre_3', 'post_3', 'post_2', 'post_1']


async def test_cleanup_ctx_multiple_yields():
    app = web.Application()
    out = []

    def f(num):
        @async_generator
        async def inner(app):
            out.append('pre_' + str(num))
            await yield_(None)
            out.append('post_' + str(num))
            await yield_(None)
        return inner

    app.cleanup_ctx.append(f(1))
    app.freeze()
    await app.startup()
    assert out == ['pre_1']
    with pytest.raises(RuntimeError) as ctx:
        await app.cleanup()
    assert "has more than one 'yield'" in str(ctx.value)
    assert out == ['pre_1', 'post_1']


async def test_subapp_chained_config_dict_visibility(aiohttp_client):

    async def main_handler(request):
        assert request.config_dict['key1'] == 'val1'
        assert 'key2' not in request.config_dict
        return web.Response(status=200)

    root = web.Application()
    root['key1'] = 'val1'
    root.add_routes([web.get('/', main_handler)])

    async def sub_handler(request):
        assert request.config_dict['key1'] == 'val1'
        assert request.config_dict['key2'] == 'val2'
        return web.Response(status=201)

    sub = web.Application()
    sub['key2'] = 'val2'
    sub.add_routes([web.get('/', sub_handler)])
    root.add_subapp('/sub', sub)

    client = await aiohttp_client(root)

    resp = await client.get('/')
    assert resp.status == 200
    resp = await client.get('/sub/')
    assert resp.status == 201


async def test_subapp_chained_config_dict_overriding(aiohttp_client):

    async def main_handler(request):
        assert request.config_dict['key'] == 'val1'
        return web.Response(status=200)

    root = web.Application()
    root['key'] = 'val1'
    root.add_routes([web.get('/', main_handler)])

    async def sub_handler(request):
        assert request.config_dict['key'] == 'val2'
        return web.Response(status=201)

    sub = web.Application()
    sub['key'] = 'val2'
    sub.add_routes([web.get('/', sub_handler)])
    root.add_subapp('/sub', sub)

    client = await aiohttp_client(root)

    resp = await client.get('/')
    assert resp.status == 200
    resp = await client.get('/sub/')
    assert resp.status == 201
