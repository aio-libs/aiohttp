import asyncio
import pytest

from aiohttp import web, log
from unittest import mock


def test_app_ctor(loop):
    app = web.Application(loop=loop)
    assert loop is app.loop
    assert app.logger is log.web_logger


def test_app_call(loop):
    app = web.Application(loop=loop)
    assert app is app()


def test_app_default_loop(loop):
    asyncio.set_event_loop(loop)
    app = web.Application()
    assert loop is app.loop


@pytest.mark.run_loop
def test_app_register_on_finish(loop):
    app = web.Application(loop=loop)
    cb1 = mock.Mock()
    cb2 = mock.Mock()
    app.register_on_finish(cb1, 1, b=2)
    app.register_on_finish(cb2, 2, c=3)
    yield from app.finish()
    cb1.assert_called_once_with(app, 1, b=2)
    cb2.assert_called_once_with(app, 2, c=3)


@pytest.mark.run_loop
def test_app_register_coro(loop):
    app = web.Application(loop=loop)

    fut = asyncio.Future(loop=loop)

    @asyncio.coroutine
    def cb(app):
        yield from asyncio.sleep(0.001, loop=loop)
        fut.set_result(123)

    app.register_on_finish(cb)
    yield from app.finish()
    assert fut.done()
    assert 123 == fut.result()


@pytest.mark.run_loop
def test_app_error_in_finish_callbacks(loop):
    app = web.Application(loop=loop)

    err = RuntimeError('bad call')
    app.register_on_finish(mock.Mock(side_effect=err))
    handler = mock.Mock()
    loop.set_exception_handler(handler)
    yield from app.finish()
    exc_info = {'exception': err,
                'application': app,
                'message': 'Error in finish callback'}
    handler.assert_called_once_with(loop, exc_info)


def test_non_default_router(loop):
    router = web.UrlDispatcher()
    app = web.Application(loop=loop, router=router)
    assert router is app.router

    def test_logging(self):
        logger = mock.Mock()
        app = web.Application(loop=self.loop)
        app.logger = logger
        self.assertIs(app.logger, logger)
