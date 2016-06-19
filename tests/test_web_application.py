import asyncio
import pytest

from aiohttp import web, log, helpers
from unittest import mock


def test_app_ctor(loop):
    app = web.Application(loop=loop)
    assert loop is app.loop
    assert app.logger is log.web_logger


def test_app_call(loop):
    app = web.Application(loop=loop)
    assert app is app()


def test_app_copy(loop):
    app = web.Application(loop=loop)
    with pytest.raises(NotImplementedError):
        app.copy()


def test_app_default_loop(loop):
    asyncio.set_event_loop(loop)
    app = web.Application()
    assert loop is app.loop


@pytest.mark.run_loop
def test_app_register_on_finish(loop):
    app = web.Application(loop=loop)
    cb1 = mock.Mock()
    cb2 = mock.Mock()
    app.on_cleanup.append(cb1)
    app.on_cleanup.append(cb2)
    yield from app.cleanup()
    cb1.assert_called_once_with(app)
    cb2.assert_called_once_with(app)


@pytest.mark.run_loop
def test_app_register_coro(loop):
    app = web.Application(loop=loop)

    fut = helpers.create_future(loop)

    @asyncio.coroutine
    def cb(app):
        yield from asyncio.sleep(0.001, loop=loop)
        fut.set_result(123)

    app.on_cleanup.append(cb)
    yield from app.cleanup()
    assert fut.done()
    assert 123 == fut.result()


@pytest.mark.run_loop
def test_app_register_and_finish_are_deprecated(loop, warning):
    app = web.Application(loop=loop)
    cb1 = mock.Mock()
    cb2 = mock.Mock()
    with warning(DeprecationWarning):
        app.register_on_finish(cb1, 1, b=2)
    with warning(DeprecationWarning):
        app.register_on_finish(cb2, 2, c=3)
    with warning(DeprecationWarning):
        yield from app.finish()
    cb1.assert_called_once_with(app, 1, b=2)
    cb2.assert_called_once_with(app, 2, c=3)


def test_non_default_router(loop):
    router = web.UrlDispatcher()
    app = web.Application(loop=loop, router=router)
    assert router is app.router

    def test_logging(self):
        logger = mock.Mock()
        app = web.Application(loop=self.loop)
        app.logger = logger
        self.assertIs(app.logger, logger)


@pytest.mark.run_loop
def test_on_shutdown(loop):
    app = web.Application(loop=loop)
    called = False

    @asyncio.coroutine
    def on_shutdown(app_param):
        nonlocal called
        assert app is app_param
        called = True

    app.on_shutdown.append(on_shutdown)

    yield from app.shutdown()
    assert called
