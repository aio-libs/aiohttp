import asyncio
import sys
from importlib.machinery import ModuleSpec, SourceFileLoader
from importlib.util import module_from_spec
from textwrap import dedent

import pytest

from aiohttp import web
from aiohttp.web_urldispatcher import UrlDispatcher


@pytest.fixture
def router():
    return UrlDispatcher()


def test_add_routeinfo(router):
    @web.get('/path')
    @asyncio.coroutine
    def handler(request):
        pass

    assert hasattr(handler, '__aiohttp_web__')
    info = handler.__aiohttp_web__
    assert info.method == 'GET'
    assert info.path == '/path'
    assert info.handler is handler


def test_add_routeinfo_twice(router):
    with pytest.raises(ValueError):
        @web.get('/path')
        @web.post('/path')
        @asyncio.coroutine
        def handler(request):
            pass


def test_scan(router):
    loader = SourceFileLoader('<fullname>', '<path>')
    spec = ModuleSpec('aiohttp.tmp_test', loader, is_package=False)
    mod = module_from_spec(spec)
    sys.modules[mod.__name__] = mod
    content = dedent("""\
        import asyncio
        from aiohttp import web

        @web.head('/path')
        @asyncio.coroutine
        def handler(request):
            pass
    """)
    try:
        exec(content, mod.__dict__)
        router.scan(mod.__name__)

        assert len(router.routes()) == 1

        route = list(router.routes())[0]
        assert route.method == 'HEAD'
        assert str(route.url_for()) == '/path'
    finally:
        del sys.modules[mod.__name__]
