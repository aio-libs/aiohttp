import asyncio
import sys
from textwrap import dedent

import pytest

from aiohttp import web
from aiohttp.web_urldispatcher import UrlDispatcher


if sys.version_info >= (3, 5):
    @pytest.fixture
    def create_module():
        from importlib.machinery import ModuleSpec, SourceFileLoader
        from importlib.util import module_from_spec
        mods = []

        def maker(name, *, is_package=False):
            loader = SourceFileLoader('<fullname>', '<path>')
            spec = ModuleSpec(name, loader, is_package=is_package)
            mod = module_from_spec(spec)
            sys.modules[mod.__name__] = mod
            mods.append(mod)
            return mod
        yield maker
        for mod in mods:
            del sys.modules[mod.__name__]
else:
    @pytest.fixture
    def create_module(name):
        from imp import new_module

        mods = []

        def maker(name, *, is_package=False):
            mod = new_module(name)
            sys.modules[mod.__name__] = mod
            mods.append(mod)
        yield maker
        for mod in mods:
            del sys.modules[mod.__name__]


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


def test_scan_mod(router, create_module):
    mod = create_module('aiohttp.tmp.test_mod')
    content = dedent("""\
        import asyncio
        from aiohttp import web

        @web.head('/path')
        @asyncio.coroutine
        def handler(request):
            pass
    """)
    exec(content, mod.__dict__)
    router.scan(mod.__name__)

    assert len(router.routes()) == 1

    route = list(router.routes())[0]
    assert route.method == 'HEAD'
    assert str(route.url_for()) == '/path'


def test_scan_package(router, create_module):
    mod = create_module('aiohttp.tmp', is_package=True)
    mod1 = create_module('aiohttp.tmp.test_mod1')
    content1 = dedent("""\
        import asyncio
        from aiohttp import web

        @web.head('/path1')
        @asyncio.coroutine
        def handler(request):
            pass
    """)
    exec(content1, mod1.__dict__)
    mod2 = create_module('aiohttp.tmp.test_mod2')
    content2 = dedent("""\
        import asyncio
        from aiohttp import web

        @web.put('/path2')
        @asyncio.coroutine
        def handler(request):
            pass
    """)
    exec(content2, mod2.__dict__)
    router.scan(mod.__package__)

    assert len(router.routes()) == 2

    route1 = list(router.routes())[0]
    assert route1.method == 'HEAD'
    assert str(route1.url_for()) == '/path1'

    route1 = list(router.routes())[1]
    assert route1.method == 'PUT'
    assert str(route1.url_for()) == '/path2'
