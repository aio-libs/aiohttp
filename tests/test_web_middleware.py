import pytest
from yarl import URL

from aiohttp import web


async def test_middleware_modifies_response(loop, aiohttp_client) -> None:
    async def handler(request):
        return web.Response(body=b'OK')

    async def middleware(request, handler):
        resp = await handler(request)
        assert 200 == resp.status
        resp.set_status(201)
        resp.text = resp.text + '[MIDDLEWARE]'
        return resp

    app = web.Application()
    app.middlewares.append(middleware)
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)
    resp = await client.get('/')
    assert 201 == resp.status
    txt = await resp.text()
    assert 'OK[MIDDLEWARE]' == txt


async def test_middleware_handles_exception(loop, aiohttp_client) -> None:
    async def handler(request):
        raise RuntimeError('Error text')

    async def middleware(request, handler):
        with pytest.raises(RuntimeError) as ctx:
            await handler(request)
        return web.Response(status=501,
                            text=str(ctx.value) + '[MIDDLEWARE]')

    app = web.Application()
    app.middlewares.append(middleware)
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)
    resp = await client.get('/')
    assert 501 == resp.status
    txt = await resp.text()
    assert 'Error text[MIDDLEWARE]' == txt


async def test_middleware_chain(loop, aiohttp_client) -> None:
    async def handler(request):
        return web.Response(text='OK')

    def make_middleware(num):
        async def middleware(request, handler):
            resp = await handler(request)
            resp.text = resp.text + '[{}]'.format(num)
            return resp
        return middleware

    app = web.Application()
    app.middlewares.append(make_middleware(1))
    app.middlewares.append(make_middleware(2))
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)
    resp = await client.get('/')
    assert 200 == resp.status
    txt = await resp.text()
    assert 'OK[2][1]' == txt


@pytest.fixture
def cli(loop, aiohttp_client):
    async def handler(request):
        return web.Response(text="OK")

    def wrapper(extra_middlewares):
        app = web.Application()
        app.router.add_route(
            'GET', '/resource1', handler)
        app.router.add_route(
            'GET', '/resource2/', handler)
        app.router.add_route(
            'GET', '/resource1/a/b', handler)
        app.router.add_route(
            'GET', '/resource2/a/b/', handler)
        app.router.add_route(
            'GET', '/resource2/a/b%2Fc/', handler)
        app.middlewares.extend(extra_middlewares)
        return aiohttp_client(app, server_kwargs={'skip_url_asserts': True})
    return wrapper


class TestNormalizePathMiddleware:

    @pytest.mark.parametrize("path, status", [
        ('/resource1', 200),
        ('/resource1/', 404),
        ('/resource2', 200),
        ('/resource2/', 200),
        ('/resource1?p1=1&p2=2', 200),
        ('/resource1/?p1=1&p2=2', 404),
        ('/resource2?p1=1&p2=2', 200),
        ('/resource2/?p1=1&p2=2', 200),
        ('/resource2/a/b%2Fc', 200),
        ('/resource2/a/b%2Fc/', 200)
    ])
    async def test_add_trailing_when_necessary(
            self, path, status, cli):
        extra_middlewares = [
            web.normalize_path_middleware(merge_slashes=False)]
        client = await cli(extra_middlewares)

        resp = await client.get(path)
        assert resp.status == status
        assert resp.url.query == URL(path).query

    @pytest.mark.parametrize("path, status", [
        ('/resource1', 200),
        ('/resource1/', 200),
        ('/resource2', 404),
        ('/resource2/', 200),
        ('/resource1?p1=1&p2=2', 200),
        ('/resource1/?p1=1&p2=2', 200),
        ('/resource2?p1=1&p2=2', 404),
        ('/resource2/?p1=1&p2=2', 200),
        ('/resource2/a/b%2Fc', 404),
        ('/resource2/a/b%2Fc/', 200),
        ('/resource12', 404),
        ('/resource12345', 404)
    ])
    async def test_remove_trailing_when_necessary(self, path,
                                                  status, cli) -> None:
        extra_middlewares = [
            web.normalize_path_middleware(
                append_slash=False, remove_slash=True, merge_slashes=False)]
        client = await cli(extra_middlewares)

        resp = await client.get(path)
        assert resp.status == status
        assert resp.url.query == URL(path).query

    @pytest.mark.parametrize("path, status", [
        ('/resource1', 200),
        ('/resource1/', 404),
        ('/resource2', 404),
        ('/resource2/', 200),
        ('/resource1?p1=1&p2=2', 200),
        ('/resource1/?p1=1&p2=2', 404),
        ('/resource2?p1=1&p2=2', 404),
        ('/resource2/?p1=1&p2=2', 200),
        ('/resource2/a/b%2Fc', 404),
        ('/resource2/a/b%2Fc/', 200)
    ])
    async def test_no_trailing_slash_when_disabled(
            self, path, status, cli):
        extra_middlewares = [
            web.normalize_path_middleware(
                append_slash=False, merge_slashes=False)]
        client = await cli(extra_middlewares)

        resp = await client.get(path)
        assert resp.status == status
        assert resp.url.query == URL(path).query

    @pytest.mark.parametrize("path, status", [
        ('/resource1/a/b', 200),
        ('//resource1//a//b', 200),
        ('//resource1//a//b/', 404),
        ('///resource1//a//b', 200),
        ('/////resource1/a///b', 200),
        ('/////resource1/a//b/', 404),
        ('/resource1/a/b?p=1', 200),
        ('//resource1//a//b?p=1', 200),
        ('//resource1//a//b/?p=1', 404),
        ('///resource1//a//b?p=1', 200),
        ('/////resource1/a///b?p=1', 200),
        ('/////resource1/a//b/?p=1', 404),
    ])
    async def test_merge_slash(self, path, status, cli) -> None:
        extra_middlewares = [
            web.normalize_path_middleware(append_slash=False)]
        client = await cli(extra_middlewares)

        resp = await client.get(path)
        assert resp.status == status
        assert resp.url.query == URL(path).query

    @pytest.mark.parametrize("path, status", [
        ('/resource1/a/b', 200),
        ('/resource1/a/b/', 404),
        ('//resource2//a//b', 200),
        ('//resource2//a//b/', 200),
        ('///resource1//a//b', 200),
        ('///resource1//a//b/', 404),
        ('/////resource1/a///b', 200),
        ('/////resource1/a///b/', 404),
        ('/resource2/a/b', 200),
        ('//resource2//a//b', 200),
        ('//resource2//a//b/', 200),
        ('///resource2//a//b', 200),
        ('///resource2//a//b/', 200),
        ('/////resource2/a///b', 200),
        ('/////resource2/a///b/', 200),
        ('/resource1/a/b?p=1', 200),
        ('/resource1/a/b/?p=1', 404),
        ('//resource2//a//b?p=1', 200),
        ('//resource2//a//b/?p=1', 200),
        ('///resource1//a//b?p=1', 200),
        ('///resource1//a//b/?p=1', 404),
        ('/////resource1/a///b?p=1', 200),
        ('/////resource1/a///b/?p=1', 404),
        ('/resource2/a/b?p=1', 200),
        ('//resource2//a//b?p=1', 200),
        ('//resource2//a//b/?p=1', 200),
        ('///resource2//a//b?p=1', 200),
        ('///resource2//a//b/?p=1', 200),
        ('/////resource2/a///b?p=1', 200),
        ('/////resource2/a///b/?p=1', 200)
    ])
    async def test_append_and_merge_slash(self, path, status, cli) -> None:
        extra_middlewares = [
            web.normalize_path_middleware()]

        client = await cli(extra_middlewares)
        resp = await client.get(path)
        assert resp.status == status
        assert resp.url.query == URL(path).query

    @pytest.mark.parametrize("path, status", [
        ('/resource1/a/b', 200),
        ('/resource1/a/b/', 200),
        ('//resource2//a//b', 404),
        ('//resource2//a//b/', 200),
        ('///resource1//a//b', 200),
        ('///resource1//a//b/', 200),
        ('/////resource1/a///b', 200),
        ('/////resource1/a///b/', 200),
        ('/////resource1/a///b///', 200),
        ('/resource2/a/b', 404),
        ('//resource2//a//b', 404),
        ('//resource2//a//b/', 200),
        ('///resource2//a//b', 404),
        ('///resource2//a//b/', 200),
        ('/////resource2/a///b', 404),
        ('/////resource2/a///b/', 200),
        ('/resource1/a/b?p=1', 200),
        ('/resource1/a/b/?p=1', 200),
        ('//resource2//a//b?p=1', 404),
        ('//resource2//a//b/?p=1', 200),
        ('///resource1//a//b?p=1', 200),
        ('///resource1//a//b/?p=1', 200),
        ('/////resource1/a///b?p=1', 200),
        ('/////resource1/a///b/?p=1', 200),
        ('/resource2/a/b?p=1', 404),
        ('//resource2//a//b?p=1', 404),
        ('//resource2//a//b/?p=1', 200),
        ('///resource2//a//b?p=1', 404),
        ('///resource2//a//b/?p=1', 200),
        ('/////resource2/a///b?p=1', 404),
        ('/////resource2/a///b/?p=1', 200)
    ])
    async def test_remove_and_merge_slash(self, path, status, cli) -> None:
        extra_middlewares = [
            web.normalize_path_middleware(
                append_slash=False, remove_slash=True)]

        client = await cli(extra_middlewares)
        resp = await client.get(path)
        assert resp.status == status
        assert resp.url.query == URL(path).query

    async def test_cannot_remove_and_add_slash(self) -> None:
        with pytest.raises(AssertionError):
            web.normalize_path_middleware(append_slash=True, remove_slash=True)


async def test_bug_3669(aiohttp_client):
    async def paymethod(request):
        return web.Response(text="OK")

    app = web.Application()
    app.router.add_route('GET', '/paymethod', paymethod)
    app.middlewares.append(
        web.normalize_path_middleware(append_slash=False, remove_slash=True)
    )

    client = await aiohttp_client(
        app, server_kwargs={'skip_url_asserts': True}
    )

    resp = await client.get('/paymethods')
    assert resp.status == 404
    assert resp.url.path != '/paymethod'


async def test_old_style_middleware(loop, aiohttp_client) -> None:
    async def view_handler(request):
        return web.Response(body=b'OK')

    with pytest.warns(DeprecationWarning, match='Middleware decorator is'):
        @web.middleware
        async def middleware(request, handler):
            resp = await handler(request)
            assert 200 == resp.status
            resp.set_status(201)
            resp.text = resp.text + '[old style middleware]'
            return resp

    app = web.Application(middlewares=[middleware])
    app.router.add_route('GET', '/', view_handler)
    client = await aiohttp_client(app)
    resp = await client.get('/')
    assert 201 == resp.status
    txt = await resp.text()
    assert 'OK[old style middleware]' == txt


async def test_new_style_middleware_class(loop, aiohttp_client) -> None:
    async def handler(request):
        return web.Response(body=b'OK')

    class Middleware:
        async def __call__(self, request, handler):
            resp = await handler(request)
            assert 200 == resp.status
            resp.set_status(201)
            resp.text = resp.text + '[new style middleware]'
            return resp

    with pytest.warns(None) as warning_checker:
        app = web.Application()
        app.middlewares.append(Middleware())
        app.router.add_route('GET', '/', handler)
        client = await aiohttp_client(app)
        resp = await client.get('/')
        assert 201 == resp.status
        txt = await resp.text()
        assert 'OK[new style middleware]' == txt

    assert len(warning_checker) == 0


async def test_new_style_middleware_method(loop, aiohttp_client) -> None:
    async def handler(request):
        return web.Response(body=b'OK')

    class Middleware:
        async def call(self, request, handler):
            resp = await handler(request)
            assert 200 == resp.status
            resp.set_status(201)
            resp.text = resp.text + '[new style middleware]'
            return resp

    with pytest.warns(None) as warning_checker:
        app = web.Application()
        app.middlewares.append(Middleware().call)
        app.router.add_route('GET', '/', handler)
        client = await aiohttp_client(app)
        resp = await client.get('/')
        assert 201 == resp.status
        txt = await resp.text()
        assert 'OK[new style middleware]' == txt

    assert len(warning_checker) == 0
