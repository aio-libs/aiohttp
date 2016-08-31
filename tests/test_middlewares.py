import asyncio

from aiohttp import web, middlewares


class TestNormalizePathMiddleware:

    @asyncio.coroutine
    def test_add_trailing_when_necessary(self, create_app_and_client):
        app, client = yield from create_app_and_client()
        app.middlewares.append(middlewares.normalize_path_middleware)
        app.router.add_route(
            'GET', '/resource1', lambda x: web.Response(text="OK"))
        app.router.add_route(
            'GET', '/resource2/', lambda x: web.Response(text="OK"))

        resp = yield from client.get('/resource1')
        assert resp.status == 200

        resp = yield from client.get('/resource1/')
        assert resp.status == 404

        resp = yield from client.get('/resource2')
        assert resp.status == 200

        resp = yield from client.get('/resource2/')
        assert resp.status == 200
