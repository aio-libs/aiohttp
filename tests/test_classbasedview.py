from unittest import mock

import pytest

from aiohttp import web
from aiohttp.web_urldispatcher import View


def test_ctor() -> None:
    request = mock.Mock()
    view = View(request)
    assert view.request is request


async def test_render_ok() -> None:
    resp = web.Response(text="OK")

    class MyView(View):
        async def get(self):
            return resp

    request = mock.Mock()
    request.method = "GET"
    resp2 = await MyView(request)
    assert resp is resp2


async def test_render_unknown_method() -> None:
    class MyView(View):
        async def get(self):
            return web.Response(text="OK")

        options = get

    request = mock.Mock()
    request.method = "UNKNOWN"
    with pytest.raises(web.HTTPMethodNotAllowed) as ctx:
        await MyView(request)
    assert ctx.value.headers["allow"] == "GET,OPTIONS"
    assert ctx.value.status == 405


async def test_render_unsupported_method() -> None:
    class MyView(View):
        async def get(self):
            return web.Response(text="OK")

        options = delete = get

    request = mock.Mock()
    request.method = "POST"
    with pytest.raises(web.HTTPMethodNotAllowed) as ctx:
        await MyView(request)
    assert ctx.value.headers["allow"] == "DELETE,GET,OPTIONS"
    assert ctx.value.status == 405
