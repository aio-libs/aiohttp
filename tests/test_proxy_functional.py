import asyncio
import os
from asyncio.compat import PY35

import pytest

from aiohttp import web


# TODO fix me check what's going on with this test on Windows?
@pytest.mark.skipif(not PY35 or os.name == 'nt',
                    reason='mitmdump does not support python 3.4')
@asyncio.coroutine
def test_proxy_via_mitmdump(loop, test_client, fake_proxy):
    @asyncio.coroutine
    def handler(request):
        return web.Response(text=request.method)

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)

    client = yield from test_client(app)
    resp = yield from client.get('/', proxy=fake_proxy.url())
    assert 200 == resp.status
    assert 'X-Mitmdump' in resp.headers
    assert resp.headers['X-Mitmdump'] == '1'
    resp.close()
