import logging
from aiohttp import web
import aiohttp_jinja2


log = logging.getLogger(__name__)


@aiohttp_jinja2.template('index.html')
async def index(request):
    resp = web.WebSocketResponse()
    ok, protocol = resp.can_start(request)
    if not ok:
        return {}

    await resp.prepare(request)
    log.info('Someone joined.')
    for ws in request.app['sockets']:
        ws.send_str('Someone joined')
    request.app['sockets'].append(resp)

    while True:
        msg = await resp.receive()

        if msg.tp == web.MsgType.text:
            for ws in request.app['sockets']:
                if ws is not resp:
                    ws.send_str(msg.data)
        else:
            break

    request.app['sockets'].remove(resp)
    log.info('Someone disconnected.')
    for ws in request.app['sockets']:
        ws.send_str('Someone disconnected.')
    return resp



def setup(app):
    app.router.add_route('GET', '/', index)
