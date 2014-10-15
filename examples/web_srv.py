import asyncio
from aiohttp import Application


def intro(request):
    txt = 'Type {}/hello/John in browser url bar'.format(request.host_url)
    binary = txt.encode('utf8')
    request.response.content_length = len(binary)
    request.response.write(binary)


def hello(request):
    resp = request.response
    name = request.match_info.matchdict.get('name', 'Anonimous')
    answer = ('Hello, ' + name).encode('utf8')
    resp.content_length = len(answer)
    resp.send_headers()
    resp.write(answer)
    yield from resp.write_eof()


@asyncio.coroutine
def init(loop):
    app = Application('localhost:8080', loop=loop)
    app.router.add_route('GET', '/', intro)
    app.router.add_route('GET', '/hello/{name}', hello)
    app.router.add_route('GET', '/hello', hello)

    srv = yield from loop.create_server(app.make_handler, '127.0.0.1', 8080)
    print("Server started at http://{}".format(app.host))
    return srv

loop = asyncio.get_event_loop()
loop.run_until_complete(init(loop))
loop.run_forever()
