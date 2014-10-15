import asyncio
import textwrap
from aiohttp import Application, ServerResponse, ServerStreamResponse


def intro(request):
    txt = textwrap.dedent("""\
        Type {url}/hello/John  {url}/simple or {url}/change_body
        in browser url bar
    """).format(url=request.host_url)
    binary = txt.encode('utf8')
    resp = ServerStreamResponse(request)
    resp.content_length = len(binary)
    resp.write(binary)


def simple(request):
    return ServerResponse(request, body=b'Simple answer')


def change_body(request):
    resp = ServerResponse(request)
    resp.body = b"Body changed"
    return resp


@asyncio.coroutine
def hello(request):
    resp = ServerStreamResponse(request)
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
    app.router.add_route('GET', '/simple', simple)
    app.router.add_route('GET', '/change_body', change_body)
    app.router.add_route('GET', '/hello/{name}', hello)
    app.router.add_route('GET', '/hello', hello)

    srv = yield from loop.create_server(app.make_handler, '127.0.0.1', 8080)
    print("Server started at http://{}".format(app.host))
    return srv

loop = asyncio.get_event_loop()
loop.run_until_complete(init(loop))
loop.run_forever()
