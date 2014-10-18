import asyncio
import textwrap
from aiohttp.web import Application, Response, StreamResponse


def intro(request):
    txt = textwrap.dedent("""\
        Type {url}/hello/John  {url}/simple or {url}/change_body
        in browser url bar
    """).format(url='127.0.0.1:8080')
    binary = txt.encode('utf8')
    resp = StreamResponse(request)
    resp.content_length = len(binary)
    resp.write(binary)
    return resp


def simple(request):
    return Response(request, b'Simple answer')


def change_body(request):
    resp = Response(request)
    resp.body = b"Body changed"
    return resp


@asyncio.coroutine
def hello(request):
    resp = StreamResponse(request)
    name = request.match_info.matchdict.get('name', 'Anonimous')
    answer = ('Hello, ' + name).encode('utf8')
    resp.content_length = len(answer)
    resp.send_headers()
    resp.write(answer)
    yield from resp.write_eof()
    return resp


@asyncio.coroutine
def init(loop):
    app = Application(loop=loop)
    app.router.add_route('GET', '/', intro)
    app.router.add_route('GET', '/simple', simple)
    app.router.add_route('GET', '/change_body', change_body)
    app.router.add_route('GET', '/hello/{name}', hello)
    app.router.add_route('GET', '/hello', hello)

    srv = yield from loop.create_server(app.make_handler, '127.0.0.1', 8080)
    print("Server started at http://127.0.0.1:8080")
    return srv

loop = asyncio.get_event_loop()
loop.run_until_complete(init(loop))
loop.run_forever()
