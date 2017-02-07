import asyncio
import os
import pathlib

import pytest

import aiohttp
from aiohttp import web
from aiohttp.file_sender import FileSender
from aiohttp.test_utils import loop_context

try:
    import ssl
except:
    ssl = False


try:
    import uvloop
except:
    uvloop = None


LOOP_FACTORIES = [asyncio.new_event_loop]
if uvloop:
    LOOP_FACTORIES.append(uvloop.new_event_loop)


@pytest.yield_fixture(params=LOOP_FACTORIES)
def loop(request):
    with loop_context(request.param) as loop:
        yield loop


@pytest.fixture(params=['sendfile', 'fallback'], ids=['sendfile', 'fallback'])
def sender(request):
    def maker(*args, **kwargs):
        ret = FileSender(*args, **kwargs)
        if request.param == 'fallback':
            ret._sendfile = ret._sendfile_fallback
        return ret
    return maker


@asyncio.coroutine
def test_static_file_ok(loop, test_client, sender):
    filepath = pathlib.Path(__file__).parent / 'data.unknown_mime_type'

    @asyncio.coroutine
    def handler(request):
        resp = yield from sender().send(request, filepath)
        return resp

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(lambda loop: app)

    resp = yield from client.get('/')
    assert resp.status == 200
    txt = yield from resp.text()
    assert 'file content' == txt.rstrip()
    assert 'application/octet-stream' == resp.headers['Content-Type']
    assert resp.headers.get('Content-Encoding') is None
    yield from resp.release()


@asyncio.coroutine
def test_static_file_not_exists(loop, test_client):

    app = web.Application(loop=loop)
    client = yield from test_client(lambda loop: app)

    resp = yield from client.get('/fake')
    assert resp.status == 404
    yield from resp.release()


@asyncio.coroutine
def test_static_file_name_too_long(loop, test_client):

    app = web.Application(loop=loop)
    client = yield from test_client(lambda loop: app)

    resp = yield from client.get('/x*500')
    assert resp.status == 404
    yield from resp.release()


@asyncio.coroutine
def test_static_file_upper_directory(loop, test_client):

    app = web.Application(loop=loop)
    client = yield from test_client(lambda loop: app)

    resp = yield from client.get('/../../')
    assert resp.status == 404
    yield from resp.release()


@asyncio.coroutine
def test_static_file_with_content_type(loop, test_client, sender):
    filepath = (pathlib.Path(__file__).parent / 'aiohttp.png')

    @asyncio.coroutine
    def handler(request):
        resp = yield from sender(chunk_size=16).send(request, filepath)
        return resp

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(lambda loop: app)

    resp = yield from client.get('/')
    assert resp.status == 200
    body = yield from resp.read()
    with filepath.open('rb') as f:
        content = f.read()
        assert content == body
    assert resp.headers['Content-Type'] == 'image/png'
    assert resp.headers.get('Content-Encoding') is None
    resp.close()


@asyncio.coroutine
def test_static_file_with_content_encoding(loop, test_client, sender):
    filepath = pathlib.Path(__file__).parent / 'hello.txt.gz'

    @asyncio.coroutine
    def handler(request):
        resp = yield from sender().send(request, filepath)
        return resp

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(lambda loop: app)

    resp = yield from client.get('/')
    assert 200 == resp.status
    body = yield from resp.read()
    assert b'hello aiohttp\n' == body
    ct = resp.headers['CONTENT-TYPE']
    assert 'text/plain' == ct
    encoding = resp.headers['CONTENT-ENCODING']
    assert 'gzip' == encoding
    resp.close()


@asyncio.coroutine
def test_static_file_if_modified_since(loop, test_client, sender):
    filename = 'data.unknown_mime_type'
    filepath = pathlib.Path(__file__).parent / filename

    @asyncio.coroutine
    def handler(request):
        resp = yield from sender().send(request, filepath)
        return resp

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(lambda loop: app)

    resp = yield from client.get('/')
    assert 200 == resp.status
    lastmod = resp.headers.get('Last-Modified')
    assert lastmod is not None
    resp.close()

    resp = yield from client.get('/', headers={'If-Modified-Since': lastmod})
    assert 304 == resp.status
    resp.close()


@asyncio.coroutine
def test_static_file_if_modified_since_past_date(loop, test_client, sender):
    filename = 'data.unknown_mime_type'
    filepath = pathlib.Path(__file__).parent / filename

    @asyncio.coroutine
    def handler(request):
        resp = yield from sender().send(request, filepath)
        return resp

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(lambda loop: app)

    lastmod = 'Mon, 1 Jan 1990 01:01:01 GMT'

    resp = yield from client.get('/', headers={'If-Modified-Since': lastmod})
    assert 200 == resp.status
    resp.close()


@asyncio.coroutine
def test_static_file_if_modified_since_invalid_date(loop, test_client, sender):
    filename = 'data.unknown_mime_type'
    filepath = pathlib.Path(__file__).parent / filename

    @asyncio.coroutine
    def handler(request):
        resp = yield from sender().send(request, filepath)
        return resp

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(lambda loop: app)

    lastmod = 'not a valid HTTP-date'

    resp = yield from client.get('/', headers={'If-Modified-Since': lastmod})
    assert 200 == resp.status
    resp.close()


@asyncio.coroutine
def test_static_file_if_modified_since_future_date(loop, test_client, sender):
    filename = 'data.unknown_mime_type'
    filepath = pathlib.Path(__file__).parent / filename

    @asyncio.coroutine
    def handler(request):
        resp = yield from sender().send(request, filepath)
        return resp

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(lambda loop: app)

    lastmod = 'Fri, 31 Dec 9999 23:59:59 GMT'

    resp = yield from client.get('/', headers={'If-Modified-Since': lastmod})
    assert 304 == resp.status
    resp.close()


@pytest.mark.skipif(not ssl, reason="ssl not supported")
@asyncio.coroutine
def test_static_file_ssl(loop, test_server, test_client):
    dirname = os.path.dirname(__file__)
    filename = 'data.unknown_mime_type'
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    ssl_ctx.load_cert_chain(
        os.path.join(dirname, 'sample.crt'),
        os.path.join(dirname, 'sample.key')
    )
    app = web.Application(loop=loop)
    app.router.add_static('/static', dirname)
    server = yield from test_server(app, ssl=ssl_ctx)
    conn = aiohttp.TCPConnector(verify_ssl=False, loop=loop)
    client = yield from test_client(server, connector=conn)

    resp = yield from client.get('/static/'+filename)
    assert 200 == resp.status
    txt = yield from resp.text()
    assert 'file content' == txt.rstrip()
    ct = resp.headers['CONTENT-TYPE']
    assert 'application/octet-stream' == ct
    assert resp.headers.get('CONTENT-ENCODING') is None


@asyncio.coroutine
def test_static_file_directory_traversal_attack(loop, test_client):
    dirname = os.path.dirname(__file__)
    relpath = '../README.rst'
    assert os.path.isfile(os.path.join(dirname, relpath))

    app = web.Application(loop=loop)
    app.router.add_static('/static', dirname)
    client = yield from test_client(app)

    resp = yield from client.get('/static/'+relpath)
    assert 404 == resp.status

    url_relpath2 = '/static/dir/../' + relpath
    resp = yield from client.get(url_relpath2)
    assert 404 == resp.status

    url_abspath = \
        '/static/' + os.path.abspath(os.path.join(dirname, relpath))
    resp = yield from client.get(url_abspath)
    assert 404 == resp.status


def test_static_route_path_existence_check():
    directory = os.path.dirname(__file__)
    web.StaticResource("/", directory)

    nodirectory = os.path.join(directory, "nonexistent-uPNiOEAg5d")
    with pytest.raises(ValueError):
        web.StaticResource("/", nodirectory)


@asyncio.coroutine
def test_static_file_huge(loop, test_client, tmpdir):
    filename = 'huge_data.unknown_mime_type'

    # fill 100MB file
    with tmpdir.join(filename).open('w') as f:
        for i in range(1024*20):
            f.write(chr(i % 64 + 0x20) * 1024)

    file_st = os.stat(str(tmpdir.join(filename)))

    app = web.Application(loop=loop)
    app.router.add_static('/static', str(tmpdir))
    client = yield from test_client(app)

    resp = yield from client.get('/static/'+filename)
    assert 200 == resp.status
    ct = resp.headers['CONTENT-TYPE']
    assert 'application/octet-stream' == ct
    assert resp.headers.get('CONTENT-ENCODING') is None
    assert int(resp.headers.get('CONTENT-LENGTH')) == file_st.st_size

    f = tmpdir.join(filename).open('rb')
    off = 0
    cnt = 0
    while off < file_st.st_size:
        chunk = yield from resp.content.readany()
        expected = f.read(len(chunk))
        assert chunk == expected
        off += len(chunk)
        cnt += 1
    f.close()


@asyncio.coroutine
def test_static_file_range(loop, test_client, sender):
    filepath = (pathlib.Path(__file__).parent / 'aiohttp.png')

    @asyncio.coroutine
    def handler(request):
        resp = yield from sender(chunk_size=16).send(request, filepath)
        return resp

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(lambda loop: app)

    with filepath.open('rb') as f:
        content = f.read()

    # Ensure the whole file requested in parts is correct
    responses = yield from asyncio.gather(
        client.get('/', headers={'Range': 'bytes=0-999'}),
        client.get('/', headers={'Range': 'bytes=1000-1999'}),
        client.get('/', headers={'Range': 'bytes=2000-'}),
        loop=loop
    )
    assert len(responses) == 3
    assert responses[0].status == 206, \
        "failed 'bytes=0-999': %s" % responses[0].reason
    assert responses[1].status == 206, \
        "failed 'bytes=1000-1999': %s" % responses[1].reason
    assert responses[2].status == 206, \
        "failed 'bytes=2000-': %s" % responses[2].reason

    body = yield from asyncio.gather(
        *(resp.read() for resp in responses),
        loop=loop
    )

    assert len(body[0]) == 1000, \
        "failed 'bytes=0-999', received %d bytes" % len(body[0])
    assert len(body[1]) == 1000, \
        "failed 'bytes=1000-1999', received %d bytes" % len(body[1])
    responses[0].close()
    responses[1].close()
    responses[2].close()

    assert content == b"".join(body)


@asyncio.coroutine
def test_static_file_range_end_bigger_than_size(loop, test_client, sender):
    filepath = (pathlib.Path(__file__).parent / 'aiohttp.png')

    @asyncio.coroutine
    def handler(request):
        resp = yield from sender(chunk_size=16).send(request, filepath)
        return resp

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(lambda loop: app)

    with filepath.open('rb') as f:
        content = f.read()

        # Ensure the whole file requested in parts is correct
        response = yield from client.get(
            '/', headers={'Range': 'bytes=61000-62000'})

        assert response.status == 206, \
            "failed 'bytes=61000-62000': %s" % response.reason

        body = yield from response.read()
        assert len(body) == 108, \
            "failed 'bytes=0-999', received %d bytes" % len(body[0])

        assert content[61000:] == body


@asyncio.coroutine
def test_static_file_range_tail(loop, test_client, sender):
    filepath = (pathlib.Path(__file__).parent / 'aiohttp.png')

    @asyncio.coroutine
    def handler(request):
        resp = yield from sender(chunk_size=16).send(request, filepath)
        return resp

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(lambda loop: app)

    with filepath.open('rb') as f:
        content = f.read()

    # Ensure the tail of the file is correct
    resp = yield from client.get('/', headers={'Range': 'bytes=-500'})
    assert resp.status == 206, resp.reason
    body4 = yield from resp.read()
    resp.close()
    assert content[-500:] == body4


@asyncio.coroutine
def test_static_file_invalid_range(loop, test_client, sender):
    filepath = (pathlib.Path(__file__).parent / 'aiohttp.png')

    @asyncio.coroutine
    def handler(request):
        resp = yield from sender(chunk_size=16).send(request, filepath)
        return resp

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(lambda loop: app)

    # range must be in bytes
    resp = yield from client.get('/', headers={'Range': 'blocks=0-10'})
    assert resp.status == 416, 'Range must be in bytes'
    resp.close()

    # start > end
    resp = yield from client.get('/', headers={'Range': 'bytes=100-0'})
    assert resp.status == 416, "Range start can't be greater than end"
    resp.close()

    # start > end
    resp = yield from client.get('/', headers={'Range': 'bytes=10-9'})
    assert resp.status == 416, "Range start can't be greater than end"
    resp.close()

    # non-number range
    resp = yield from client.get('/', headers={'Range': 'bytes=a-f'})
    assert resp.status == 416, 'Range must be integers'
    resp.close()

    # double dash range
    resp = yield from client.get('/', headers={'Range': 'bytes=0--10'})
    assert resp.status == 416, 'double dash in range'
    resp.close()

    # no range
    resp = yield from client.get('/', headers={'Range': 'bytes=-'})
    assert resp.status == 416, 'no range given'
    resp.close()
