import asyncio
import os
import pathlib

import pytest

import aiohttp
from aiohttp import web


try:
    import ssl
except ImportError:
    ssl = False


@pytest.fixture(params=['sendfile', 'fallback'], ids=['sendfile', 'fallback'])
def sender(request):
    def maker(*args, **kwargs):
        ret = web.FileResponse(*args, **kwargs)
        if request.param == 'fallback':
            ret._sendfile = ret._sendfile_fallback
        return ret
    return maker


async def test_static_file_ok(aiohttp_client, sender):
    filepath = pathlib.Path(__file__).parent / 'data.unknown_mime_type'

    async def handler(request):
        return sender(filepath)

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    resp = await client.get('/')
    assert resp.status == 200
    txt = await resp.text()
    assert 'file content' == txt.rstrip()
    assert 'application/octet-stream' == resp.headers['Content-Type']
    assert resp.headers.get('Content-Encoding') is None
    await resp.release()


async def test_static_file_ok_string_path(aiohttp_client, sender):
    filepath = pathlib.Path(__file__).parent / 'data.unknown_mime_type'

    async def handler(request):
        return sender(str(filepath))

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    resp = await client.get('/')
    assert resp.status == 200
    txt = await resp.text()
    assert 'file content' == txt.rstrip()
    assert 'application/octet-stream' == resp.headers['Content-Type']
    assert resp.headers.get('Content-Encoding') is None
    await resp.release()


async def test_static_file_not_exists(aiohttp_client):

    app = web.Application()
    client = await aiohttp_client(app)

    resp = await client.get('/fake')
    assert resp.status == 404
    await resp.release()


async def test_static_file_name_too_long(aiohttp_client):

    app = web.Application()
    client = await aiohttp_client(app)

    resp = await client.get('/x*500')
    assert resp.status == 404
    await resp.release()


async def test_static_file_upper_directory(aiohttp_client):

    app = web.Application()
    client = await aiohttp_client(app)

    resp = await client.get('/../../')
    assert resp.status == 404
    await resp.release()


async def test_static_file_with_content_type(aiohttp_client, sender):
    filepath = (pathlib.Path(__file__).parent / 'aiohttp.jpg')

    async def handler(request):
        return sender(filepath, chunk_size=16)

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    resp = await client.get('/')
    assert resp.status == 200
    body = await resp.read()
    with filepath.open('rb') as f:
        content = f.read()
        assert content == body
    assert resp.headers['Content-Type'] == 'image/jpeg'
    assert resp.headers.get('Content-Encoding') is None
    resp.close()


async def test_static_file_custom_content_type(aiohttp_client, sender):
    filepath = (pathlib.Path(__file__).parent / 'hello.txt.gz')

    async def handler(request):
        resp = sender(filepath, chunk_size=16)
        resp.content_type = 'application/pdf'
        return resp

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    resp = await client.get('/')
    assert resp.status == 200
    body = await resp.read()
    with filepath.open('rb') as f:
        content = f.read()
        assert content == body
    assert resp.headers['Content-Type'] == 'application/pdf'
    assert resp.headers.get('Content-Encoding') is None
    resp.close()


async def test_static_file_custom_content_type_compress(aiohttp_client,
                                                        sender):
    filepath = (pathlib.Path(__file__).parent / 'hello.txt')

    async def handler(request):
        resp = sender(filepath, chunk_size=16)
        resp.content_type = 'application/pdf'
        return resp

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    resp = await client.get('/')
    assert resp.status == 200
    body = await resp.read()
    assert b'hello aiohttp\n' == body
    assert resp.headers['Content-Type'] == 'application/pdf'
    assert resp.headers.get('Content-Encoding') == 'gzip'
    resp.close()


async def test_static_file_with_content_encoding(aiohttp_client, sender):
    filepath = pathlib.Path(__file__).parent / 'hello.txt.gz'

    async def handler(request):
        return sender(filepath)

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    resp = await client.get('/')
    assert 200 == resp.status
    body = await resp.read()
    assert b'hello aiohttp\n' == body
    ct = resp.headers['CONTENT-TYPE']
    assert 'text/plain' == ct
    encoding = resp.headers['CONTENT-ENCODING']
    assert 'gzip' == encoding
    resp.close()


async def test_static_file_if_modified_since(aiohttp_client, sender):
    filename = 'data.unknown_mime_type'
    filepath = pathlib.Path(__file__).parent / filename

    async def handler(request):
        return sender(filepath)

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    resp = await client.get('/')
    assert 200 == resp.status
    lastmod = resp.headers.get('Last-Modified')
    assert lastmod is not None
    resp.close()

    resp = await client.get('/', headers={'If-Modified-Since': lastmod})
    body = await resp.read()
    assert 304 == resp.status
    assert resp.headers.get('Content-Length') is None
    assert b'' == body
    resp.close()


async def test_static_file_if_modified_since_past_date(aiohttp_client, sender):
    filename = 'data.unknown_mime_type'
    filepath = pathlib.Path(__file__).parent / filename

    async def handler(request):
        return sender(filepath)

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    lastmod = 'Mon, 1 Jan 1990 01:01:01 GMT'

    resp = await client.get('/', headers={'If-Modified-Since': lastmod})
    assert 200 == resp.status
    resp.close()


async def test_static_file_if_modified_since_invalid_date(aiohttp_client,
                                                          sender):
    filename = 'data.unknown_mime_type'
    filepath = pathlib.Path(__file__).parent / filename

    async def handler(request):
        return sender(filepath)

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    lastmod = 'not a valid HTTP-date'

    resp = await client.get('/', headers={'If-Modified-Since': lastmod})
    assert 200 == resp.status
    resp.close()


async def test_static_file_if_modified_since_future_date(aiohttp_client,
                                                         sender):
    filename = 'data.unknown_mime_type'
    filepath = pathlib.Path(__file__).parent / filename

    async def handler(request):
        return sender(filepath)

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    lastmod = 'Fri, 31 Dec 9999 23:59:59 GMT'

    resp = await client.get('/', headers={'If-Modified-Since': lastmod})
    body = await resp.read()
    assert 304 == resp.status
    assert resp.headers.get('Content-Length') is None
    assert b'' == body
    resp.close()


@pytest.mark.skipif(not ssl, reason="ssl not supported")
async def test_static_file_ssl(aiohttp_server, aiohttp_client):
    dirname = os.path.dirname(__file__)
    filename = 'data.unknown_mime_type'
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    ssl_ctx.load_cert_chain(
        os.path.join(dirname, 'sample.crt'),
        os.path.join(dirname, 'sample.key')
    )
    app = web.Application()
    app.router.add_static('/static', dirname)
    server = await aiohttp_server(app, ssl=ssl_ctx)
    conn = aiohttp.TCPConnector(ssl=False)
    client = await aiohttp_client(server, connector=conn)

    resp = await client.get('/static/'+filename)
    assert 200 == resp.status
    txt = await resp.text()
    assert 'file content' == txt.rstrip()
    ct = resp.headers['CONTENT-TYPE']
    assert 'application/octet-stream' == ct
    assert resp.headers.get('CONTENT-ENCODING') is None


async def test_static_file_directory_traversal_attack(loop, aiohttp_client):
    dirname = os.path.dirname(__file__)
    relpath = '../README.rst'
    assert os.path.isfile(os.path.join(dirname, relpath))

    app = web.Application()
    app.router.add_static('/static', dirname)
    client = await aiohttp_client(app)

    resp = await client.get('/static/'+relpath)
    assert 404 == resp.status

    url_relpath2 = '/static/dir/../' + relpath
    resp = await client.get(url_relpath2)
    assert 404 == resp.status

    url_abspath = \
        '/static/' + os.path.abspath(os.path.join(dirname, relpath))
    resp = await client.get(url_abspath)
    assert 403 == resp.status


def test_static_route_path_existence_check():
    directory = os.path.dirname(__file__)
    web.StaticResource("/", directory)

    nodirectory = os.path.join(directory, "nonexistent-uPNiOEAg5d")
    with pytest.raises(ValueError):
        web.StaticResource("/", nodirectory)


async def test_static_file_huge(loop, aiohttp_client, tmpdir):
    filename = 'huge_data.unknown_mime_type'

    # fill 100MB file
    with tmpdir.join(filename).open('w') as f:
        for i in range(1024*20):
            f.write(chr(i % 64 + 0x20) * 1024)

    file_st = os.stat(str(tmpdir.join(filename)))

    app = web.Application()
    app.router.add_static('/static', str(tmpdir))
    client = await aiohttp_client(app)

    resp = await client.get('/static/'+filename)
    assert 200 == resp.status
    ct = resp.headers['CONTENT-TYPE']
    assert 'application/octet-stream' == ct
    assert resp.headers.get('CONTENT-ENCODING') is None
    assert int(resp.headers.get('CONTENT-LENGTH')) == file_st.st_size

    f = tmpdir.join(filename).open('rb')
    off = 0
    cnt = 0
    while off < file_st.st_size:
        chunk = await resp.content.readany()
        expected = f.read(len(chunk))
        assert chunk == expected
        off += len(chunk)
        cnt += 1
    f.close()


async def test_static_file_range(loop, aiohttp_client, sender):
    filepath = (pathlib.Path(__file__).parent.parent / 'LICENSE.txt')

    async def handler(request):
        return sender(filepath, chunk_size=16)

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(lambda loop: app)

    with filepath.open('rb') as f:
        content = f.read()

    # Ensure the whole file requested in parts is correct
    responses = await asyncio.gather(
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

    body = await asyncio.gather(
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


async def test_static_file_range_end_bigger_than_size(
    loop,
    aiohttp_client,
    sender
):
    filepath = (pathlib.Path(__file__).parent / 'aiohttp.png')

    async def handler(request):
        return sender(filepath, chunk_size=16)

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(lambda loop: app)

    with filepath.open('rb') as f:
        content = f.read()

        # Ensure the whole file requested in parts is correct
        response = await client.get(
            '/', headers={'Range': 'bytes=61000-62000'})

        assert response.status == 206, \
            "failed 'bytes=61000-62000': %s" % response.reason

        body = await response.read()
        assert len(body) == 108, \
            "failed 'bytes=0-999', received %d bytes" % len(body[0])

        assert content[61000:] == body


async def test_static_file_range_beyond_eof(loop, aiohttp_client, sender):
    filepath = (pathlib.Path(__file__).parent / 'aiohttp.png')

    async def handler(request):
        return sender(filepath, chunk_size=16)

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(lambda loop: app)

    # Ensure the whole file requested in parts is correct
    response = await client.get(
        '/', headers={'Range': 'bytes=1000000-1200000'})

    assert response.status == 206, \
        "failed 'bytes=1000000-1200000': %s" % response.reason
    assert response.headers['content-length'] == '0'


async def test_static_file_range_tail(loop, aiohttp_client, sender):
    filepath = (pathlib.Path(__file__).parent / 'aiohttp.png')

    async def handler(request):
        return sender(filepath, chunk_size=16)

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(lambda loop: app)

    with filepath.open('rb') as f:
        content = f.read()

    # Ensure the tail of the file is correct
    resp = await client.get('/', headers={'Range': 'bytes=-500'})
    assert resp.status == 206, resp.reason
    body4 = await resp.read()
    resp.close()
    assert content[-500:] == body4


async def test_static_file_invalid_range(loop, aiohttp_client, sender):
    filepath = (pathlib.Path(__file__).parent / 'aiohttp.png')

    async def handler(request):
        return sender(filepath, chunk_size=16)

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(lambda loop: app)

    # range must be in bytes
    resp = await client.get('/', headers={'Range': 'blocks=0-10'})
    assert resp.status == 416, 'Range must be in bytes'
    resp.close()

    # start > end
    resp = await client.get('/', headers={'Range': 'bytes=100-0'})
    assert resp.status == 416, "Range start can't be greater than end"
    resp.close()

    # start > end
    resp = await client.get('/', headers={'Range': 'bytes=10-9'})
    assert resp.status == 416, "Range start can't be greater than end"
    resp.close()

    # non-number range
    resp = await client.get('/', headers={'Range': 'bytes=a-f'})
    assert resp.status == 416, 'Range must be integers'
    resp.close()

    # double dash range
    resp = await client.get('/', headers={'Range': 'bytes=0--10'})
    assert resp.status == 416, 'double dash in range'
    resp.close()

    # no range
    resp = await client.get('/', headers={'Range': 'bytes=-'})
    assert resp.status == 416, 'no range given'
    resp.close()
