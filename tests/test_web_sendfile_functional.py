import asyncio
import pathlib
import socket
import zlib

import pytest

import aiohttp
from aiohttp import web

try:
    import ssl
except ImportError:
    ssl = None  # type: ignore


@pytest.fixture(params=['sendfile', 'fallback'], ids=['sendfile', 'fallback'])
def sender(request):
    def maker(*args, **kwargs):
        ret = web.FileResponse(*args, **kwargs)
        if request.param == 'fallback':
            ret._sendfile = ret._sendfile_fallback
        return ret
    return maker


async def test_static_file_ok(aiohttp_client, sender) -> None:
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


async def test_static_file_ok_string_path(aiohttp_client, sender) -> None:
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


async def test_static_file_not_exists(aiohttp_client) -> None:

    app = web.Application()
    client = await aiohttp_client(app)

    resp = await client.get('/fake')
    assert resp.status == 404
    await resp.release()


async def test_static_file_name_too_long(aiohttp_client) -> None:

    app = web.Application()
    client = await aiohttp_client(app)

    resp = await client.get('/x*500')
    assert resp.status == 404
    await resp.release()


async def test_static_file_upper_directory(aiohttp_client) -> None:

    app = web.Application()
    client = await aiohttp_client(app)

    resp = await client.get('/../../')
    assert resp.status == 404
    await resp.release()


async def test_static_file_with_content_type(aiohttp_client, sender) -> None:
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


async def test_static_file_custom_content_type(aiohttp_client, sender) -> None:
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


async def test_static_file_with_content_encoding(aiohttp_client,
                                                 sender) -> None:
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


async def test_static_file_if_modified_since(aiohttp_client, sender) -> None:
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


async def test_static_file_if_modified_since_past_date(aiohttp_client,
                                                       sender) -> None:
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
async def test_static_file_ssl(
        aiohttp_server, ssl_ctx,
        aiohttp_client, client_ssl_ctx,
) -> None:
    dirname = pathlib.Path(__file__).parent
    filename = 'data.unknown_mime_type'
    app = web.Application()
    app.router.add_static('/static', dirname)
    server = await aiohttp_server(app, ssl=ssl_ctx)
    conn = aiohttp.TCPConnector(ssl=client_ssl_ctx)
    client = await aiohttp_client(server, connector=conn)

    resp = await client.get('/static/'+filename)
    assert 200 == resp.status
    txt = await resp.text()
    assert 'file content' == txt.rstrip()
    ct = resp.headers['CONTENT-TYPE']
    assert 'application/octet-stream' == ct
    assert resp.headers.get('CONTENT-ENCODING') is None


async def test_static_file_directory_traversal_attack(aiohttp_client) -> None:
    dirname = pathlib.Path(__file__).parent
    relpath = '../README.rst'
    full_path = dirname / relpath
    assert full_path.is_file()

    app = web.Application()
    app.router.add_static('/static', dirname)
    client = await aiohttp_client(app)

    resp = await client.get('/static/'+relpath)
    assert 404 == resp.status

    url_relpath2 = '/static/dir/../' + relpath
    resp = await client.get(url_relpath2)
    assert 404 == resp.status

    url_abspath = '/static/' + str(full_path.resolve())
    resp = await client.get(url_abspath)
    assert 403 == resp.status


def test_static_route_path_existence_check() -> None:
    directory = pathlib.Path(__file__).parent
    web.StaticResource("/", directory)

    nodirectory = directory / "nonexistent-uPNiOEAg5d"
    with pytest.raises(ValueError):
        web.StaticResource("/", nodirectory)


async def test_static_file_huge(aiohttp_client, tmp_path) -> None:
    file_path = tmp_path / 'huge_data.unknown_mime_type'

    # fill 20MB file
    with file_path.open('wb') as f:
        for i in range(1024*20):
            f.write((chr(i % 64 + 0x20) * 1024).encode())

    file_st = file_path.stat()

    app = web.Application()
    app.router.add_static('/static', str(tmp_path))
    client = await aiohttp_client(app)

    resp = await client.get('/static/'+file_path.name)
    assert 200 == resp.status
    ct = resp.headers['CONTENT-TYPE']
    assert 'application/octet-stream' == ct
    assert resp.headers.get('CONTENT-ENCODING') is None
    assert int(resp.headers.get('CONTENT-LENGTH')) == file_st.st_size

    f = file_path.open('rb')
    off = 0
    cnt = 0
    while off < file_st.st_size:
        chunk = await resp.content.readany()
        expected = f.read(len(chunk))
        assert chunk == expected
        off += len(chunk)
        cnt += 1
    f.close()


async def test_static_file_range(aiohttp_client, sender) -> None:
    filepath = (pathlib.Path(__file__).parent.parent / 'LICENSE.txt')

    filesize = filepath.stat().st_size

    async def handler(request):
        return sender(filepath, chunk_size=16)

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    with filepath.open('rb') as f:
        content = f.read()

    # Ensure the whole file requested in parts is correct
    responses = await asyncio.gather(
        client.get('/', headers={'Range': 'bytes=0-999'}),
        client.get('/', headers={'Range': 'bytes=1000-1999'}),
        client.get('/', headers={'Range': 'bytes=2000-'}),
    )
    assert len(responses) == 3
    assert responses[0].status == 206, \
        "failed 'bytes=0-999': %s" % responses[0].reason
    assert responses[0].headers['Content-Range'] == 'bytes 0-999/{0}'.format(
        filesize), 'failed: Content-Range Error'
    assert responses[1].status == 206, \
        "failed 'bytes=1000-1999': %s" % responses[1].reason
    assert responses[1].headers['Content-Range'] == \
        'bytes 1000-1999/{0}'.format(filesize), 'failed: Content-Range Error'
    assert responses[2].status == 206, \
        "failed 'bytes=2000-': %s" % responses[2].reason
    assert responses[2].headers['Content-Range'] == \
        'bytes 2000-{0}/{1}'.format(filesize - 1, filesize), \
        'failed: Content-Range Error'

    body = await asyncio.gather(
        *(resp.read() for resp in responses),
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
    aiohttp_client,
    sender
):
    filepath = (pathlib.Path(__file__).parent / 'aiohttp.png')

    async def handler(request):
        return sender(filepath, chunk_size=16)

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    with filepath.open('rb') as f:
        content = f.read()

        # Ensure the whole file requested in parts is correct
        response = await client.get(
            '/', headers={'Range': 'bytes=54000-55000'})

        assert response.status == 206, \
            "failed 'bytes=54000-55000': %s" % response.reason
        assert response.headers['Content-Range'] == \
            'bytes 54000-54996/54997', 'failed: Content-Range Error'

        body = await response.read()
        assert len(body) == 997, \
            "failed 'bytes=54000-55000', received %d bytes" % len(body)

        assert content[54000:] == body


async def test_static_file_range_beyond_eof(aiohttp_client, sender) -> None:
    filepath = (pathlib.Path(__file__).parent / 'aiohttp.png')

    async def handler(request):
        return sender(filepath, chunk_size=16)

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    # Ensure the whole file requested in parts is correct
    response = await client.get(
        '/', headers={'Range': 'bytes=1000000-1200000'})

    assert response.status == 416, \
        "failed 'bytes=1000000-1200000': %s" % response.reason


async def test_static_file_range_tail(aiohttp_client, sender) -> None:
    filepath = (pathlib.Path(__file__).parent / 'aiohttp.png')

    async def handler(request):
        return sender(filepath, chunk_size=16)

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    with filepath.open('rb') as f:
        content = f.read()

    # Ensure the tail of the file is correct
    resp = await client.get('/', headers={'Range': 'bytes=-500'})
    assert resp.status == 206, resp.reason
    assert resp.headers['Content-Range'] == 'bytes 54497-54996/54997', \
        'failed: Content-Range Error'
    body4 = await resp.read()
    resp.close()
    assert content[-500:] == body4

    # Ensure out-of-range tails could be handled
    resp2 = await client.get('/', headers={'Range': 'bytes=-99999999999999'})
    assert resp2.status == 206, resp.reason
    assert resp2.headers['Content-Range'] == 'bytes 0-54996/54997', \
        'failed: Content-Range Error'


async def test_static_file_invalid_range(aiohttp_client, sender) -> None:
    filepath = (pathlib.Path(__file__).parent / 'aiohttp.png')

    async def handler(request):
        return sender(filepath, chunk_size=16)

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

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


async def test_static_file_if_unmodified_since_past_with_range(
        aiohttp_client, sender):
    filename = 'data.unknown_mime_type'
    filepath = pathlib.Path(__file__).parent / filename

    async def handler(request):
        return sender(filepath)

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    lastmod = 'Mon, 1 Jan 1990 01:01:01 GMT'

    resp = await client.get('/', headers={
        'If-Unmodified-Since': lastmod,
        'Range': 'bytes=2-'})
    assert 412 == resp.status
    resp.close()


async def test_static_file_if_unmodified_since_future_with_range(
        aiohttp_client, sender):
    filename = 'data.unknown_mime_type'
    filepath = pathlib.Path(__file__).parent / filename

    async def handler(request):
        return sender(filepath)

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    lastmod = 'Fri, 31 Dec 9999 23:59:59 GMT'

    resp = await client.get('/', headers={
        'If-Unmodified-Since': lastmod,
        'Range': 'bytes=2-'})
    assert 206 == resp.status
    assert resp.headers['Content-Range'] == 'bytes 2-12/13'
    assert resp.headers['Content-Length'] == '11'
    resp.close()


async def test_static_file_if_range_past_with_range(
        aiohttp_client, sender):
    filename = 'data.unknown_mime_type'
    filepath = pathlib.Path(__file__).parent / filename

    async def handler(request):
        return sender(filepath)

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    lastmod = 'Mon, 1 Jan 1990 01:01:01 GMT'

    resp = await client.get('/', headers={
        'If-Range': lastmod,
        'Range': 'bytes=2-'})
    assert 200 == resp.status
    assert resp.headers['Content-Length'] == '13'
    resp.close()


async def test_static_file_if_range_future_with_range(
        aiohttp_client, sender):
    filename = 'data.unknown_mime_type'
    filepath = pathlib.Path(__file__).parent / filename

    async def handler(request):
        return sender(filepath)

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    lastmod = 'Fri, 31 Dec 9999 23:59:59 GMT'

    resp = await client.get('/', headers={
        'If-Range': lastmod,
        'Range': 'bytes=2-'})
    assert 206 == resp.status
    assert resp.headers['Content-Range'] == 'bytes 2-12/13'
    assert resp.headers['Content-Length'] == '11'
    resp.close()


async def test_static_file_if_unmodified_since_past_without_range(
        aiohttp_client, sender):
    filename = 'data.unknown_mime_type'
    filepath = pathlib.Path(__file__).parent / filename

    async def handler(request):
        return sender(filepath)

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    lastmod = 'Mon, 1 Jan 1990 01:01:01 GMT'

    resp = await client.get('/', headers={'If-Unmodified-Since': lastmod})
    assert 412 == resp.status
    resp.close()


async def test_static_file_if_unmodified_since_future_without_range(
        aiohttp_client, sender):
    filename = 'data.unknown_mime_type'
    filepath = pathlib.Path(__file__).parent / filename

    async def handler(request):
        return sender(filepath)

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    lastmod = 'Fri, 31 Dec 9999 23:59:59 GMT'

    resp = await client.get('/', headers={'If-Unmodified-Since': lastmod})
    assert 200 == resp.status
    assert resp.headers['Content-Length'] == '13'
    resp.close()


async def test_static_file_if_range_past_without_range(
        aiohttp_client, sender):
    filename = 'data.unknown_mime_type'
    filepath = pathlib.Path(__file__).parent / filename

    async def handler(request):
        return sender(filepath)

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    lastmod = 'Mon, 1 Jan 1990 01:01:01 GMT'

    resp = await client.get('/', headers={'If-Range': lastmod})
    assert 200 == resp.status
    assert resp.headers['Content-Length'] == '13'
    resp.close()


async def test_static_file_if_range_future_without_range(
        aiohttp_client, sender):
    filename = 'data.unknown_mime_type'
    filepath = pathlib.Path(__file__).parent / filename

    async def handler(request):
        return sender(filepath)

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    lastmod = 'Fri, 31 Dec 9999 23:59:59 GMT'

    resp = await client.get('/', headers={'If-Range': lastmod})
    assert 200 == resp.status
    assert resp.headers['Content-Length'] == '13'
    resp.close()


async def test_static_file_if_unmodified_since_invalid_date(aiohttp_client,
                                                            sender):
    filename = 'data.unknown_mime_type'
    filepath = pathlib.Path(__file__).parent / filename

    async def handler(request):
        return sender(filepath)

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    lastmod = 'not a valid HTTP-date'

    resp = await client.get('/', headers={'If-Unmodified-Since': lastmod})
    assert 200 == resp.status
    resp.close()


async def test_static_file_if_range_invalid_date(aiohttp_client,
                                                 sender):
    filename = 'data.unknown_mime_type'
    filepath = pathlib.Path(__file__).parent / filename

    async def handler(request):
        return sender(filepath)

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    lastmod = 'not a valid HTTP-date'

    resp = await client.get('/', headers={'If-Range': lastmod})
    assert 200 == resp.status
    resp.close()


async def test_static_file_compression(aiohttp_client, sender) -> None:
    filepath = pathlib.Path(__file__).parent / 'data.unknown_mime_type'

    async def handler(request):
        ret = sender(filepath)
        ret.enable_compression()
        return ret

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app, auto_decompress=False)

    resp = await client.get('/')
    assert resp.status == 200
    zcomp = zlib.compressobj(wbits=zlib.MAX_WBITS)
    expected_body = zcomp.compress(b'file content\n') + zcomp.flush()
    assert expected_body == await resp.read()
    assert 'application/octet-stream' == resp.headers['Content-Type']
    assert resp.headers.get('Content-Encoding') == 'deflate'
    await resp.release()


async def test_static_file_huge_cancel(aiohttp_client, tmp_path) -> None:
    file_path = tmp_path / 'huge_data.unknown_mime_type'

    # fill 100MB file
    with file_path.open('wb') as f:
        for i in range(1024*20):
            f.write((chr(i % 64 + 0x20) * 1024).encode())

    task = None

    async def handler(request):
        nonlocal task
        task = request.task
        # reduce send buffer size
        tr = request.transport
        sock = tr.get_extra_info('socket')
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)
        ret = web.FileResponse(file_path)
        return ret

    app = web.Application()

    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    resp = await client.get('/')
    assert resp.status == 200
    task.cancel()
    await asyncio.sleep(0)
    data = b''
    while True:
        try:
            data += await resp.content.read(1024)
        except aiohttp.ClientPayloadError:
            break
    assert len(data) < 1024 * 1024 * 20


async def test_static_file_huge_error(aiohttp_client, tmp_path) -> None:
    file_path = tmp_path / 'huge_data.unknown_mime_type'

    # fill 20MB file
    with file_path.open('wb') as f:
        f.seek(20*1024*1024)
        f.write(b'1')

    async def handler(request):
        # reduce send buffer size
        tr = request.transport
        sock = tr.get_extra_info('socket')
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)
        ret = web.FileResponse(file_path)
        return ret

    app = web.Application()

    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    resp = await client.get('/')
    assert resp.status == 200
    # raise an exception on server side
    resp.close()
