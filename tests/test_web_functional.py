import asyncio
import json
import pathlib
import zlib
from unittest import mock

import pytest
from multidict import MultiDict

from aiohttp import FormData, multipart, web
from aiohttp.protocol import HttpVersion, HttpVersion10, HttpVersion11
from aiohttp.streams import EOF_MARKER

try:
    import ssl
except:
    ssl = False


@asyncio.coroutine
def test_simple_get(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        body = yield from request.read()
        assert b'' == body
        return web.Response(body=b'OK')

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    resp = yield from client.get('/')
    assert 200 == resp.status
    txt = yield from resp.text()
    assert 'OK' == txt


@asyncio.coroutine
def test_handler_returns_not_response(loop, test_server, test_client):
    logger = mock.Mock()

    @asyncio.coroutine
    def handler(request):
        return 'abc'

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    server = yield from test_server(app, logger=logger)
    client = yield from test_client(server)

    resp = yield from client.get('/')
    assert 500 == resp.status

    logger.exception.assert_called_with("Error handling request")


@asyncio.coroutine
def test_head_returns_empty_body(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        return web.Response(body=b'test')

    app = web.Application(loop=loop)
    app.router.add_head('/', handler)
    client = yield from test_client(app)

    resp = yield from client.head('/', version=HttpVersion11)
    assert 200 == resp.status
    txt = yield from resp.text()
    assert '' == txt


@asyncio.coroutine
def test_post_form(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        data = yield from request.post()
        assert {'a': '1', 'b': '2'} == data
        return web.Response(body=b'OK')

    app = web.Application(loop=loop)
    app.router.add_post('/', handler)
    client = yield from test_client(app)

    resp = yield from client.post('/', data={'a': 1, 'b': 2})
    assert 200 == resp.status
    txt = yield from resp.text()
    assert 'OK' == txt


@asyncio.coroutine
def test_post_text(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        data = yield from request.text()
        assert 'русский' == data
        data2 = yield from request.text()
        assert data == data2
        return web.Response(text=data)

    app = web.Application(loop=loop)
    app.router.add_post('/', handler)
    client = yield from test_client(app)

    resp = yield from client.post('/', data='русский')
    assert 200 == resp.status
    txt = yield from resp.text()
    assert 'русский' == txt


@asyncio.coroutine
def test_post_json(loop, test_client):

    dct = {'key': 'текст'}

    @asyncio.coroutine
    def handler(request):
        data = yield from request.json()
        assert dct == data
        data2 = yield from request.json(loads=json.loads)
        assert data == data2
        with pytest.warns(DeprecationWarning):
            data3 = yield from request.json(loader=json.loads)
        assert data == data3
        resp = web.Response()
        resp.content_type = 'application/json'
        resp.body = json.dumps(data).encode('utf8')
        return resp

    app = web.Application(loop=loop)
    app.router.add_post('/', handler)
    client = yield from test_client(app)

    headers = {'Content-Type': 'application/json'}
    resp = yield from client.post('/', data=json.dumps(dct), headers=headers)
    assert 200 == resp.status
    data = yield from resp.json()
    assert dct == data


@asyncio.coroutine
def test_multipart(loop, test_client):
    with multipart.MultipartWriter() as writer:
        writer.append('test')
        writer.append_json({'passed': True})

    @asyncio.coroutine
    def handler(request):
        reader = yield from request.multipart()
        assert isinstance(reader, multipart.MultipartReader)

        part = yield from reader.next()
        assert isinstance(part, multipart.BodyPartReader)
        thing = yield from part.text()
        assert thing == 'test'

        part = yield from reader.next()
        assert isinstance(part, multipart.BodyPartReader)
        assert part.headers['Content-Type'] == 'application/json'
        thing = yield from part.json()
        assert thing == {'passed': True}

        resp = web.Response()
        resp.content_type = 'application/json'
        resp.body = b''
        return resp

    app = web.Application(loop=loop)
    app.router.add_post('/', handler)
    client = yield from test_client(app)

    resp = yield from client.post('/', data=writer, headers=writer.headers)
    assert 200 == resp.status
    yield from resp.release()


@asyncio.coroutine
def test_multipart_content_transfer_encoding(loop, test_client):
    """For issue #1168"""
    with multipart.MultipartWriter() as writer:
        writer.append(b'\x00' * 10,
                      headers={'Content-Transfer-Encoding': 'binary'})

    @asyncio.coroutine
    def handler(request):
        reader = yield from request.multipart()
        assert isinstance(reader, multipart.MultipartReader)

        part = yield from reader.next()
        assert isinstance(part, multipart.BodyPartReader)
        assert part.headers['Content-Transfer-Encoding'] == 'binary'
        thing = yield from part.read()
        assert thing == b'\x00' * 10

        resp = web.Response()
        resp.content_type = 'application/json'
        resp.body = b''
        return resp

    app = web.Application(loop=loop)
    app.router.add_post('/', handler)
    client = yield from test_client(app)

    resp = yield from client.post('/', data=writer, headers=writer.headers)
    assert 200 == resp.status
    yield from resp.release()


@asyncio.coroutine
def test_render_redirect(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        raise web.HTTPMovedPermanently(location='/path')

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    resp = yield from client.get('/', allow_redirects=False)
    assert 301 == resp.status
    txt = yield from resp.text()
    assert '301: Moved Permanently' == txt
    assert '/path' == resp.headers['location']


@asyncio.coroutine
def test_post_single_file(loop, test_client):

    here = pathlib.Path(__file__).parent

    def check_file(fs):
        fullname = here / fs.filename
        with fullname.open() as f:
            test_data = f.read().encode()
            data = fs.file.read()
            assert test_data == data

    @asyncio.coroutine
    def handler(request):
        with pytest.warns(DeprecationWarning):
            data = yield from request.post()
        assert ['sample.crt'] == list(data.keys())
        for fs in data.values():
            check_file(fs)
            fs.file.close()
        resp = web.Response(body=b'OK')
        return resp

    app = web.Application(loop=loop)
    app.router.add_post('/', handler)
    client = yield from test_client(app)

    fname = here / 'sample.crt'

    resp = yield from client.post('/', data=[fname.open()])
    assert 200 == resp.status


@asyncio.coroutine
def test_files_upload_with_same_key(loop, test_client):
    @asyncio.coroutine
    def handler(request):
        data = yield from request.post()
        files = data.getall('file')
        file_names = set()
        for _file in files:
            assert not _file.file.closed
            if _file.filename == 'test1.jpeg':
                assert _file.file.read() == b'binary data 1'
            if _file.filename == 'test2.jpeg':
                assert _file.file.read() == b'binary data 2'
            file_names.add(_file.filename)
        assert len(files) == 2
        assert file_names == {'test1.jpeg', 'test2.jpeg'}
        resp = web.Response(body=b'OK')
        return resp

    app = web.Application(loop=loop)
    app.router.add_post('/', handler)
    client = yield from test_client(app)

    data = FormData()
    data.add_field('file', b'binary data 1',
                   content_type='image/jpeg',
                   filename='test1.jpeg')
    data.add_field('file', b'binary data 2',
                   content_type='image/jpeg',
                   filename='test2.jpeg')
    resp = yield from client.post('/', data=data)
    assert 200 == resp.status


@asyncio.coroutine
def test_post_files(loop, test_client):

    here = pathlib.Path(__file__).parent

    def check_file(fs):
        fullname = here / fs.filename
        with fullname.open() as f:
            test_data = f.read().encode()
            data = fs.file.read()
            assert test_data == data

    @asyncio.coroutine
    def handler(request):
        data = yield from request.post()
        assert ['sample.crt', 'sample.key'] == list(data.keys())
        for fs in data.values():
            check_file(fs)
            fs.file.close()
        resp = web.Response(body=b'OK')
        return resp

    app = web.Application(loop=loop)
    app.router.add_post('/', handler)
    client = yield from test_client(app)

    with (here / 'sample.crt').open() as f1:
        with (here / 'sample.key').open() as f2:
            resp = yield from client.post('/', data=[f1, f2])
            assert 200 == resp.status


@asyncio.coroutine
def test_release_post_data(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        yield from request.release()
        chunk = yield from request.content.readany()
        assert chunk is EOF_MARKER
        return web.Response()

    app = web.Application(loop=loop)
    app.router.add_post('/', handler)
    client = yield from test_client(app)

    resp = yield from client.post('/', data='post text')
    assert 200 == resp.status


@asyncio.coroutine
def test_POST_DATA_with_content_transfer_encoding(loop, test_client):
    @asyncio.coroutine
    def handler(request):
        data = yield from request.post()
        assert b'123' == data['name']
        return web.Response()

    app = web.Application(loop=loop)
    app.router.add_post('/', handler)
    client = yield from test_client(app)

    form = FormData()
    form.add_field('name', b'123',
                   content_transfer_encoding='base64')

    resp = yield from client.post('/', data=form)
    assert 200 == resp.status


@asyncio.coroutine
def test_post_form_with_duplicate_keys(loop, test_client):
    @asyncio.coroutine
    def handler(request):
        data = yield from request.post()
        lst = list(data.items())
        assert [('a', '1'), ('a', '2')] == lst
        return web.Response()

    app = web.Application(loop=loop)
    app.router.add_post('/', handler)
    client = yield from test_client(app)

    resp = yield from client.post('/', data=MultiDict([('a', 1), ('a', 2)]))
    assert 200 == resp.status


def test_repr_for_application(loop):
    app = web.Application(loop=loop)
    assert "<Application>" == repr(app)


@asyncio.coroutine
def test_expect_default_handler_unknown(loop, test_client):
    """Test default Expect handler for unknown Expect value.

    A server that does not understand or is unable to comply with any of
    the expectation values in the Expect field of a request MUST respond
    with appropriate error status. The server MUST respond with a 417
    (Expectation Failed) status if any of the expectations cannot be met
    or, if there are other problems with the request, some other 4xx
    status.

    http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.20
    """
    @asyncio.coroutine
    def handler(request):
        yield from request.post()
        pytest.xfail('Handler should not proceed to this point in case of '
                     'unknown Expect header')

    app = web.Application(loop=loop)
    app.router.add_post('/', handler)
    client = yield from test_client(app)

    resp = yield from client.post('/', headers={'Expect': 'SPAM'})
    assert 417 == resp.status


@asyncio.coroutine
def test_100_continue(loop, test_client):
    @asyncio.coroutine
    def handler(request):
        data = yield from request.post()
        assert b'123' == data['name']
        return web.Response()

    form = FormData()
    form.add_field('name', b'123',
                   content_transfer_encoding='base64')

    app = web.Application(loop=loop)
    app.router.add_post('/', handler)
    client = yield from test_client(app)

    resp = yield from client.post('/', data=form, expect100=True)
    assert 200 == resp.status


@asyncio.coroutine
def test_100_continue_custom(loop, test_client):

    expect_received = False

    @asyncio.coroutine
    def handler(request):
        data = yield from request.post()
        assert b'123' == data['name']
        return web.Response()

    @asyncio.coroutine
    def expect_handler(request):
        nonlocal expect_received
        expect_received = True
        if request.version == HttpVersion11:
            request.transport.write(b"HTTP/1.1 100 Continue\r\n\r\n")

    form = FormData()
    form.add_field('name', b'123',
                   content_transfer_encoding='base64')

    app = web.Application(loop=loop)
    app.router.add_post('/', handler, expect_handler=expect_handler)
    client = yield from test_client(app)

    resp = yield from client.post('/', data=form, expect100=True)
    assert 200 == resp.status
    assert expect_received


@asyncio.coroutine
def test_100_continue_custom_response(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        data = yield from request.post()
        assert b'123', data['name']
        return web.Response()

    @asyncio.coroutine
    def expect_handler(request):
        if request.version == HttpVersion11:
            if auth_err:
                return web.HTTPForbidden()

            request.transport.write(b"HTTP/1.1 100 Continue\r\n\r\n")

    form = FormData()
    form.add_field('name', b'123',
                   content_transfer_encoding='base64')

    app = web.Application(loop=loop)
    app.router.add_post('/', handler, expect_handler=expect_handler)
    client = yield from test_client(app)

    auth_err = False
    resp = yield from client.post('/', data=form, expect100=True)
    assert 200 == resp.status

    auth_err = True
    resp = yield from client.post('/', data=form, expect100=True)
    assert 403 == resp.status


@asyncio.coroutine
def test_100_continue_for_not_found(loop, test_client):

    app = web.Application(loop=loop)
    client = yield from test_client(app)

    resp = yield from client.post('/not_found', data='data', expect100=True)
    assert 404 == resp.status


@asyncio.coroutine
def test_100_continue_for_not_allowed(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        return web.Response()

    app = web.Application(loop=loop)
    app.router.add_post('/', handler)
    client = yield from test_client(app)

    resp = yield from client.get('/', expect100=True)
    assert 405 == resp.status


@asyncio.coroutine
def test_http11_keep_alive_default(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        return web.Response()

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    resp = yield from client.get('/', version=HttpVersion11)
    assert 200 == resp.status
    assert resp.version == HttpVersion11
    assert 'Connection' not in resp.headers


@asyncio.coroutine
def test_http10_keep_alive_default(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        return web.Response()

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    resp = yield from client.get('/', version=HttpVersion10)
    assert 200 == resp.status
    assert resp.version == HttpVersion10
    assert resp.headers['Connection'] == 'keep-alive'


@asyncio.coroutine
def test_http09_keep_alive_default(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        yield from request.read()
        return web.Response()

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    headers = {'Connection': 'keep-alive'}  # should be ignored
    resp = yield from client.get('/', version=HttpVersion(0, 9),
                                 headers=headers)
    assert 200 == resp.status
    assert resp.version == HttpVersion(0, 9)
    assert 'Connection' not in resp.headers


@asyncio.coroutine
def test_http10_keep_alive_with_headers_close(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        yield from request.read()
        return web.Response(body=b'OK')

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    headers = {'Connection': 'close'}
    resp = yield from client.get('/', version=HttpVersion10,
                                 headers=headers)
    assert 200 == resp.status
    assert resp.version == HttpVersion10
    assert 'Connection' not in resp.headers


@asyncio.coroutine
def test_http10_keep_alive_with_headers(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        yield from request.read()
        return web.Response(body=b'OK')

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    headers = {'Connection': 'keep-alive'}
    resp = yield from client.get('/', version=HttpVersion10,
                                 headers=headers)
    assert 200 == resp.status
    assert resp.version == HttpVersion10
    assert resp.headers['Connection'] == 'keep-alive'


@asyncio.coroutine
def test_upload_file(loop, test_client):

    here = pathlib.Path(__file__).parent
    fname = here / 'software_development_in_picture.jpg'
    with fname.open('rb') as f:
        data = f.read()

    @asyncio.coroutine
    def handler(request):
        form = yield from request.post()
        raw_data = form['file'].file.read()
        assert data == raw_data
        return web.Response()

    app = web.Application(loop=loop)
    app.router.add_post('/', handler)
    client = yield from test_client(app)

    resp = yield from client.post('/', data={'file': data})
    assert 200 == resp.status


@asyncio.coroutine
def test_upload_file_object(loop, test_client):
    here = pathlib.Path(__file__).parent
    fname = here / 'software_development_in_picture.jpg'
    with fname.open('rb') as f:
        data = f.read()

    @asyncio.coroutine
    def handler(request):
        form = yield from request.post()
        raw_data = form['file'].file.read()
        assert data == raw_data
        return web.Response()

    app = web.Application(loop=loop)
    app.router.add_post('/', handler)
    client = yield from test_client(app)

    with fname.open('rb') as f:
        resp = yield from client.post('/', data={'file': f})
        assert 200 == resp.status


@asyncio.coroutine
def test_empty_content_for_query_without_body(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        assert not request.has_body
        return web.Response()

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    resp = yield from client.get('/')
    assert 200 == resp.status


@asyncio.coroutine
def test_empty_content_for_query_with_body(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        assert request.has_body
        body = yield from request.read()
        return web.Response(body=body)

    app = web.Application(loop=loop)
    app.router.add_post('/', handler)
    client = yield from test_client(app)

    resp = yield from client.post('/', data=b'data')
    assert 200 == resp.status


@asyncio.coroutine
def test_get_with_empty_arg(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        assert 'arg' in request.GET
        assert '' == request.GET['arg']
        return web.Response()

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    resp = yield from client.get('/?arg')
    assert 200 == resp.status


@asyncio.coroutine
def test_large_header(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        return web.Response()

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    headers = {'Long-Header': 'ab' * 8129}
    resp = yield from client.get('/', headers=headers)
    assert 400 == resp.status


@asyncio.coroutine
def test_large_header_allowed(loop, test_client, test_server):

    @asyncio.coroutine
    def handler(request):
        return web.Response()

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    server = yield from test_server(app, max_field_size=81920)
    client = yield from test_client(server)

    headers = {'Long-Header': 'ab' * 8129}
    resp = yield from client.get('/', headers=headers)
    assert 200 == resp.status


@asyncio.coroutine
def test_get_with_empty_arg_with_equal(loop, test_client):
    @asyncio.coroutine
    def handler(request):
        assert 'arg' in request.GET
        assert '' == request.GET['arg']
        return web.Response()

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    resp = yield from client.get('/?arg=')
    assert 200 == resp.status


@pytest.mark.xfail  # and had never worked
@asyncio.coroutine
def test_response_with_precompressed_body(loop, test_client):
    @asyncio.coroutine
    def handler(request):
        headers = {'Content-Encoding': 'gzip'}
        deflated_data = zlib.compress(b'mydata')
        return web.Response(body=deflated_data, headers=headers)

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    resp = yield from client.get('/')
    assert 200 == resp.status
    data = yield from resp.read()
    assert b'mydata' == data
    assert resp.headers.get('Content-Encoding') == 'deflate'


@asyncio.coroutine
def test_stream_response_multiple_chunks(loop, test_client):
    @asyncio.coroutine
    def handler(request):
        resp = web.StreamResponse()
        resp.enable_chunked_encoding()
        yield from resp.prepare(request)
        resp.write(b'x')
        resp.write(b'y')
        resp.write(b'z')
        return resp

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    resp = yield from client.get('/')
    assert 200 == resp.status
    data = yield from resp.read()
    assert b'xyz' == data


@asyncio.coroutine
def test_start_without_routes(loop, test_client):

    app = web.Application(loop=loop)
    client = yield from test_client(app)

    resp = yield from client.get('/')
    assert 404 == resp.status


@asyncio.coroutine
def test_requests_count(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        return web.Response()

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(app)
    assert client.handler.requests_count == 0

    resp = yield from client.get('/')
    assert 200 == resp.status
    assert client.handler.requests_count == 1

    resp = yield from client.get('/')
    assert 200 == resp.status
    assert client.handler.requests_count == 2

    resp = yield from client.get('/')
    assert 200 == resp.status
    assert client.handler.requests_count == 3
