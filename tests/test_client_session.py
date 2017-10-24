import asyncio
import contextlib
import gc
import re
import types
from http.cookies import SimpleCookie
from types import SimpleNamespace
from unittest import mock

import pytest
from multidict import CIMultiDict, MultiDict
from yarl import URL

import aiohttp
from aiohttp import hdrs, helpers, web
from aiohttp.client import ClientSession
from aiohttp.client_reqrep import ClientRequest
from aiohttp.connector import BaseConnector, TCPConnector


@pytest.fixture
def connector(loop):
    conn = BaseConnector(loop=loop)
    proto = mock.Mock()
    conn._conns['a'] = [(proto, 123)]
    return conn


@pytest.yield_fixture
def create_session(loop):
    session = None

    def maker(*args, **kwargs):
        nonlocal session
        session = ClientSession(*args, loop=loop, **kwargs)
        return session
    yield maker
    if session is not None:
        session.close()


@pytest.fixture
def session(create_session):
    return create_session()


@pytest.fixture
def params():
    return dict(
        headers={"Authorization": "Basic ..."},
        max_redirects=2,
        encoding="latin1",
        version=aiohttp.HttpVersion10,
        compress="deflate",
        chunked=True,
        expect100=True,
        read_until_eof=False)


def test_close_coro(create_session, loop):
    session = create_session()
    loop.run_until_complete(session.close())


async def test_close_deprecated(create_session):
    session = create_session()

    with pytest.warns(DeprecationWarning) as ctx:
        session.close()

    # Assert the warning points at us and not at _CoroGuard.
    assert ctx.list[0].filename == __file__


def test_init_headers_simple_dict(create_session):
    session = create_session(headers={"h1": "header1",
                                      "h2": "header2"})
    assert (sorted(session._default_headers.items()) ==
            ([("h1", "header1"), ("h2", "header2")]))


def test_init_headers_list_of_tuples(create_session):
    session = create_session(headers=[("h1", "header1"),
                                      ("h2", "header2"),
                                      ("h3", "header3")])
    assert (session._default_headers ==
            CIMultiDict([("h1", "header1"),
                         ("h2", "header2"),
                         ("h3", "header3")]))


def test_init_headers_MultiDict(create_session):
    session = create_session(headers=MultiDict([("h1", "header1"),
                                                ("h2", "header2"),
                                                ("h3", "header3")]))
    assert (session._default_headers ==
            CIMultiDict([("H1", "header1"),
                         ("H2", "header2"),
                         ("H3", "header3")]))


def test_init_headers_list_of_tuples_with_duplicates(create_session):
    session = create_session(headers=[("h1", "header11"),
                                      ("h2", "header21"),
                                      ("h1", "header12")])
    assert (session._default_headers ==
            CIMultiDict([("H1", "header11"),
                         ("H2", "header21"),
                         ("H1", "header12")]))


def test_init_cookies_with_simple_dict(create_session):
    session = create_session(cookies={"c1": "cookie1",
                                      "c2": "cookie2"})
    cookies = session.cookie_jar.filter_cookies()
    assert set(cookies) == {'c1', 'c2'}
    assert cookies['c1'].value == 'cookie1'
    assert cookies['c2'].value == 'cookie2'


def test_init_cookies_with_list_of_tuples(create_session):
    session = create_session(cookies=[("c1", "cookie1"),
                                      ("c2", "cookie2")])

    cookies = session.cookie_jar.filter_cookies()
    assert set(cookies) == {'c1', 'c2'}
    assert cookies['c1'].value == 'cookie1'
    assert cookies['c2'].value == 'cookie2'


def test_merge_headers(create_session):
        # Check incoming simple dict
    session = create_session(headers={"h1": "header1",
                                      "h2": "header2"})
    headers = session._prepare_headers({"h1": "h1"})

    assert isinstance(headers, CIMultiDict)
    assert headers == {"h1": "h1", "h2": "header2"}


def test_merge_headers_with_multi_dict(create_session):
    session = create_session(headers={"h1": "header1",
                                      "h2": "header2"})
    headers = session._prepare_headers(MultiDict([("h1", "h1")]))
    assert isinstance(headers, CIMultiDict)
    assert headers == {"h1": "h1", "h2": "header2"}


def test_merge_headers_with_list_of_tuples(create_session):
    session = create_session(headers={"h1": "header1",
                                      "h2": "header2"})
    headers = session._prepare_headers([("h1", "h1")])
    assert isinstance(headers, CIMultiDict)
    assert headers == {"h1": "h1", "h2": "header2"}


def test_merge_headers_with_list_of_tuples_duplicated_names(create_session):
    session = create_session(headers={"h1": "header1",
                                      "h2": "header2"})

    headers = session._prepare_headers([("h1", "v1"),
                                        ("h1", "v2")])

    assert isinstance(headers, CIMultiDict)
    assert list(sorted(headers.items())) == [("h1", "v1"),
                                             ("h1", "v2"),
                                             ("h2", "header2")]


def test_http_GET(session, params):
    with mock.patch("aiohttp.client.ClientSession._request") as patched:
        session.get("http://test.example.com",
                    params={"x": 1},
                    **params)
    assert patched.called, "`ClientSession._request` not called"
    assert list(patched.call_args) == [("GET", "http://test.example.com",),
                                       dict(
                                           params={"x": 1},
                                           allow_redirects=True,
                                           **params)]


def test_http_OPTIONS(session, params):
    with mock.patch("aiohttp.client.ClientSession._request") as patched:
        session.options("http://opt.example.com",
                        params={"x": 2},
                        **params)
    assert patched.called, "`ClientSession._request` not called"
    assert list(patched.call_args) == [("OPTIONS", "http://opt.example.com",),
                                       dict(
                                           params={"x": 2},
                                           allow_redirects=True,
                                           **params)]


def test_http_HEAD(session, params):
    with mock.patch("aiohttp.client.ClientSession._request") as patched:
        session.head("http://head.example.com",
                     params={"x": 2},
                     **params)
    assert patched.called, "`ClientSession._request` not called"
    assert list(patched.call_args) == [("HEAD", "http://head.example.com",),
                                       dict(
                                           params={"x": 2},
                                           allow_redirects=False,
                                           **params)]


def test_http_POST(session, params):
    with mock.patch("aiohttp.client.ClientSession._request") as patched:
        session.post("http://post.example.com",
                     params={"x": 2},
                     data="Some_data",
                     **params)
    assert patched.called, "`ClientSession._request` not called"
    assert list(patched.call_args) == [("POST", "http://post.example.com",),
                                       dict(
                                           params={"x": 2},
                                           data="Some_data",
                                           **params)]


def test_http_PUT(session, params):
    with mock.patch("aiohttp.client.ClientSession._request") as patched:
        session.put("http://put.example.com",
                    params={"x": 2},
                    data="Some_data",
                    **params)
    assert patched.called, "`ClientSession._request` not called"
    assert list(patched.call_args) == [("PUT", "http://put.example.com",),
                                       dict(
                                           params={"x": 2},
                                           data="Some_data",
                                           **params)]


def test_http_PATCH(session, params):
    with mock.patch("aiohttp.client.ClientSession._request") as patched:
        session.patch("http://patch.example.com",
                      params={"x": 2},
                      data="Some_data",
                      **params)
    assert patched.called, "`ClientSession._request` not called"
    assert list(patched.call_args) == [("PATCH", "http://patch.example.com",),
                                       dict(
                                           params={"x": 2},
                                           data="Some_data",
                                           **params)]


def test_http_DELETE(session, params):
    with mock.patch("aiohttp.client.ClientSession._request") as patched:
        session.delete("http://delete.example.com",
                       params={"x": 2},
                       **params)
    assert patched.called, "`ClientSession._request` not called"
    assert list(patched.call_args) == [("DELETE",
                                        "http://delete.example.com",),
                                       dict(
                                           params={"x": 2},
                                           **params)]


def test_close(create_session, connector):
    session = create_session(connector=connector)

    session.close()
    assert session.connector is None
    assert connector.closed


def test_closed(session):
    assert not session.closed
    session.close()
    assert session.closed


def test_connector(create_session, loop, mocker):
    connector = TCPConnector(loop=loop)
    mocker.spy(connector, 'close')
    session = create_session(connector=connector)
    assert session.connector is connector

    session.close()
    assert connector.close.called
    connector.close()


def test_create_connector(create_session, loop, mocker):
    session = create_session()
    connector = session.connector
    mocker.spy(session.connector, 'close')

    session.close()
    assert connector.close.called


def test_connector_loop(loop):
    with contextlib.ExitStack() as stack:
        another_loop = asyncio.new_event_loop()
        stack.enter_context(contextlib.closing(another_loop))
        connector = TCPConnector(loop=another_loop)
        stack.enter_context(contextlib.closing(connector))
        with pytest.raises(RuntimeError) as ctx:
            ClientSession(connector=connector, loop=loop)
        assert re.match("Session and connector has to use same event loop",
                        str(ctx.value))


def test_detach(session):
    conn = session.connector
    try:
        assert not conn.closed
        session.detach()
        assert session.connector is None
        assert session.closed
        assert not conn.closed
    finally:
        conn.close()


async def test_request_closed_session(session):
    session.close()
    with pytest.raises(RuntimeError):
        await session.request('get', '/')


def test_close_flag_for_closed_connector(session):
    conn = session.connector
    assert not session.closed
    conn.close()
    assert session.closed


def test_double_close(connector, create_session):
    session = create_session(connector=connector)

    session.close()
    assert session.connector is None
    session.close()
    assert session.closed
    assert connector.closed


def test_del(connector, loop):
    # N.B. don't use session fixture, it stores extra reference internally
    session = ClientSession(connector=connector, loop=loop)
    loop.set_exception_handler(lambda loop, ctx: None)

    with pytest.warns(ResourceWarning):
        del session
        gc.collect()


def test_context_manager(connector, loop):
    with pytest.warns(DeprecationWarning):
        with ClientSession(loop=loop, connector=connector) as session:
            pass

    assert session.closed


def test_borrow_connector_loop(connector, create_session, loop):
    session = ClientSession(connector=connector, loop=None)
    try:
        assert session._loop, loop
    finally:
        session.close()


async def test_reraise_os_error(create_session):
    err = OSError(1, "permission error")
    req = mock.Mock()
    req_factory = mock.Mock(return_value=req)
    req.send = mock.Mock(side_effect=err)
    session = create_session(request_class=req_factory)

    async def create_connection(req, trace_context=None):
        # return self.transport, self.protocol
        return mock.Mock()
    session._connector._create_connection = create_connection

    with pytest.raises(aiohttp.ClientOSError) as ctx:
        await session.request('get', 'http://example.com')
    e = ctx.value
    assert e.errno == err.errno
    assert e.strerror == err.strerror


async def test_request_ctx_manager_props(loop):
    await asyncio.sleep(0, loop=loop)  # to make it a task
    with pytest.warns(DeprecationWarning):
        with aiohttp.ClientSession(loop=loop) as client:
            ctx_mgr = client.get('http://example.com')

            next(ctx_mgr)
            assert isinstance(ctx_mgr.gi_frame, types.FrameType)
            assert not ctx_mgr.gi_running
            assert isinstance(ctx_mgr.gi_code, types.CodeType)
            await asyncio.sleep(0.1, loop=loop)


async def test_cookie_jar_usage(loop, test_client):
    req_url = None

    jar = mock.Mock()
    jar.filter_cookies.return_value = None

    async def handler(request):
        nonlocal req_url
        req_url = "http://%s/" % request.host

        resp = web.Response()
        resp.set_cookie("response", "resp_value")
        return resp

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    session = await test_client(
        app,
        cookies={"request": "req_value"},
        cookie_jar=jar
    )

    # Updating the cookie jar with initial user defined cookies
    jar.update_cookies.assert_called_with({"request": "req_value"})

    jar.update_cookies.reset_mock()
    resp = await session.get("/")
    await resp.release()

    # Filtering the cookie jar before sending the request,
    # getting the request URL as only parameter
    jar.filter_cookies.assert_called_with(URL(req_url))

    # Updating the cookie jar with the response cookies
    assert jar.update_cookies.called
    resp_cookies = jar.update_cookies.call_args[0][0]
    assert isinstance(resp_cookies, SimpleCookie)
    assert "response" in resp_cookies
    assert resp_cookies["response"].value == "resp_value"


def test_session_default_version(loop):
    session = aiohttp.ClientSession(loop=loop)
    assert session.version == aiohttp.HttpVersion11


def test_session_loop(loop):
    session = aiohttp.ClientSession(loop=loop)
    assert session.loop is loop
    session.close()


def test_proxy_str(session, params):
    with mock.patch("aiohttp.client.ClientSession._request") as patched:
        session.get("http://test.example.com",
                    proxy='http://proxy.com',
                    **params)
    assert patched.called, "`ClientSession._request` not called"
    assert list(patched.call_args) == [("GET", "http://test.example.com",),
                                       dict(
                                           allow_redirects=True,
                                           proxy='http://proxy.com',
                                           **params)]


def test_client_session_implicit_loop_warn():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    with pytest.warns(ResourceWarning):
        session = aiohttp.ClientSession()
        assert session._loop is loop
        session.close()

    asyncio.set_event_loop(None)
    loop.close()


@asyncio.coroutine
def test_request_tracing(loop):
    trace_context = {}
    on_request_start = mock.Mock()
    on_request_redirect = mock.Mock()
    on_request_end = mock.Mock()
    on_request_headers_sent = mock.Mock()
    on_request_content_sent = mock.Mock()

    session = aiohttp.ClientSession(loop=loop)
    session.on_request_start.append(on_request_start)
    session.on_request_redirect.append(on_request_redirect)
    session.on_request_end.append(on_request_end)
    session.on_request_headers_sent.append(on_request_headers_sent)
    session.on_request_content_sent.append(on_request_content_sent)

    resp = yield from session.get(
        'http://example.com',
        trace_context=trace_context
    )

    on_request_start.assert_called_once_with(
        trace_context,
        hdrs.METH_GET,
        "example.com",
        80,
        CIMultiDict()
    )

    on_request_end.assert_called_once_with(trace_context, resp)
    on_request_headers_sent.assert_called_once_with(trace_context)
    on_request_content_sent.assert_called_once_with(trace_context)
    assert not on_request_redirect.called


@asyncio.coroutine
def test_request_tracing_default_trace_context(loop):
    on_request_start = mock.Mock()

    session = aiohttp.ClientSession(loop=loop)
    session.on_request_start.append(on_request_start)

    yield from session.get('http://example.com')

    assert isinstance(on_request_start.call_args[0][0], SimpleNamespace)


@asyncio.coroutine
def test_request_tracing_exception(loop):
    on_request_end = mock.Mock()
    on_request_exception = mock.Mock()

    with mock.patch("aiohttp.client.TCPConnector.connect") as connect_patched:
        error = Exception()
        f = helpers.create_future(loop)
        f.set_exception(error)
        connect_patched.return_value = f

        session = aiohttp.ClientSession(loop=loop)
        session.on_request_end.append(on_request_end)
        session.on_request_exception.append(on_request_exception)

        try:
            yield from session.get('http://example.com')
        except Exception:
            pass

        on_request_exception.assert_called_once_with(mock.ANY, error)
        assert not on_request_end.called


@asyncio.coroutine
def test_request_tracing_interpose_headers(loop):

    class MyClientRequest(ClientRequest):
        headers = None

        def __init__(self, *args, **kwargs):
            super(MyClientRequest, self).__init__(*args, **kwargs)
            MyClientRequest.headers = self.headers

    @asyncio.coroutine
    def new_headers(trace_context, method, host, port, headers):
        headers['foo'] = 'bar'

    session = aiohttp.ClientSession(loop=loop, request_class=MyClientRequest)
    session.on_request_start.append(new_headers)

    yield from session.get('http://example.com')
    assert MyClientRequest.headers['foo'] == 'bar'


@asyncio.coroutine
def test_request_tracing_proxies_connector_signals(loop):
    connector = TCPConnector(loop=loop)
    session = aiohttp.ClientSession(connector=connector, loop=loop)
    assert id(session.on_request_queued_start) == id(connector.on_queued_start)
    assert id(session.on_request_queued_end) == id(connector.on_queued_end)
    assert id(session.on_request_createconn_start) ==\
        id(connector.on_createconn_start)
    assert id(session.on_request_createconn_end) ==\
        id(connector.on_createconn_end)
    assert id(session.on_request_reuseconn) == id(connector.on_reuseconn)
    assert id(session.on_request_resolvehost_start) ==\
        id(connector.on_resolvehost_start)
    assert id(session.on_request_resolvehost_end) ==\
        id(connector.on_resolvehost_end)
    assert id(session.on_request_dnscache_hit) ==\
        id(connector.on_dnscache_hit)
    assert id(session.on_request_dnscache_miss) ==\
        id(connector.on_dnscache_miss)


@asyncio.coroutine
def test_request_tracing_clientrequest_signals(loop):

    class MyClientRequest(ClientRequest):

        def __init__(self, *args, **kwargs):
            super(MyClientRequest, self).__init__(*args, **kwargs)
            MyClientRequest.on_headers_sent = self._on_headers_sent
            MyClientRequest.on_content_sent = self._on_content_sent
            MyClientRequest.on_headers_received = self._on_headers_received
            MyClientRequest.on_content_received = self._on_content_received
            MyClientRequest.trace_context = self._trace_context

    trace_context = mock.Mock()

    session = aiohttp.ClientSession(loop=loop, request_class=MyClientRequest)
    yield from session.get('http://example.com', trace_context=trace_context)
    assert MyClientRequest.on_headers_sent == session.on_request_headers_sent
    assert MyClientRequest.on_content_sent == session.on_request_content_sent
    assert MyClientRequest.on_headers_received ==\
        session.on_request_headers_received
    assert MyClientRequest.on_content_received ==\
        session.on_request_content_received
    assert MyClientRequest.trace_context == trace_context
