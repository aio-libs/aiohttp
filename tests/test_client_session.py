import asyncio
import contextlib
import gc
import re
import types
import http.cookies
from unittest import mock

import aiohttp
import pytest
from aiohttp.client import ClientSession
from aiohttp.connector import BaseConnector, TCPConnector
from aiohttp.multidict import CIMultiDict, MultiDict


@pytest.fixture
def connector(loop):
    conn = BaseConnector(loop=loop)
    transp = mock.Mock()
    conn._conns['a'] = [(transp, 'proto', 123)]
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


def test_init_headers_simple_dict(create_session):
    session = create_session(headers={"h1": "header1",
                                      "h2": "header2"})
    assert (sorted(session._default_headers.items()) ==
            ([("H1", "header1"), ("H2", "header2")]))


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
    assert set(session.cookies) == {'c1', 'c2'}
    assert session.cookies['c1'].value == 'cookie1'
    assert session.cookies['c2'].value == 'cookie2'


def test_init_cookies_with_list_of_tuples(create_session):
    session = create_session(cookies=[("c1", "cookie1"),
                                      ("c2", "cookie2")])

    assert set(session.cookies) == {'c1', 'c2'}
    assert session.cookies['c1'].value == 'cookie1'
    assert session.cookies['c2'].value == 'cookie2'


def test_merge_headers(create_session):
        # Check incoming simple dict
    session = create_session(headers={"h1": "header1",
                                      "h2": "header2"})
    headers = session._prepare_headers({"h1": "h1"})

    assert isinstance(headers, CIMultiDict)
    assert headers == CIMultiDict([("h2", "header2"),
                                   ("h1", "h1")])


def test_merge_headers_with_multi_dict(create_session):
    session = create_session(headers={"h1": "header1",
                                      "h2": "header2"})
    headers = session._prepare_headers(MultiDict([("h1", "h1")]))
    assert isinstance(headers, CIMultiDict)
    assert headers == CIMultiDict([("h2", "header2"),
                                   ("h1", "h1")])


def test_merge_headers_with_list_of_tuples(create_session):
    session = create_session(headers={"h1": "header1",
                                      "h2": "header2"})
    headers = session._prepare_headers([("h1", "h1")])
    assert isinstance(headers, CIMultiDict)
    assert headers == CIMultiDict([("h2", "header2"),
                                   ("h1", "h1")])


def test_merge_headers_with_list_of_tuples_duplicated_names(create_session):
    session = create_session(headers={"h1": "header1",
                                      "h2": "header2"})

    headers = session._prepare_headers([("h1", "v1"),
                                        ("h1", "v2")])

    assert isinstance(headers, CIMultiDict)
    assert headers == CIMultiDict([("H2", "header2"),
                                   ("H1", "v1"),
                                   ("H1", "v2")])


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


def test_connector(create_session, loop):
    connector = TCPConnector(loop=loop)
    session = create_session(connector=connector)
    assert session.connector is connector


def test_connector_loop(loop):
    with contextlib.ExitStack() as stack:
        another_loop = asyncio.new_event_loop()
        stack.enter_context(contextlib.closing(another_loop))
        connector = TCPConnector(loop=another_loop)
        stack.enter_context(contextlib.closing(connector))
        with pytest.raises(ValueError) as ctx:
            ClientSession(connector=connector, loop=loop)
        assert re.match("loop argument must agree with connector",
                        str(ctx.value))


def test_cookies_are_readonly(session):
    with pytest.raises(AttributeError):
        session.cookies = 123


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


@pytest.mark.run_loop
def test_request_closed_session(session):
    session.close()
    with pytest.raises(RuntimeError):
        yield from session.request('get', '/')


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


def test_del(connector, loop, warning):
    # N.B. don't use session fixture, it stores extra reference internally
    session = ClientSession(connector=connector, loop=loop)
    loop.set_exception_handler(lambda loop, ctx: None)

    with warning(ResourceWarning):
        del session
        gc.collect()


def test_context_manager(connector, loop):
    with ClientSession(loop=loop, connector=connector) as session:
        pass

    assert session.closed


def test_borrow_connector_loop(connector, create_session, loop):
    session = ClientSession(connector=connector, loop=None)
    try:
        assert session._loop, loop
    finally:
        session.close()


@pytest.mark.run_loop
def test_reraise_os_error(create_session):
    err = OSError(1, "permission error")
    req = mock.Mock()
    req_factory = mock.Mock(return_value=req)
    req.send = mock.Mock(side_effect=err)
    session = create_session(request_class=req_factory)

    @asyncio.coroutine
    def create_connection(req):
        # return self.transport, self.protocol
        return mock.Mock(), mock.Mock()
    session._connector._create_connection = create_connection

    with pytest.raises(aiohttp.ClientOSError) as ctx:
        yield from session.request('get', 'http://example.com')
    e = ctx.value
    assert e.errno == err.errno
    assert e.strerror == err.strerror


def test_request_ctx_manager_props(loop):
    with aiohttp.ClientSession(loop=loop) as client:
        ctx_mgr = client.get('http://example.com')

        next(ctx_mgr)
        assert isinstance(ctx_mgr.gi_frame, types.FrameType)
        assert not ctx_mgr.gi_running
        assert isinstance(ctx_mgr.gi_code, types.CodeType)


@pytest.fixture
def get_with_cookies(create_session):
    # Cookies to send from client to server as "Cookie" header
    cookies_to_send = (
        "shared-cookie=first; "
        "domain-cookie=second; Domain=example.com; "
        "subdomain1-cookie=third; Domain=test1.example.com; "
        "subdomain2-cookie=fourth; Domain=test2.example.com; "
        "dotted-domain-cookie=fifth; Domain=.example.com; "
        "different-domain-cookie=sixth; Domain=different.org; "
    )

    # Cookies received from the server as "Set-Cookie" header
    cookies_to_receive = (
        "unconstrained-cookie=first; "
        "domain-cookie=second; Domain=example.com; "
        "subdomain1-cookie=third; Domain=test1.example.com; "
        "subdomain2-cookie=fourth; Domain=test2.example.com; "
        "dotted-domain-cookie=fifth; Domain=.example.com; "
        "different-domain-cookie=sixth; Domain=different.org; "
    )

    req = mock.Mock()
    req_factory = mock.Mock(return_value=req)
    resp = mock.Mock()
    resp.cookies = http.cookies.SimpleCookie(cookies_to_receive)

    def send(writer, reader):
        # Clear the cookies between send and receive
        session.cookies.clear()
        # Reply with the requested URL
        resp.url = req_factory.call_args[0][1]
        return resp
    req.send = send

    @asyncio.coroutine
    def start(connection, read_until_eof=False):
        connection.close()
        return resp
    resp.start = start

    session = create_session(
        request_class=req_factory,
        cookies=http.cookies.SimpleCookie(cookies_to_send))

    @asyncio.coroutine
    def create_connection(req):
        # return self.transport, self.protocol
        return mock.Mock(), mock.Mock()
    session._connector._create_connection = create_connection

    return session, req_factory


@pytest.fixture
def send_cookie_request(get_with_cookies):
    session, req = get_with_cookies

    @asyncio.coroutine
    def maker(*args, **kwargs):
        yield from session.get(*args, **kwargs)

        cookies_sent = req.call_args[1]["cookies"]
        cookies_received = session.cookies
        return cookies_sent, cookies_received
    return maker


@pytest.mark.run_loop
def test_cookie_domain_filter_ip(send_cookie_request):
    cookies_sent, cookies_received = (
        yield from send_cookie_request("http://1.2.3.4/"))

    assert set(cookies_sent.keys()) == {
        "shared-cookie"
    }

    assert set(cookies_received.keys()) == set()


@pytest.mark.run_loop
def test_cookie_domain_filter_same_host(send_cookie_request):
    cookies_sent, cookies_received = (
        yield from send_cookie_request("http://example.com/"))

    assert set(cookies_sent.keys()) == {
        "shared-cookie",
        "domain-cookie",
        "dotted-domain-cookie"
    }

    assert set(cookies_received.keys()) == {
        "unconstrained-cookie",
        "domain-cookie",
        "dotted-domain-cookie"
    }


@pytest.mark.run_loop
def test_cookie_domain_filter_same_host_and_subdomain(send_cookie_request):
    cookies_sent, cookies_received = (
        yield from send_cookie_request("http://test1.example.com/"))

    assert set(cookies_sent.keys()) == {
        "shared-cookie",
        "domain-cookie",
        "subdomain1-cookie",
        "dotted-domain-cookie"
    }

    assert set(cookies_received.keys()) == {
        "unconstrained-cookie",
        "domain-cookie",
        "subdomain1-cookie",
        "dotted-domain-cookie"
    }


@pytest.mark.run_loop
def test_cookie_domain_filter_same_host_diff_subdomain(send_cookie_request):
    cookies_sent, cookies_received = (
        yield from send_cookie_request("http://different.example.com/"))

    assert set(cookies_sent.keys()) == {
        "shared-cookie",
        "domain-cookie",
        "dotted-domain-cookie"
    }

    assert set(cookies_received.keys()) == {
        "unconstrained-cookie",
        "domain-cookie",
        "dotted-domain-cookie"
    }


@pytest.mark.run_loop
def test_cookie_domain_filter_diff_host(send_cookie_request):
    cookies_sent, cookies_received = (
        yield from send_cookie_request("http://different.org/"))

    assert set(cookies_sent.keys()) == {
        "shared-cookie",
        "different-domain-cookie"
    }

    assert set(cookies_received.keys()) == {
        "unconstrained-cookie",
        "different-domain-cookie"
    }
