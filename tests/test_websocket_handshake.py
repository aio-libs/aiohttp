# Tests for http/websocket.py

import base64
import os
from typing import List, Tuple

import pytest

from aiohttp import web
from aiohttp.test_utils import make_mocked_request


def gen_ws_headers(
    protocols: str = "",
    compress: int = 0,
    extension_text: str = "",
    server_notakeover: bool = False,
    client_notakeover: bool = False,
) -> Tuple[List[Tuple[str, str]], str]:
    key = base64.b64encode(os.urandom(16)).decode()
    hdrs = [
        ("Upgrade", "websocket"),
        ("Connection", "upgrade"),
        ("Sec-Websocket-Version", "13"),
        ("Sec-Websocket-Key", key),
    ]
    if protocols:
        hdrs += [("Sec-Websocket-Protocol", protocols)]
    if compress:
        params = "permessage-deflate"
        if compress < 15:
            params += "; server_max_window_bits=" + str(compress)
        if server_notakeover:
            params += "; server_no_context_takeover"
        if client_notakeover:
            params += "; client_no_context_takeover"
        if extension_text:
            params += "; " + extension_text
        hdrs += [("Sec-Websocket-Extensions", params)]
    return hdrs, key


async def test_not_get() -> None:
    ws = web.WebSocketResponse()
    req = make_mocked_request("POST", "/")
    with pytest.raises(web.HTTPMethodNotAllowed):
        await ws.prepare(req)


async def test_inappropriate_method() -> None:
    ws = web.WebSocketResponse()
    req = make_mocked_request(
        "HEAD",
        "/",
        headers=[
            ("Upgrade", "websocket"),
            # expect refusal; not a 1xx status (or two)
            ("Expect", "100-continue"),
            ("Expect", "100-continue"),
        ],
    )
    with pytest.raises(web.HTTPMethodNotAllowed) as ctx:
        await ws.prepare(req)
    assert ctx.value.method == "HEAD"
    assert ctx.value.allowed_methods == {"GET"}
    assert ctx.value.status == 405


async def test_no_upgrade() -> None:
    ws = web.WebSocketResponse()
    req = make_mocked_request("GET", "/")
    with pytest.raises(web.HTTPBadRequest) as ctx:
        await ws.prepare(req)
    assert ctx.value.text and "UPGRADE" in ctx.value.text
    assert ctx.value.status == 400


async def test_no_connection() -> None:
    ws = web.WebSocketResponse()
    req = make_mocked_request(
        "GET", "/", headers={"Upgrade": "websocket", "Connection": "keep-alive"}
    )
    with pytest.raises(web.HTTPBadRequest) as ctx:
        await ws.prepare(req)
    assert ctx.value.text and "CONNECTION" in ctx.value.text
    assert ctx.value.status == 400


async def test_protocol_version_unset() -> None:
    ws = web.WebSocketResponse()
    req = make_mocked_request(
        "GET", "/", headers={"Upgrade": "websocket", "Connection": "upgrade"}
    )
    with pytest.raises(web.HTTPBadRequest) as ctx:
        await ws.prepare(req)
    assert ctx.value.text and "version" in ctx.value.text
    assert ctx.value.status == 400


async def test_protocol_version_not_supported() -> None:
    ws = web.WebSocketResponse()
    req = make_mocked_request(
        "GET",
        "/",
        headers={
            "Upgrade": "websocket",
            "Connection": "upgrade",
            "Sec-Websocket-Version": "1",
        },
    )
    with pytest.raises(web.HTTPBadRequest) as ctx:
        await ws.prepare(req)
    assert ctx.value.text and "version" in ctx.value.text
    assert ctx.value.status == 400


async def test_protocol_key_not_present() -> None:
    ws = web.WebSocketResponse()
    req = make_mocked_request(
        "GET",
        "/",
        headers={
            "Upgrade": "websocket",
            "Connection": "upgrade",
            "Sec-Websocket-Version": "13",
        },
    )
    with pytest.raises(web.HTTPBadRequest) as ctx:
        await ws.prepare(req)
    assert ctx.value.text and "Handshake" in ctx.value.text
    assert ctx.value.status == 400


async def test_protocol_key_invalid() -> None:
    ws = web.WebSocketResponse()
    req = make_mocked_request(
        "GET",
        "/",
        headers={
            "Upgrade": "websocket",
            "Connection": "upgrade",
            "Sec-Websocket-Version": "13",
            "Sec-Websocket-Key": "123",
        },
    )
    with pytest.raises(web.HTTPBadRequest) as ctx:
        await ws.prepare(req)
    assert ctx.value.text and "Handshake" in ctx.value.text
    assert ctx.value.status == 400


async def test_protocol_key_bad_size() -> None:
    ws = web.WebSocketResponse()
    sec_key = base64.b64encode(os.urandom(2))
    val = sec_key.decode()
    req = make_mocked_request(
        "GET",
        "/",
        headers={
            "Upgrade": "websocket",
            "Connection": "upgrade",
            "Sec-Websocket-Version": "13",
            "Sec-Websocket-Key": val,
        },
    )
    with pytest.raises(web.HTTPBadRequest) as ctx:
        await ws.prepare(req)
    assert ctx.value.text and "Handshake" in ctx.value.text
    assert ctx.value.status == 400


async def test_handshake_ok() -> None:
    hdrs, sec_key = gen_ws_headers()
    ws = web.WebSocketResponse()
    req = make_mocked_request("GET", "/", headers=hdrs)

    await ws.prepare(req)

    assert ws.ws_protocol is None


async def test_handshake_protocol() -> None:
    # Tests if one protocol is returned by handshake
    proto = "chat"

    ws = web.WebSocketResponse(protocols={"chat"})
    req = make_mocked_request("GET", "/", headers=gen_ws_headers(proto)[0])

    await ws.prepare(req)

    assert ws.ws_protocol == proto


async def test_handshake_protocol_agreement() -> None:
    # Tests if the right protocol is selected given multiple
    best_proto = "worse_proto"
    wanted_protos = ["best", "chat", "worse_proto"]
    server_protos = "worse_proto,chat"

    ws = web.WebSocketResponse(protocols=wanted_protos)
    req = make_mocked_request("GET", "/", headers=gen_ws_headers(server_protos)[0])

    await ws.prepare(req)

    assert ws.ws_protocol == best_proto


async def test_handshake_protocol_unsupported(caplog: pytest.LogCaptureFixture) -> None:
    # Tests if a protocol mismatch handshake warns and returns None
    proto = "chat"
    req = make_mocked_request("GET", "/", headers=gen_ws_headers("test")[0])

    ws = web.WebSocketResponse(protocols=[proto])
    await ws.prepare(req)

    assert (
        caplog.records[-1].msg
        == "%s: Client protocols %r don’t overlap server-known ones %r"
    )
    assert ws.ws_protocol is None


async def test_handshake_compress() -> None:
    hdrs, sec_key = gen_ws_headers(compress=15)

    req = make_mocked_request("GET", "/", headers=hdrs)

    ws = web.WebSocketResponse()
    await ws.prepare(req)

    assert ws.compress == 15


def test_handshake_compress_server_notakeover() -> None:
    hdrs, sec_key = gen_ws_headers(compress=15, server_notakeover=True)

    req = make_mocked_request("GET", "/", headers=hdrs)

    ws = web.WebSocketResponse()
    headers, _, compress, notakeover = ws._handshake(req)

    assert compress == 15
    assert notakeover is True
    assert "Sec-Websocket-Extensions" in headers
    assert headers["Sec-Websocket-Extensions"] == (
        "permessage-deflate; server_no_context_takeover"
    )


def test_handshake_compress_client_notakeover() -> None:
    hdrs, sec_key = gen_ws_headers(compress=15, client_notakeover=True)

    req = make_mocked_request("GET", "/", headers=hdrs)

    ws = web.WebSocketResponse()
    headers, _, compress, notakeover = ws._handshake(req)

    assert "Sec-Websocket-Extensions" in headers
    assert headers["Sec-Websocket-Extensions"] == ("permessage-deflate"), hdrs

    assert compress == 15


def test_handshake_compress_wbits() -> None:
    hdrs, sec_key = gen_ws_headers(compress=9)

    req = make_mocked_request("GET", "/", headers=hdrs)

    ws = web.WebSocketResponse()
    headers, _, compress, notakeover = ws._handshake(req)

    assert "Sec-Websocket-Extensions" in headers
    assert headers["Sec-Websocket-Extensions"] == (
        "permessage-deflate; server_max_window_bits=9"
    )
    assert compress == 9


def test_handshake_compress_wbits_error() -> None:
    hdrs, sec_key = gen_ws_headers(compress=6)

    req = make_mocked_request("GET", "/", headers=hdrs)

    ws = web.WebSocketResponse()
    headers, _, compress, notakeover = ws._handshake(req)

    assert "Sec-Websocket-Extensions" not in headers
    assert compress == 0


def test_handshake_compress_bad_ext() -> None:
    hdrs, sec_key = gen_ws_headers(compress=15, extension_text="bad")

    req = make_mocked_request("GET", "/", headers=hdrs)

    ws = web.WebSocketResponse()
    headers, _, compress, notakeover = ws._handshake(req)

    assert "Sec-Websocket-Extensions" not in headers
    assert compress == 0


def test_handshake_compress_multi_ext_bad() -> None:
    hdrs, sec_key = gen_ws_headers(
        compress=15, extension_text="bad, permessage-deflate"
    )

    req = make_mocked_request("GET", "/", headers=hdrs)

    ws = web.WebSocketResponse()
    headers, _, compress, notakeover = ws._handshake(req)

    assert "Sec-Websocket-Extensions" in headers
    assert headers["Sec-Websocket-Extensions"] == "permessage-deflate"


def test_handshake_compress_multi_ext_wbits() -> None:
    hdrs, sec_key = gen_ws_headers(compress=6, extension_text=", permessage-deflate")

    req = make_mocked_request("GET", "/", headers=hdrs)

    ws = web.WebSocketResponse()
    headers, _, compress, notakeover = ws._handshake(req)

    assert "Sec-Websocket-Extensions" in headers
    assert headers["Sec-Websocket-Extensions"] == "permessage-deflate"
    assert compress == 15


def test_handshake_no_transfer_encoding() -> None:
    hdrs, sec_key = gen_ws_headers()
    req = make_mocked_request("GET", "/", headers=hdrs)

    ws = web.WebSocketResponse()
    headers, _, compress, notakeover = ws._handshake(req)

    assert "Transfer-Encoding" not in headers
