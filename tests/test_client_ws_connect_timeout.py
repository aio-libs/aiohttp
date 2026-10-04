"""Regression: ws_connect must not leave the handshake on the session default.

#7220: `_ws_connect` called `self.request(...)` with no `timeout`, so `_request`
fell back to `self._timeout`. The websocket handshake is an ordinary request, so
it was already bounded by the session total -- but nothing at the call site
connected the session timeout to the handshake, and the caller had no way to see
the handshake was running under a fallback rather than under the timeout they
configured.

`ClientWSTimeout` carries only `ws_receive` / `ws_close`; it has no connect leg,
so it cannot express "bound the handshake". Threading the timeout through the
call makes that dependency explicit at the call site.

Mocking follows tests/test_client_ws.py: patch `ClientSession.request` on the
class, since the instance attribute is read-only.
"""

import asyncio
from unittest import mock

import pytest
from yarl import URL

import aiohttp
from aiohttp import hdrs
from aiohttp.client_ws import ClientWSTimeout


def _handshake_response(ws_key: str) -> mock.Mock:
    resp = mock.Mock()
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: "websocket",
        hdrs.CONNECTION: "upgrade",
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
    }
    resp._upgraded = True
    resp.connection.protocol.read_timeout = None
    return resp


def _resolved(req: mock.Mock, value: mock.Mock) -> mock.Mock:
    req.return_value = asyncio.get_running_loop().create_future()
    req.return_value.set_result(value)
    return req


async def test_ws_connect_threads_timeout_into_handshake_request(
    ws_key: str, key_data: bytes
) -> None:
    resp = _handshake_response(ws_key)
    with (
        mock.patch("aiohttp.client.os") as m_os,
        mock.patch("aiohttp.client.ClientSession.request") as m_req,
    ):
        m_os.urandom.return_value = key_data
        _resolved(m_req, resp)

        await aiohttp.ClientSession().ws_connect(
            URL("http://example.com"), timeout=ClientWSTimeout()
        )

        assert "timeout" in m_req.call_args.kwargs, (
            "ws_connect passed no timeout to the handshake request, so it fell "
            "back to the session default. kwargs="
            f"{sorted(m_req.call_args.kwargs)}"
        )


async def test_ws_connect_does_not_leak_ws_legs_into_handshake(
    ws_key: str, key_data: bytes
) -> None:
    """ws_receive / ws_close belong to the websocket, not to the handshake."""
    resp = _handshake_response(ws_key)
    ws_timeout = ClientWSTimeout(ws_receive=2.5, ws_close=1.5)
    with (
        mock.patch("aiohttp.client.os") as m_os,
        mock.patch("aiohttp.client.ClientSession.request") as m_req,
    ):
        m_os.urandom.return_value = key_data
        _resolved(m_req, resp)

        await aiohttp.ClientSession().ws_connect(
            URL("http://example.com"), timeout=ws_timeout
        )

        assert m_req.call_args.kwargs.get("timeout") is not ws_timeout