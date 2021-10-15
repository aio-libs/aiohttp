#!/usr/bin/env python3
import asyncio
import pathlib
import socket
import ssl
from typing import Any, Dict, List, Union

from aiohttp import ClientSession, TCPConnector, resolver, test_utils, web
from aiohttp.abc import AbstractResolver


class FakeResolver(AbstractResolver):
    _LOCAL_HOST = {0: "127.0.0.1", socket.AF_INET: "127.0.0.1", socket.AF_INET6: "::1"}

    def __init__(self, fakes: Dict[str, int]) -> None:
        """fakes -- dns -> port dict"""
        self._fakes = fakes
        self._resolver = resolver.DefaultResolver()

    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: Union[socket.AddressFamily, int] = socket.AF_INET,
    ) -> List[Dict[str, Any]]:
        fake_port = self._fakes.get(host)
        if fake_port is not None:
            return [
                {
                    "hostname": host,
                    "host": self._LOCAL_HOST[family],
                    "port": fake_port,
                    "family": family,
                    "proto": 0,
                    "flags": socket.AI_NUMERICHOST,
                }
            ]
        else:
            return await self._resolver.resolve(host, port, family)

    async def close(self) -> None:
        self._resolver.close()


class FakeFacebook:
    def __init__(self) -> None:
        self.app = web.Application()
        self.app.router.add_routes(
            [
                web.get("/v2.7/me", self.on_me),
                web.get("/v2.7/me/friends", self.on_my_friends),
            ]
        )
        self.runner = web.AppRunner(self.app)
        here = pathlib.Path(__file__)
        ssl_cert = here.parent / "server.crt"
        ssl_key = here.parent / "server.key"
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ssl_context.load_cert_chain(str(ssl_cert), str(ssl_key))

    async def start(self) -> Dict[str, int]:
        port = test_utils.unused_port()
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", port, ssl_context=self.ssl_context)
        await site.start()
        return {"graph.facebook.com": port}

    async def stop(self) -> None:
        await self.runner.cleanup()

    async def on_me(self, request: web.Request) -> web.StreamResponse:
        return web.json_response({"name": "John Doe", "id": "12345678901234567"})

    async def on_my_friends(self, request: web.Request) -> web.StreamResponse:
        return web.json_response(
            {
                "data": [
                    {"name": "Bill Doe", "id": "233242342342"},
                    {"name": "Mary Doe", "id": "2342342343222"},
                    {"name": "Alex Smith", "id": "234234234344"},
                ],
                "paging": {
                    "cursors": {
                        "before": "QVFIUjRtc2c5NEl0ajN",
                        "after": "QVFIUlpFQWM0TmVuaDRad0dt",
                    },
                    "next": (
                        "https://graph.facebook.com/v2.7/12345678901234567/"
                        "friends?access_token=EAACEdEose0cB"
                    ),
                },
                "summary": {"total_count": 3},
            }
        )


async def main() -> None:
    token = "ER34gsSGGS34XCBKd7u"

    fake_facebook = FakeFacebook()
    info = await fake_facebook.start()
    resolver = FakeResolver(info)
    connector = TCPConnector(resolver=resolver, ssl=False)

    async with ClientSession(connector=connector) as session:
        async with session.get(
            "https://graph.facebook.com/v2.7/me", params={"access_token": token}
        ) as resp:
            print(await resp.json())

        async with session.get(
            "https://graph.facebook.com/v2.7/me/friends", params={"access_token": token}
        ) as resp:
            print(await resp.json())

    await fake_facebook.stop()


loop = asyncio.get_event_loop()
loop.run_until_complete(main())
