#!/usr/bin/env python3

import argparse
import asyncio

import aiohttp


async def curl(url: str) -> None:
    async with aiohttp.ClientSession() as session:
        async with session.request("GET", url) as response:
            print(repr(response))
            chunk = await response.content.read()
            print("Downloaded: %s" % len(chunk))


if __name__ == "__main__":
    ARGS = argparse.ArgumentParser(description="GET url example")
    ARGS.add_argument("url", nargs=1, metavar="URL", help="URL to download")
    ARGS.add_argument(
        "--iocp",
        default=False,
        action="store_true",
        help="Use ProactorEventLoop on Windows",
    )
    options = ARGS.parse_args()

    if options.iocp:
        from asyncio import events, windows_events

        el = windows_events.ProactorEventLoop()
        events.set_event_loop(el)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(curl(options.url[0]))
