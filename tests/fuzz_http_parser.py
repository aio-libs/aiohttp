#!/usr/bin/python3
import sys
import atheris

# aiohttp imports
import asyncio
import aiohttp
from aiohttp.base_protocol import BaseProtocol
from aiohttp import http_exceptions, streams

def TestOneInput(data):
    loop = asyncio.get_event_loop()
    pr = BaseProtocol(loop)
    h_p = aiohttp.http_parser.HttpRequestParser(pr, loop, 32768)
    try:
        h_p.feed_data(data)
    except aiohttp.http_exceptions.HttpProcessingError:
        return
    return

def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    loop = asyncio.get_event_loop()
    asyncio.set_event_loop(loop)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
