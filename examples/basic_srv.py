#!/usr/bin/env python3
"""Basic HTTP server with minimal setup"""

import asyncio
from urllib.parse import parse_qsl, urlparse

import aiohttp
import aiohttp.server
from aiohttp import MultiDict


class HttpRequestHandler(aiohttp.server.ServerHttpProtocol):

    @asyncio.coroutine
    def handle_request(self, message, payload):
        response = aiohttp.Response(
            self.writer, 200, http_version=message.version)
        get_params = MultiDict(parse_qsl(urlparse(message.path).query))
        if message.method == 'POST':
            post_params = yield from payload.read()
        else:
            post_params = None
        content = "<h1>It Works!</h1>"
        if get_params:
            content += "<h2>Get params</h2><p>" + str(get_params) + "</p>"
        if post_params:
            content += "<h2>Post params</h2><p>" + str(post_params) + "</p>"
        bcontent = content.encode('utf-8')
        response.add_header('Content-Type', 'text/html; charset=UTF-8')
        response.add_header('Content-Length', str(len(bcontent)))
        response.send_headers()
        response.write(bcontent)
        yield from response.write_eof()


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    f = loop.create_server(
        lambda: HttpRequestHandler(debug=True, keep_alive=75),
        '0.0.0.0', 8080)
    srv = loop.run_until_complete(f)
    print('serving on', srv.sockets[0].getsockname())
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
