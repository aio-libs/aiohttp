.. _server:

HTTP Server
===========

.. module:: aiohttp.client

Run a basic server
-------

Start implementing the basic server by inheriting 
aiohttp.server.ServerHttpProtocol object. Your class
should implement the only method handle_request which must
be a coroutine to handle requests asynchronously

 .. code-block:: python

      import aiohttp
      import aiohttp.server

      import asyncio

      class HttpRequestHandler(aiohttp.server.ServerHttpProtocol):

        @asyncio.coroutine
        def handle_request(self, message, payload):
            response = aiohttp.Response(
                self.writer, 200, http_version=message.version
            )
            response.add_header('Content-type', 'text/plain')
            response.send_headers()
            response.write(b'Hello world!')
            yield from response.write_eof()

All necessary data is passed to handle request in message and payload params.
Message contains HTTP request headers 'as is', payload is the body of the requests
wrapped in FlowControlStreamReader. To read the body of the request, you should
yield from payload's read method like so:

 .. code-block:: python

    msg = yield from payload.read()


Next step is creating a loop and registering your handler within a server. 
KeyboardInterrupt exception handling is necessary so you can stop 
your server with Ctrl+C at any time.

 .. code-block:: python

    if __name__ == '__main__':
        loop = asyncio.get_event_loop()
        f = loop.create_server(
            lambda: HttpRequestHandler(debug=True, keep_alive=75), '0.0.0.0', '8080'
        )
        srv = loop.run_until_complete(f)
        print('serving on', srv.sockets[0].getsockname())
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            pass
