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

      from urllib.parse import urlparse, parse_qsl

      import aiohttp
      import aiohttp.server
      from aiohttp.multidict import MultiDict


      import asyncio

      class HttpRequestHandler(aiohttp.server.ServerHttpProtocol):

        @asyncio.coroutine
        def handle_request(self, message, payload):
            response = aiohttp.Response(
                self.writer, 200, http_version=message.version
            )
            response.add_header('Content-Type', 'text/html')
            response.add_header('Content-Length', '18')
            response.send_headers()
            response.write(b'<h1>It Works!</h1>')
            yield from response.write_eof()

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

Headers
-------
Request data is passed to handler in  the ``message`` , while request body is passed in ``payload`` param.
HTTP headers are accessed through ``headers`` member of the message.
To check what current request method is, use ``method`` member of the ``message``. It should be one of
``GET``, ``POST``, ``PUT`` or ``DELETE`` strings.

Handling GET params
-------

Currently aiohttp does not provide automatical parsing of incoming GET params. 
However aiohttp does provide a nice MulitiDict wrapper for already parsed params.


 .. code-block:: python

    from urllib.parse import urlparse, parse_qsl

    from aiohttp.multidict import MultiDict

    class HttpRequestHandler(aiohttp.server.ServerHttpProtocol):

        @asyncio.coroutine
        def handle_request(self, message, payload):
            response = aiohttp.Response(
                self.writer, 200, http_version=message.version
            )
            get_params = MultiDict(parse_qsl(urlparse(message.path).query))
            print("Passed in GET", get_params)


Handling POST data
-------

POST data is accessed through the ``payload.read()`` generator method. 
If you have form data in the request body, you can parse it the same way as
GET params.

 .. code-block:: python

    from urllib.parse import urlparse, parse_qsl

    from aiohttp.multidict import MultiDict

    class HttpRequestHandler(aiohttp.server.ServerHttpProtocol):

        @asyncio.coroutine
        def handle_request(self, message, payload):
            response = aiohttp.Response(
                self.writer, 200, http_version=message.version
            )
            data = yield from payload.read()
            post_params = MultiDict(parse_qsl(data))
            print("Passed in POST", post_params)


