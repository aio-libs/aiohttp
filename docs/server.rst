.. _aiohttp-server:

Low-level HTTP Server
=====================

.. currentmodule:: aiohttp.server

.. note::

   This topic describes the low-level HTTP support. For high-level
   interface please take a look on :mod:`aiohttp.web`.

Run a basic server
------------------

Start implementing the basic server by inheriting the
:class:`ServerHttpProtocol` object. Your class should
implement the only method :meth:`ServerHttpProtocol.handle_request`
which must be a coroutine to handle requests asynchronously::

      from urllib.parse import urlparse, parse_qsl

      import aiohttp
      import aiohttp.server
      from aiohttp import MultiDict


      import asyncio

      class HttpRequestHandler(aiohttp.server.ServerHttpProtocol):

        async def handle_request(self, message, payload):
            response = aiohttp.Response(
                self.writer, 200, http_version=message.version
            )
            response.add_header('Content-Type', 'text/html')
            response.add_header('Content-Length', '18')
            response.send_headers()
            response.write(b'<h1>It Works!</h1>')
            await response.write_eof()

The next step is to create a loop and register your handler within a server.
:exc:`KeyboardInterrupt` exception handling is necessary so you can stop
your server with Ctrl+C at any time::

    if __name__ == '__main__':
        loop = asyncio.get_event_loop()
        f = loop.create_server(
            lambda: HttpRequestHandler(debug=True, keep_alive=75),
            '0.0.0.0', '8080')
        srv = loop.run_until_complete(f)
        print('serving on', srv.sockets[0].getsockname())
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            pass

Headers
-------

Data is passed to the handler in the ``message``, while request body is
passed in ``payload`` param.  HTTP headers are accessed through
``headers`` member of the message.  To check what the current method of
the request is use the ``method`` member of the ``message``. It should be one
of ``GET``, ``POST``, ``PUT`` or ``DELETE`` strings.

Handling GET params
-------------------

Currently aiohttp does not provide automatic parsing of incoming GET
params.  However aiohttp does provide a nice
:class:`MulitiDict` wrapper for already parsed params::

    from urllib.parse import urlparse, parse_qsl

    from aiohttp import MultiDict

    class HttpRequestHandler(aiohttp.server.ServerHttpProtocol):

        async def handle_request(self, message, payload):
            response = aiohttp.Response(
                self.writer, 200, http_version=message.version
            )
            get_params = MultiDict(parse_qsl(urlparse(message.path).query))
            print("Passed in GET", get_params)


Sending pre-compressed data
---------------------------

To include data in the response that is already compressed, do not call
`enable_compression`.  Instead, set the `Content-Encoding` header explicitly::

    @asyncio.coroutine
    def handler(request):
        headers = {'Content-Encoding': 'gzip'}
        deflated_data = zlib.compress(b'mydata')
        return web.Response(body=deflated_data, headers=headers)


Handling POST data
------------------

POST data is accessed through the ``payload.read()`` generator method.
If you have form data in the request body, you can parse it in the same way as
GET params::

    from urllib.parse import urlparse, parse_qsl

    from aiohttp import MultiDict

    class HttpRequestHandler(aiohttp.server.ServerHttpProtocol):

        async def handle_request(self, message, payload):
            response = aiohttp.Response(
                self.writer, 200, http_version=message.version
            )
            data = await payload.read()
            post_params = MultiDict(parse_qsl(data))
            print("Passed in POST", post_params)

SSL
---

To use asyncio's SSL support, just pass an SSLContext object to the
:meth:`asyncio.AbstractEventLoop.create_server` method of the loop::

    import ssl

    sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    sslcontext.load_cert_chain('sample.crt', 'sample.key')

    loop = asyncio.get_event_loop()
    loop.create_server(lambda: handler, "0.0.0.0", "8080", ssl=sslcontext)



Reference
---------

.. automodule:: aiohttp.server
    :members:
    :undoc-members:
    :show-inheritance:


.. disqus::
  :title: aiohttp low-level server
