.. _aiohttp-migration:

Migration to 2.x
================

Client
------

chunking
^^^^^^^^

aiohttp does not support custom chunking sizes. It is up to the developer
to decide how to chunk data streams. If chunking is enabled, aiohttp
encodes the provided chunks in the "Transfer-encoding: chunked" format.

aiohttp does not enable chunked encoding automatically even if a
*transfer-encoding* header is supplied: *chunked* has to be set
explicitly. If *chunked* is set, then the *Transfer-encoding* and
*content-length* headers are disallowed.

compression
^^^^^^^^^^^

Compression has to be enabled explicitly with the *compress* parameter.
If compression is enabled, adding a *content-encoding* header is not allowed.
Compression also enables the *chunked* transfer-encoding.
Compression can not be combined with a *Content-Length* header.


Client Connector
^^^^^^^^^^^^^^^^

1. By default a connector object manages a total number of concurrent
   connections.  This limit was a per host rule in version 1.x. In
   2.x, the `limit` parameter defines how many concurrent connection
   connector can open and a new `limit_per_host` parameter defines the
   limit per host. By default there is no per-host limit.
2. BaseConnector.close is now a normal function as opposed to
   coroutine in version 1.x
3. BaseConnector.conn_timeout was moved to ClientSession


ClientResponse.release
^^^^^^^^^^^^^^^^^^^^^^

Internal implementation was significantly redesigned. It is not
required to call `release` on the response object. When the client
fully receives the payload, the underlying connection automatically
returns back to pool. If the payload is not fully read, the connection
is closed


Client exceptions
^^^^^^^^^^^^^^^^^

Exception hierarchy has been significantly modified. aiohttp now defines only
exceptions that covers connection handling and server response misbehaviors.
For developer specific mistakes, aiohttp uses python standard exceptions
like ValueError or TypeError.

Reading a response content may raise a ClientPayloadError
exception. This exception indicates errors specific to the payload
encoding. Such as invalid compressed data, malformed chunked-encoded
chunks or not enough data that satisfy the content-length header.

All exceptions are moved from `aiohttp.errors` module to top level
`aiohttp` module.

New hierarchy of exceptions:

* `ClientError` - Base class for all client specific exceptions

  - `ClientResponseError` - exceptions that could happen after we get
    response from server

    * `WSServerHandshakeError` - web socket server response error

      - `ClientHttpProxyError` - proxy response

  - `ClientConnectionError` - exceptions related to low-level
    connection problems

    * `ClientOSError` - subset of connection errors that are initiated
      by an OSError exception

      - `ClientConnectorError` - connector related exceptions

        * `ClientProxyConnectionError` - proxy connection initialization error

          - `ServerConnectionError` - server connection related errors

        * `ServerDisconnectedError` - server disconnected

        * `ServerTimeoutError` - server operation timeout, (read timeout, etc)

        * `ServerFingerprintMismatch` - server fingerprint mismatch

  - `ClientPayloadError` - This exception can only be raised while
    reading the response payload if one of these errors occurs:
    invalid compression, malformed chunked encoding or not enough data
    that satisfy content-length header.


Client payload (form-data)
^^^^^^^^^^^^^^^^^^^^^^^^^^

To unify form-data/payload handling a new `Payload` system was
introduced. It handles customized handling of existing types and
provide implementation for user-defined types.

1. FormData.__call__ does not take an encoding arg anymore
   and its return value changes from an iterator or bytes to a Payload instance.
   aiohttp provides payload adapters for some standard types like `str`, `byte`,
   `io.IOBase`, `StreamReader` or `DataQueue`.

2. a generator is not supported as data provider anymore, `streamer`
   can be used instead.  For example, to upload data from file::

     @aiohttp.streamer
     def file_sender(writer, file_name=None):
           with open(file_name, 'rb') as f:
               chunk = f.read(2**16)
               while chunk:
                   yield from writer.write(chunk)
                   chunk = f.read(2**16)

     # Then you can use `file_sender` like this:

     async with session.post('http://httpbin.org/post',
                             data=file_sender(file_name='huge_file')) as resp:
            print(await resp.text())


Various
^^^^^^^

1. the `encoding` parameter is deprecated in `ClientSession.request()`.
   Payload encoding is controlled at the payload level.
   It is possible to specify an encoding for each payload instance.

2. the `version` parameter is removed in `ClientSession.request()`
   client version can be specified in the `ClientSession` constructor.

3. `aiohttp.MsgType` dropped, use `aiohttp.WSMsgType` instead.

4. `ClientResponse.url` is an instance of `yarl.URL` class (`url_obj`
   is deprecated)

5. `ClientResponse.raise_for_status()` raises
   :exc:`aiohttp.ClientResponseError` exception

6. `ClientResponse.json()` is strict about response's content type. if
   content type does not match, it raises
   :exc:`aiohttp.ClientResponseError` exception.  To disable content
   type check you can pass ``None`` as `content_type` parameter.




Server
------

ServerHttpProtocol and low-level details
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Internal implementation was significantly redesigned to provide
better performance and support HTTP pipelining.
ServerHttpProtocol is dropped, implementation is merged with RequestHandler
a lot of low-level api's are dropped.


Application
^^^^^^^^^^^

1. Constructor parameter `loop` is deprecated. Loop is get configured by application runner,
   `run_app` function for any of gunicorn workers.

2. `Application.router.add_subapp` is dropped, use `Application.add_subapp` instead

3. `Application.finished` is dropped, use `Application.cleanup` instead


WebRequest and WebResponse
^^^^^^^^^^^^^^^^^^^^^^^^^^

1. the `GET` and `POST` attributes no longer exist. Use the `query` attribute instead of `GET`

2. Custom chunking size is not support `WebResponse.chunked` - developer is
   responsible for actual chunking.

3. Payloads are supported as body. So it is possible to use client response's content
   object as body parameter for `WebResponse`

4. `FileSender` api is dropped, it is replaced with more general `FileResponse` class::

     async def handle(request):
         return web.FileResponse('path-to-file.txt')

5. `WebSocketResponse.protocol` is renamed to `WebSocketResponse.ws_protocol`.
   `WebSocketResponse.protocol` is instance of `RequestHandler` class.



RequestPayloadError
^^^^^^^^^^^^^^^^^^^

Reading request's payload may raise a `RequestPayloadError` exception. The behavior is similar
to `ClientPayloadError`.


WSGI
^^^^

*WSGI* support has been dropped, as well as gunicorn wsgi support. We still provide default and uvloop gunicorn workers for `web.Application`
