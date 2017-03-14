.. _aiohttp-migration:

Migration to 2.x
================

Client
------

chunking
^^^^^^^^

aiohttp does not support custom chunking sizes. It is up to developer
to decide how to chunk data stream. If chunking is enabled aiohttp
encodes provided chunks into "Transfer-encoding: chunked" format.

Aiohttp does not enable chunked encoding automatically if *transfer-encoding*
header is supplied. *chunked* has to be set explicitly. If *chunked* encoding
is enabled *Transfer-encoding* and *content-length* headers are disallowed.

compression
^^^^^^^^^^^

Compression has to be enabled explicitly with *compress* parameter.
If compression is enabled *content-encoding* header is not allowed. Compression
also enables *chunked* transfer-encoding. Compression can not be combined
with *Content-Length* header.


Client Connector
^^^^^^^^^^^^^^^^

1. By default connector object manages total number of concurrent connections.
   In version 1.x connector uses per host rule. In 2.x version `limit` parameter
   defines how many concurrent connection connector can open.
   To enable 1.x behavior use `limit_per_host` parameter, which defines limit per host,
   by default it is disabled.
2.  BaseConnector.close is normal function as opposite to coroutine in version 1.x
3.  BaseConnector.conn_timeout was moved to ClientSession


ClientResponse.release
^^^^^^^^^^^^^^^^^^^^^^

Internal implementation was significantly redesigned. It is not required
to call `release` on response object. If client fully received payload,
then underlined connection returns back to pool automatically, otherwise it get closed.


Client exceptions
^^^^^^^^^^^^^^^^^

Exception hierarchy has been significantly modified. Aiohttp defines only
exceptions that covers connection handling and server response misbehave.
For developer specific mistakes, aiohttp uses python standard exceptions
like ValueError or TypeError.

Reading response content may raise ClientPayloadError exception. This exception
indicates payload encoding specific errors. For example bad compression or
malformed chunked encoding or not enough data that satisfy content-length header.


New hierarchy of exceptions:

* `ClientError` - Base class for all client specific exceptions

  - `ClientResponseError` - exceptions that could happen after we get response from server

    * `WSServerHandshakeError` - web socket server response error

      - `ClientHttpProxyError` - proxy response

  - `ClientConnectionError` - exceptions related to low-level connection problem

    * `ClientOSError` - subset of connection errors that are initiated by OSError exception

      - `ClientConnectorError` - connector related exceptions

        * `ClientProxyConnectionError` - proxy connection initialization error

          - `ServerConnectionError` - server connection related errors

        * `ServerDisconnectedError` - server disconnected

        * `ServerTimeoutError` - server operation timeout, (read timeout, etc)

        * `ServerFingerprintMismatch` - server fingerprint mismatch

  - `ClientPayloadError` - This exception can be raised only during reading response
    payload in following conditions. Bad compression or malformed chunked encoding or
    not enough data that satisfy content-length header.


Client payload (form-data)
^^^^^^^^^^^^^^^^^^^^^^^^^^

To unify form-data/payload handling new `Payload` system was introduced. It allows
customize handling of existing types and provide implementation for user-defined types.

1. FormData.__call__ does not take an encoding arg anymore
   and its return value changes from an iterator or bytes to a Payload instance.
   aiohttp provides payload adapters for some standard types like string, bytes,
   `io.IOBase`, `StreamReader`, `DataQueue`.

2. generator is not supported as data provider anymore, `streamer` can be used instead.
   For example you can upload data from file::

     @aiohttp.streamer
     def file_sender(writer, file_name=None):
           with open(file_name, 'rb') as f:
               chunk = f.read(2**16)
               while chunk:
                   yield from writer.write(chunk)
                   chunk = f.read(2**16)

     # Then you can use `file_sender` like this:

     async with session.post('http://httpbin.org/post',
       data=file_sender(file_name='hude_file')) as resp:
            print(await resp.text())


Various
^^^^^^^

1. `encoding` parameter is deprecated for `ClientSession.request()`.
   Payload encoding is controlled on payload level. It is possible to specify
   encoding for each payload instance.

2. `version` parameter dropped for `ClientSession.request()`
   client version can be specified with `ClientSession` constructor.

3. `aiohttp.MsgType` dropped, use `aiohttp.WSMsgType` instead.

4. `ClientResponse.url` is an instance of `yarl.URL` class (`url_obj` is deprecated)

5. `ClientSession.close()` is not a coroutine.



Server
------

ServerHttpProtocol and low-level details
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Internal implementation was significantly redesigned to provide
better performance and support http pipelining.
ServerHttpProtocol is dropped, implementation is merged with RequestHandler
a lot of low-level api's are dropped.


WebRequest and WebResponse
^^^^^^^^^^^^^^^^^^^^^^^^^^

1. `GET` and `POST` are dropped. Use `query` attribute instead of `GET`

2. Custom chunking size is not support `WebResponse.chunked` - developer is
   responsible for actual chunking.

3. Payloads are supported as body. So it is possible to use client response's content
   object as body parameter for `WebResponse`

4. `FileSender` api is dropped, it is replaced with more general `FileResponse` class::

     async def handle(request):
         return web.FileResponse('path-to-file.txt)

5. `Application.router.add_subapp` is dropped, use `Application.add_subapp` instead

6. `Application.finished` is dropped, use `Application.cleanup` instead


RequestPayloadError
^^^^^^^^^^^^^^^^^^^

Reading request's payload may raise `RequestPayloadError` exception. Behavior is similar
to `ClientPayloadError`.
