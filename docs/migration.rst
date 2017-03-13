.. _aiohttp-migration:

Migration to 2.x
================

Client
------

0. Payload's

1. FormData().__call__ does not take an encoding arg anymore and its return value changes for an iterator or bytes to a Writer

2. FormData.is_multipart attribute is gone

3. chunked=True can not be combined with "Transfer-encoding: chunked" header

4. chunked=True can not be combined with "Content-Length" header

5. compress parameter can not be combined with "Content-Encoding" header

6. Client exceptions refactoring

7. ClientPayloadError - new exception for payload parsing errors

8. ClientResponse.release - no need to call

9. chunked - client itself responding for chunking, aiohttp just encodes transfer-encoding

10. generator is not supported as data provider

11. ClientResponse.url is `yarl.URL` (url_obj is deprecated)

12. BaseConnector.limit - meaning is different

13. encoding and version params are dropped for ClientSession.request()

14. BaseConnector.close - not a coroutine

15. ClientSession.close - not a coroutine

16. TCPConnector.conn_timeout - moved to ClientSession

17. aiohttp.MsgType dropped, use aiohttp.WSMsgType


Web
---

1. ServerHttpProtocol dropped, merged with RequestHandler, a lot of low-level api's are dropped

2. GET, POST gone

3. query instead of GET

4. WebResponse.chunked - developer responsible for actual chunking

5. Payload's supported as body

6. FileSender api is gone, replacement is FileResponse

7. `Application.add_subapp`

8. `Application.finished`
