.. _aiohttp-migration:

Migration to 2.x
================

Client
------

1. FormData().__call__ does not take an encoding arg anymore and its return value changes for an iterator or bytes to a Writer
2. FormData.is_multipart attribute is gone

3. chunked=True can not be combined with "Transfer-encoding: chunked" header

4. chunked=True can not be combined with "Content-Length" header

5. compress parameter can not be combined with "Content-Encoding" header

6. ClientPayloadError

7. ClientResponse.release

8. chunked


Web
---

1. GET, POST, url_obj gone
