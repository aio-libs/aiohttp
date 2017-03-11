.. _aiohttp-migration:

Migration to 2.x
================

Client
------

1. FormData().__call__ does not take an encoding arg anymore and its return value changes for an iterator or bytes to a Writer
2. FormData.is_multipart attribute is gone
