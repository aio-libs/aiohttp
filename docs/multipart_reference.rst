.. module:: aiohttp

Multipart reference
===================

.. class:: MultipartResponseWrapper

   Wrapper around the :class:`MultipartBodyReader` to take care about
   underlying connection and close it when it needs in.


   .. method:: at_eof()

      Returns ``True`` when all response data had been read.

      :rtype: bool

   .. comethod:: next()

      Emits next multipart reader object.
