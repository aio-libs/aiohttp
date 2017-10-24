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

   .. comethod:: release()

      Releases the connection gracefully, reading all the content
      to the void.

