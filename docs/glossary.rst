.. _aiohttp-glossary:


==========
 Glossary
==========

.. if you add new entries, keep the alphabetical sorting!

.. glossary::

   asyncio

      The library for writing single-threaded concurrent code using
      coroutines, multiplexing I/O access over sockets and other
      resources, running network clients and servers, and other
      related primitives.

      Reference implementation of :pep:`3156`

      https://pypi.python.org/pypi/asyncio/

   callable

      Any object that can be called. Use :func:`callable` to check
      that.

   chardet

       The Universal Character Encoding Detector

       https://pypi.python.org/pypi/chardet/

   cchardet

       cChardet is high speed universal character encoding detector -
       binding to charsetdetect.

       https://pypi.python.org/pypi/cchardet/

   keep-alive

       A technique for communicating between HTTP client and server
       when connection is not closed after sending response but keeped
       open for sending next request through the same socket.

       It makes communication faster by getting rid of connection
       establishment for every request.

   web-handler

       An endpoint that returns HTTP response.


.. disqus::
