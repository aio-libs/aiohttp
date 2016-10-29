.. _aiohttp-glossary:


==========
 Glossary
==========

.. if you add new entries, keep the alphabetical sorting!

.. glossary::
   :sorted:

   aiodns

      DNS resolver for asyncio.

      https://pypi.python.org/pypi/aiodns

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

   gunicorn

       Gunicorn 'Green Unicorn' is a Python WSGI HTTP Server for
       UNIX.

       http://gunicorn.org/

   keep-alive

       A technique for communicating between HTTP client and server
       when connection is not closed after sending response but kept
       open for sending next request through the same socket.

       It makes communication faster by getting rid of connection
       establishment for every request.

   nginx

      Nginx [engine x] is an HTTP and reverse proxy server, a mail
      proxy server, and a generic TCP/UDP proxy server.

      https://nginx.org/en/

   resource

      A concept reflects the HTTP **path**, every resource corresponds
      to *URI*.

      May have a unique name.

      Contains :term:`route`\'s for different HTTP methods.

   route

       A part of :term:`resource`, resource's *path* coupled with HTTP method.

   web-handler

       An endpoint that returns HTTP response.

   websocket

       A protocol providing full-duplex communication channels over a
       single TCP connection. The WebSocket protocol was standardized
       by the IETF as :rfc:`6455`

   yarl

      A library for operating with URL objects.

      https://pypi.python.org/pypi/yarl



.. disqus::
  :title: aiohttp glossary
