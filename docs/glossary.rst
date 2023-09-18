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

   Brotli

      Brotli is a generic-purpose lossless compression algorithm that
      compresses data using a combination of a modern variant
      of the LZ77 algorithm, Huffman coding and second order context modeling,
      with a compression ratio comparable to the best currently available
      general-purpose compression methods. It is similar in speed with deflate
      but offers more dense compression.

      The specification of the Brotli Compressed Data Format is defined :rfc:`7932`

      https://pypi.org/project/Brotli/

   brotlicffi

      An alternative implementation of :term:`Brotli` built using the CFFI
      library. This implementation supports PyPy correctly.

      https://pypi.org/project/brotlicffi/

   callable

      Any object that can be called. Use :func:`callable` to check
      that.

   gunicorn

       Gunicorn 'Green Unicorn' is a Python WSGI HTTP Server for
       UNIX.

       http://gunicorn.org/

   IDNA

       An Internationalized Domain Name in Applications (IDNA) is an
       industry standard for encoding Internet Domain Names that contain in
       whole or in part, in a language-specific script or alphabet,
       such as Arabic, Chinese, Cyrillic, Tamil, Hebrew or the Latin
       alphabet-based characters with diacritics or ligatures, such as
       French. These writing systems are encoded by computers in
       multi-byte Unicode. Internationalized domain names are stored
       in the Domain Name System as ASCII strings using Punycode
       transcription.

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

   percent-encoding

      A mechanism for encoding information in a Uniform Resource
      Locator (URL) if URL parts don't fit in safe characters space.

   requests

      Currently the most popular synchronous library to make
      HTTP requests in Python.

      https://requests.readthedocs.io

   requoting

      Applying :term:`percent-encoding` to non-safe symbols and decode
      percent encoded safe symbols back.

      According to :rfc:`3986` allowed path symbols are::

         allowed       = unreserved / pct-encoded / sub-delims
                         / ":" / "@" / "/"

         pct-encoded   = "%" HEXDIG HEXDIG

         unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"

         sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
                         / "*" / "+" / "," / ";" / "="

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


Environment Variables
=====================

.. envvar:: NETRC

   If set, HTTP Basic Auth will be read from the file pointed to by this environment variable,
   rather than from :file:`~/.netrc`.

   .. seealso::

      ``.netrc`` documentation: https://www.gnu.org/software/inetutils/manual/html_node/The-_002enetrc-file.html
