Added ``strategy`` parameter to :meth:`aiohttp.web.StreamResponse.enable_compression`
The value of this parameter is passed to the :func:`zlib.compressobj` function, allowing people
to use a more sufficient compression algorithm for their data served by :mod:`aiohttp.web`
-- by :user:`shootkin`
