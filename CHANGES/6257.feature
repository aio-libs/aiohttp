Added ``strategy`` parameter to :py:method:`aiohttp.web.StreamResponse.enable_compression`
The value of this parameter is passed to the :py:function:`zlib.compressobj` function, allowing people
to use most sufficient compression algorithm for their data served by :py:module:`aiohttp.web`
-- by :user:`shootkin`
