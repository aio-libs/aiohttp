Added ``strategy`` parameter to :py:method:`aiohttp.web.StreamResponse.enable_compression`
The value of this parameter goes to :py:function:`zlib.compressobj` function and allows people
to use most sufficient compression algorithm for their data served by :py:module:`aiohttp.web`
-- by :user:`shootkin`
