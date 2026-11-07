Added :meth:`StreamReader.close() <aiohttp.StreamReader.close>` and ``close()`` on the
iterators returned by :meth:`~aiohttp.StreamReader.iter_chunked`,
:meth:`~aiohttp.StreamReader.iter_any` and :meth:`~aiohttp.StreamReader.iter_chunks`,
which close the client response the stream belongs to. Code that is only handed
``response.content`` or one of its iterators can now release the connection of a
partially read response
-- by :user:`zweckj`.
