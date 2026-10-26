Fixed :class:`~aiohttp.web.FileResponse` to include ``Accept-Encoding`` in
``Vary`` for uncompressed and conditional responses, and to preserve existing
``Vary`` fields when serving precompressed files -- by :user:`umtong`.

This also prevents caches from reusing a ``404 Not Found`` response across
encodings when only a precompressed file exists.
