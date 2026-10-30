Fixed :meth:`StreamReader.readuntil() <aiohttp.StreamReader.readuntil>` raising
``AttributeError`` when reading an empty response body, including HEAD, 204, and
304 responses -- by :user:`sushu0`.
