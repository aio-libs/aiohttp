Fixed a memory leak when the content of a released
:class:`~aiohttp.ClientResponse` was read, including a read that was
already waiting for data when :meth:`~aiohttp.ClientResponse.release`
or :meth:`~aiohttp.ClientResponse.close` was called, or when a request
body was read after the response had been sent. All such reads raised
one shared exception instance, whose traceback kept the frames of every
failed read alive -- by :user:`availov`.
