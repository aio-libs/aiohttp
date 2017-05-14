Third-Party libraries
=====================


aiohttp is not the library for making HTTP requests and creating WEB
server only.

It is the grand basement for libraries built *on top* of aiohttp.

This page is a list of these tools.

Please feel free to add your open sourced library if it's not enlisted
yet by making Pull Request to https://github.com/aio-libs/aiohttp/

- Q. Why do you might want to include your awesome library into the list?

- A. Just because the list increases your library visibility. People
  will have an easy way to find it.


Officially supported
--------------------

This list contains libraries which are supported by *aio-libs* team
and located on https://github.com/aio-libs


aiohttp extensions
^^^^^^^^^^^^^^^^^^

- `aiohttp-session <https://github.com/aio-libs/aiohttp-session>`_
   provides sessions for :mod:`aiohttp.web`.

- `aiohttp-debugtoolbar <https://github.com/aio-libs/aiohttp-debugtoolbar>`_
   is a library for *debug toolbar* support for :mod:`aiohttp.web`.

- `aiohttp-security <https://github.com/aio-libs/aiohttp-security>`_
   auth and permissions for :mod:`aiohttp.web`.


Database drivers
^^^^^^^^^^^^^^^^

- `aiopg <https://github.com/aio-libs/aiopg>`_ PostgreSQL async driver.

- `aiomysql <https://github.com/aio-libs/aiomysql>`_ MySql async driver.

- `aioredis <https://github.com/aio-libs/aioredis>`_ Redis async driver.


Approved third-party libraries
------------------------------

The libraries are not part of ``aio-libs`` but they are proven to be very
well written and highly recommended for usage.

- `uvloop <https://github.com/MagicStack/uvloop>`_ Ultra fast
  implementation of asyncio event loop on top of ``libuv``.

  We are highly recommending to use it instead of standard ``asyncio``.

Database drivers
^^^^^^^^^^^^^^^^

- `asyncpg <https://github.com/MagicStack/asyncpg>`_ Another
  PostgreSQL async driver. It's much faster than ``aiopg`` but it is
  not drop-in replacement -- the API is different. Anyway please take
  a look on it -- the driver is really incredible fast.


Others
------

The list of libs which are exists but not enlisted in former categories.

They are may be perfect or not -- we don't know.

Please add your library reference here first and after some time
period ask to raise he status.

- `aiohttp-cache <https://github.com/cr0hn/aiohttp-cache>`_ A cache
  system for aiohttp server.
- `aiocache <https://github.com/argaen/aiocache>`_ Caching for asyncio
  with multiple backends (framework agnostic)
- `aiohttp-devtools <https://github.com/samuelcolvin/aiohttp-devtools>`_
  provides development tools for :mod:`aiohttp.web` applications

