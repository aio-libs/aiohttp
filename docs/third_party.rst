.. _aiohttp-3rd-party:

Third-Party libraries
=====================


aiohttp is not the library for making HTTP requests and creating WEB
server only.

It is the grand basement for libraries built *on top* of aiohttp.

This page is a list of these tools.

Please feel free to add your open sourced library if it's not enlisted
yet by making Pull Request to https://github.com/aio-libs/aiohttp/

* Why do you might want to include your awesome library into the list?

* Just because the list increases your library visibility. People
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

- `aiohttp-devtools <https://github.com/aio-libs/aiohttp-devtools>`_
  provides development tools for :mod:`aiohttp.web` applications.

- `aiohttp-cors <https://github.com/aio-libs/aiohttp-cors>`_ CORS
  support for aiohttp.

- `aiohttp-sse <https://github.com/aio-libs/aiohttp-sse>`_ Server-sent
  events support for aiohttp.

- `pytest-aiohttp <https://github.com/aio-libs/pytest-aiohttp>`_
  pytest plugin for aiohttp support.

- `aiohttp-mako <https://github.com/aio-libs/aiohttp-mako>`_ Mako
  template renderer for aiohttp.web.

- `aiohttp-jinja2 <https://github.com/aio-libs/aiohttp-jinja2>`_ Jinja2
  template renderer for aiohttp.web.

Database drivers
^^^^^^^^^^^^^^^^

- `aiopg <https://github.com/aio-libs/aiopg>`_ PostgreSQL async driver.

- `aiomysql <https://github.com/aio-libs/aiomysql>`_ MySql async driver.

- `aioredis <https://github.com/aio-libs/aioredis>`_ Redis async driver.

Other tools
^^^^^^^^^^^

- `aiodocker <https://github.com/aio-libs/aiodocker>`_ Python Docker
  API client based on asyncio and aiohttp.

- `aiobotocore <https://github.com/aio-libs/aiobotocore>`_ asyncio
  support for botocore library using aiohttp.


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

The list of libraries which are exists but not enlisted in former categories.

They may be perfect or not -- we don't know.

Please add your library reference here first and after some time
period ask to raise the status.

- `aiohttp-cache <https://github.com/cr0hn/aiohttp-cache>`_ A cache
  system for aiohttp server.

- `aiocache <https://github.com/argaen/aiocache>`_ Caching for asyncio
  with multiple backends (framework agnostic)

- `gain <https://github.com/gaojiuli/gain>`_ Web crawling framework
  based on asyncio for everyone.

- `aiohttp-swagger <https://github.com/cr0hn/aiohttp-swagger>`_
  Swagger API Documentation builder for aiohttp server.

- `aiohttp-swaggerify <https://github.com/dchaplinsky/aiohttp_swaggerify>`_
  Library to automatically generate swagger2.0 definition for aiohttp endpoints.

- `aiohttp-validate <https://github.com/dchaplinsky/aiohttp_validate>`_
  Simple library that helps you validate your API endpoints requests/responses with json schema.

- `raven-aiohttp <https://github.com/getsentry/raven-aiohttp>`_ An
  aiohttp transport for raven-python (Sentry client).

- `webargs <https://github.com/sloria/webargs>`_ A friendly library
  for parsing HTTP request arguments, with built-in support for
  popular web frameworks, including Flask, Django, Bottle, Tornado,
  Pyramid, webapp2, Falcon, and aiohttp.

- `aioauth-client <https://github.com/klen/aioauth-client>`_ OAuth
  client for aiohttp.

- `aiohttpretty
  <https://github.com/CenterForOpenScience/aiohttpretty>`_ A simple
  asyncio compatible httpretty mock using aiohttp.

- `aioresponses <https://github.com/pnuckowski/aioresponses>`_ a
  helper for mock/fake web requests in python aiohttp package.

- `aiohttp-transmute
  <https://github.com/toumorokoshi/aiohttp-transmute>`_ A transmute
  implementation for aiohttp.

- `aiohttp_apiset <https://github.com/aamalev/aiohttp_apiset>`_
  Package to build routes using swagger specification.

- `aiohttp-login <https://github.com/imbolc/aiohttp-login>`_
  Registration and authorization (including social) for aiohttp
  applications.

- `aiohttp_utils <https://github.com/sloria/aiohttp_utils>`_ Handy
  utilities for building aiohttp.web applications.

- `aiohttpproxy <https://github.com/jmehnle/aiohttpproxy>`_ Simple
  aiohttp HTTP proxy.

- `aiohttp_traversal <https://github.com/zzzsochi/aiohttp_traversal>`_
  Traversal based router for aiohttp.web.

- `aiohttp_autoreload
  <https://github.com/anti1869/aiohttp_autoreload>`_ Makes aiohttp
  server auto-reload on source code change.

- `gidgethub <https://github.com/brettcannon/gidgethub>`_ An async
  GitHub API library for Python.

- `aiohttp_jrpc <https://github.com/zloidemon/aiohttp_jrpc>`_ aiohttp
  JSON-RPC service.

- `fbemissary <https://github.com/cdunklau/fbemissary>`_ A bot
  framework for the Facebook Messenger platform, built on asyncio and
  aiohttp.

- `aioslacker <https://github.com/wikibusiness/aioslacker>`_ slacker
  wrapper for asyncio.

- `aioreloader <https://github.com/and800/aioreloader>`_ Port of
  tornado reloader to asyncio.

- `aiohttp_babel <https://github.com/jie/aiohttp_babel>`_ Babel
  localization support for aiohttp.

- `python-mocket <https://github.com/mindflayer/python-mocket>`_ a
  socket mock framework - for all kinds of socket animals, web-clients
  included.

- `aioraft <https://github.com/lisael/aioraft>`_ asyncio RAFT
  algorithm based on aiohttp.

- `home-assistant <https://github.com/home-assistant/home-assistant>`_
  Open-source home automation platform running on Python 3.

- `discord.py <https://github.com/Rapptz/discord.py>`_ Discord client library.

- `aiohttp-graphql <https://github.com/graphql-python/aiohttp-graphql>`_
  GraphQL and GraphIQL interface for aiohttp.

- `aiohttp-sentry <https://github.com/underyx/aiohttp-sentry>`_
  An aiohttp middleware for reporting errors to Sentry. Python 3.5+ is required.

- `async-v20 <https://github.com/jamespeterschinner/async_v20>`_
  Asynchronous FOREX client for OANDA's v20 API. Python 3.6+
