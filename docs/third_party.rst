.. _aiohttp-3rd-party:

Third-Party libraries
=====================


aiohttp is not just a library for making HTTP requests and creating web
servers.

It is the foundation for libraries built *on top* of aiohttp.

This page is a list of these tools.

Please feel free to add your open source library if it's not listed
yet by making a pull request to https://github.com/aio-libs/aiohttp/

* Why would you want to include your awesome library in this list?

* Because the list increases your library visibility. People
  will have an easy way to find it.


Officially supported
--------------------

This list contains libraries which are supported by the *aio-libs* team
and located on https://github.com/aio-libs


aiohttp extensions
^^^^^^^^^^^^^^^^^^

- `aiohttp-apischema <https://github.com/aio-libs/aiohttp-apischema>`_
  provides automatic API schema generation and validation of user input
  for :mod:`aiohttp.web`.

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

- `aiozipkin <https://github.com/aio-libs/aiozipkin>`_ distributed
  tracing instrumentation for `aiohttp` client and server.

Database drivers
^^^^^^^^^^^^^^^^

- `aiopg <https://github.com/aio-libs/aiopg>`_ PostgreSQL async driver.

- `aiomysql <https://github.com/aio-libs/aiomysql>`_ MySQL async driver.

- `aioredis <https://github.com/aio-libs/aioredis>`_ Redis async driver.

Other tools
^^^^^^^^^^^

- `aiodocker <https://github.com/aio-libs/aiodocker>`_ Python Docker
  API client based on asyncio and aiohttp.

- `aiobotocore <https://github.com/aio-libs/aiobotocore>`_ asyncio
  support for botocore library using aiohttp.


Approved third-party libraries
------------------------------

These libraries are not part of ``aio-libs`` but they have proven to be very
well written and highly recommended for usage.

- `uvloop <https://github.com/MagicStack/uvloop>`_ Ultra fast
  implementation of asyncio event loop on top of ``libuv``.

  We highly recommend to use this instead of standard ``asyncio``.

Database drivers
^^^^^^^^^^^^^^^^

- `asyncpg <https://github.com/MagicStack/asyncpg>`_ Another
  PostgreSQL async driver. It's much faster than ``aiopg`` but is
  not a drop-in replacement -- the API is different. But, please take
  a look at it -- the driver is incredibly fast.

OpenAPI / Swagger extensions
----------------------------

Extensions bringing `OpenAPI <https://swagger.io/docs/specification/about>`_
support to aiohttp web servers.

- `aiohttp-apispec <https://github.com/maximdanilchenko/aiohttp-apispec>`_
  Build and document REST APIs with ``aiohttp`` and ``apispec``.

- `aiohttp_apiset <https://github.com/aamalev/aiohttp_apiset>`_
  Package to build routes using swagger specification.

- `aiohttp-pydantic <https://github.com/Maillol/aiohttp-pydantic>`_
  An ``aiohttp.View`` to validate the HTTP request's body, query-string, and
  headers regarding function annotations and generate OpenAPI doc.

- `aiohttp-swagger <https://github.com/cr0hn/aiohttp-swagger>`_
  Swagger API Documentation builder for aiohttp server.

- `aiohttp-swagger3 <https://github.com/hh-h/aiohttp-swagger3>`_
  Library for Swagger documentation builder and validating aiohttp requests
  using swagger specification 3.0.

- `aiohttp-swaggerify <https://github.com/dchaplinsky/aiohttp_swaggerify>`_
  Library to automatically generate swagger2.0 definition for aiohttp endpoints.

- `aio-openapi <https://github.com/quantmind/aio-openapi>`_
  Asynchronous web middleware for aiohttp and serving Rest APIs with OpenAPI v3
  specification and with optional PostgreSQL database bindings.

- `rororo <https://github.com/playpauseandstop/rororo>`_
  Implement ``aiohttp.web`` OpenAPI 3 server applications with schema first
  approach.

Others
------

Here is a list of other known libraries that do not belong in the former categories.

We cannot vouch for the quality of these libraries, use them at your own risk.

Please add your library reference here first and after some time
ask to raise the status.

- `pytest-aiohttp-client <https://github.com/sivakov512/pytest-aiohttp-client>`_
  Pytest fixture with simpler api, payload decoding and status code assertions.

- `octomachinery <https://octomachinery.dev>`_ A framework for developing
  GitHub Apps and GitHub Actions.

- `aiomixcloud <https://github.com/amikrop/aiomixcloud>`_
  Mixcloud API wrapper for Python and Async IO.

- `aiohttp-cache <https://github.com/cr0hn/aiohttp-cache>`_ A cache
  system for aiohttp server.

- `aiocache <https://github.com/argaen/aiocache>`_ Caching for asyncio
  with multiple backends (framework agnostic)

- `gain <https://github.com/gaojiuli/gain>`_ Web crawling framework
  based on asyncio for everyone.

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

- `aiogram <https://github.com/aiogram/aiogram>`_
  A fully asynchronous library for Telegram Bot API written with asyncio and aiohttp.

- `aiohttp-graphql <https://github.com/graphql-python/aiohttp-graphql>`_
  GraphQL and GraphIQL interface for aiohttp.

- `aiohttp-sentry <https://github.com/underyx/aiohttp-sentry>`_
  An aiohttp middleware for reporting errors to Sentry.

- `aiohttp-datadog <https://github.com/underyx/aiohttp-datadog>`_
  An aiohttp middleware for reporting metrics to DataDog.

- `async-v20 <https://github.com/jamespeterschinner/async_v20>`_
  Asynchronous FOREX client for OANDA's v20 API.

- `aiohttp-jwt <https://github.com/hzlmn/aiohttp-jwt>`_
  An aiohttp middleware for JWT(JSON Web Token) support.

- `AWS Xray Python SDK <https://github.com/aws/aws-xray-sdk-python>`_
  Native tracing support for Aiohttp applications.

- `GINO <https://github.com/fantix/gino>`_
  An asyncio ORM on top of SQLAlchemy core, delivered with an aiohttp extension.

- `New Relic <https://github.com/newrelic/newrelic-quickstarts/tree/main/quickstarts/python/aiohttp>`_ An aiohttp middleware for reporting your `Python application performance <https://newrelic.com/instant-observability/aiohttp>`_ metrics to New Relic.

- `eider-py <https://github.com/eider-rpc/eider-py>`_ Python implementation of
  the `Eider RPC protocol <http://eider.readthedocs.io/>`_.

- `asynapplicationinsights <https://github.com/RobertoPrevato/asynapplicationinsights>`_
  A client for `Azure Application Insights
  <https://azure.microsoft.com/en-us/services/application-insights/>`_ implemented using
  ``aiohttp`` client, including a middleware for ``aiohttp`` servers to collect web apps
  telemetry.

- `aiogmaps <https://github.com/hzlmn/aiogmaps>`_
  Asynchronous client for Google Maps API Web Services.

- `DBGR <https://github.com/JakubTesarek/dbgr>`_
  Terminal based tool to test and debug HTTP APIs with ``aiohttp``.

- `aiohttp-middlewares <https://github.com/playpauseandstop/aiohttp-middlewares>`_
  Collection of useful middlewares for ``aiohttp.web`` applications.

- `aiohttp-tus <https://github.com/pylotcode/aiohttp-tus>`_
  `tus.io <https://tus.io>`_ protocol implementation for ``aiohttp.web``
  applications.

- `aiohttp-sse-client <https://github.com/rtfol/aiohttp-sse-client>`_
  A Server-Sent Event python client base on aiohttp.

- `aiohttp-retry <https://github.com/inyutin/aiohttp_retry>`_
  Wrapper for aiohttp client for retrying requests.

- `aiohttp-socks <https://github.com/romis2012/aiohttp-socks>`_
  SOCKS proxy connector for aiohttp.

- `aiohttp-catcher <https://github.com/yuvalherziger/aiohttp-catcher>`_
  An aiohttp middleware library for centralized error handling in aiohttp servers.

- `rsocket <https://github.com/rsocket/rsocket-py>`_
  Python implementation of `RSocket protocol <https://rsocket.io>`_.

- `nacl_middleware <https://github.com/CosmicDNA/nacl_middleware>`_
  An aiohttp middleware library for asymmetric encryption of data transmitted via http and/or websocket connections.

- `aiohttp-asgi-connector <https://github.com/thearchitector/aiohttp-asgi-connector>`_
  An aiohttp connector for using a ``ClientSession`` to interface directly with separate ASGI applications.
