.. _aiohttp-tracing-reference:

Tracing Reference
=================

.. module:: aiohttp
.. currentmodule:: aiohttp


TraceConfig
-----------

Trace config is the configuration object used to trace requests launched by
a Client session object using different events related to different parts of
the request flow.

.. class:: TraceConfig(trace_config_ctx_factory=SimpleNamespace)

   :param trace_config_ctx_factory: factory used to create trace contexts,
      default class used :class:`SimpleNamespace`

   .. method:: trace_config_ctx(trace_request_ctx=None)

      :param trace_request_ctx: Will be used to pass as a kw for the
        ``trace_config_ctx_factory``.

      Return a new trace context.

   .. attribute:: on_request_start

      Property that gives access to the signals that will be executed when a
      request starts, based on the :class:`~signals.Signal` implementation.

      The coroutines listening will receive as a param the ``session``,
      ``trace_config_ctx``, ``method``, ``url`` and ``headers``.

      .. versionadded:: 3.0

   .. attribute:: on_request_redirect

      Property that gives access to the signals that will be executed when a
      redirect happens during a request flow.

      The coroutines that are listening will receive the ``session``,
      ``trace_config_ctx``, ``method``, ``url``, ``headers`` and ``resp`` params.

      .. versionadded:: 3.0

   .. attribute:: on_request_end

      Property that gives access to the signals that will be executed when a
      request ends.

      The coroutines that are listening will receive the ``session``,
      ``trace_config_ctx``, ``method``, ``url``, ``headers`` and ``resp`` params

      .. versionadded:: 3.0

   .. attribute:: on_request_exception

      Property that gives access to the signals that will be executed when a
      request finishes with an exception.

      The coroutines listening will receive the ``session``,
      ``trace_config_ctx``, ``method``, ``url``, ``headers`` and ``exception`` params.

      .. versionadded:: 3.0

   .. attribute:: on_connection_queued_start

      Property that gives access to the signals that will be executed when a
      request has been queued waiting for an available connection.

      The coroutines that are listening will receive the ``session`` and
      ``trace_config_ctx`` params.

      .. versionadded:: 3.0

   .. attribute:: on_connection_queued_end

      Property that gives access to the signals that will be executed when a
      request that was queued already has an available connection.

      The coroutines that are listening will receive the ``session`` and
      ``trace_config_ctx`` params.

      .. versionadded:: 3.0

   .. attribute:: on_connection_create_start

      Property that gives access to the signals that will be executed when a
      request creates a new connection.

      The coroutines listening will receive the ``session`` and
      ``trace_config_ctx`` params.

      .. versionadded:: 3.0

   .. attribute:: on_connection_create_end

      Property that gives access to the signals that will be executed when a
      request that created a new connection finishes its creation.

      The coroutines listening will receive the ``session`` and
      ``trace_config_ctx`` params.

      .. versionadded:: 3.0

   .. attribute:: on_connection_reuseconn

      Property that gives access to the signals that will be executed when a
      request reuses a connection.

      The coroutines listening will receive the ``session`` and
      ``trace_config_ctx`` params.

      .. versionadded:: 3.0

   .. attribute:: on_dns_resolvehost_start

      Property that gives access to the signals that will be executed when a
      request starts to resolve the domain related with the request.

      The coroutines listening will receive the ``session`` and
      ``trace_config_ctx`` params.

      .. versionadded:: 3.0

   .. attribute:: on_dns_resolvehost_end

      Property that gives access to the signals that will be executed when a
      request finishes to resolve the domain related with the request.

      The coroutines listening will receive the ``session`` and ``trace_config_ctx``
      params.

      .. versionadded:: 3.0

   .. attribute:: on_dns_cache_hit

      Property that gives access to the signals that will be executed when a
      request was able to use a cached DNS resolution for the domain related
      with the request.

      The coroutines listening will receive the ``session`` and
      ``trace_config_ctx`` params.

      .. versionadded:: 3.0

   .. attribute:: on_dns_cache_miss

      Property that gives access to the signals that will be executed when a
      request was not able to use a cached DNS resolution for the domain related
      with the request.

      The coroutines listening will receive the ``session`` and
      ``trace_config_ctx`` params.

      .. versionadded:: 3.0
