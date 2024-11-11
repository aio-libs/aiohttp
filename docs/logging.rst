.. currentmodule:: aiohttp

.. _aiohttp-logging:

Logging
=======

*aiohttp* uses standard :mod:`logging` for tracking the
library activity.

We have the following loggers enumerated by names:

- ``'aiohttp.access'``
- ``'aiohttp.client'``
- ``'aiohttp.internal'``
- ``'aiohttp.server'``
- ``'aiohttp.web'``
- ``'aiohttp.websocket'``

You may subscribe to these loggers for getting logging messages.  The
page does not provide instructions for logging subscribing while the
most friendly method is :func:`logging.config.dictConfig` for
configuring whole loggers in your application.

Logging does not work out of the box. It requires at least minimal ``'logging'``
configuration.
Example of minimal working logger setup::

  import logging
  from aiohttp import web

  app = web.Application()
  logging.basicConfig(level=logging.DEBUG)
  web.run_app(app, port=5000)

.. versionadded:: 4.0.0

Access logs
-----------

Access logs are enabled by default. If the `debug` flag is set, and the default
logger ``'aiohttp.access'`` is used, access logs will be output to
:obj:`~sys.stderr` if no handlers are attached.
Furthermore, if the default logger has no log level set, the log level will be
set to :obj:`logging.DEBUG`.

This logging may be controlled by :meth:`aiohttp.web.AppRunner` and
:func:`aiohttp.web.run_app`.

To override the default logger, pass an instance of :class:`logging.Logger` to
override the default logger.

.. note::

   Use ``web.run_app(app, access_log=None)`` to disable access logs.


In addition, *access_log_format* may be used to specify the log format.

.. _aiohttp-logging-access-log-format-spec:

Format specification
^^^^^^^^^^^^^^^^^^^^

The library provides custom micro-language to specifying info about
request and response:

+--------------+---------------------------------------------------------+
| Option       | Meaning                                                 |
+==============+=========================================================+
| ``%%``       | The percent sign                                        |
+--------------+---------------------------------------------------------+
| ``%a``       | Remote IP-address                                       |
|              | (IP-address of proxy if using reverse proxy)            |
+--------------+---------------------------------------------------------+
| ``%t``       | Time when the request was started to process            |
+--------------+---------------------------------------------------------+
| ``%P``       | The process ID of the child that serviced the request   |
+--------------+---------------------------------------------------------+
| ``%r``       | First line of request                                   |
+--------------+---------------------------------------------------------+
| ``%s``       | Response status code                                    |
+--------------+---------------------------------------------------------+
| ``%b``       | Size of response in bytes, including HTTP headers       |
+--------------+---------------------------------------------------------+
| ``%T``       | The time taken to serve the request, in seconds         |
+--------------+---------------------------------------------------------+
| ``%Tf``      | The time taken to serve the request, in seconds         |
|              | with fraction in %.06f format                           |
+--------------+---------------------------------------------------------+
| ``%D``       | The time taken to serve the request, in microseconds    |
+--------------+---------------------------------------------------------+
| ``%{FOO}i``  | ``request.headers['FOO']``                              |
+--------------+---------------------------------------------------------+
| ``%{FOO}o``  | ``response.headers['FOO']``                             |
+--------------+---------------------------------------------------------+

The default access log format is::

   '%a %t "%r" %s %b "%{Referer}i" "%{User-Agent}i"'

.. versionadded:: 2.3.0

*access_log_class* introduced.

Example of a drop-in replacement for the default access logger::

  from aiohttp.abc import AbstractAccessLogger

  class AccessLogger(AbstractAccessLogger):

      def log(self, request, response, time):
          self.logger.info(f'{request.remote} '
                           f'"{request.method} {request.path} '
                           f'done in {time}s: {response.status}')


.. versionadded:: 4.0.0


``AccessLogger.log()`` can now access any exception raised while processing
the request with ``sys.exc_info()``.


.. versionadded:: 4.0.0


If your logging needs to perform IO you can instead inherit from
:class:`aiohttp.abc.AbstractAsyncAccessLogger`::


  from aiohttp.abc import AbstractAsyncAccessLogger

  class AccessLogger(AbstractAsyncAccessLogger):

      async def log(self, request, response, time):
          logging_service = request.app['logging_service']
          await logging_service.log(f'{request.remote} '
                                    f'"{request.method} {request.path} '
                                    f'done in {time}s: {response.status}')

      @property
      def enabled(self) -> bool:
          """Return True if logger is enabled.

          Override this property if logging is disabled to avoid the
          overhead of calculating details to feed the logger.
          """
          return True


This also allows access to the results of coroutines on the ``request`` and
``response``, e.g. ``request.text()``.

.. _gunicorn-accesslog:

Gunicorn access logs
^^^^^^^^^^^^^^^^^^^^
When `Gunicorn <http://docs.gunicorn.org/en/latest/index.html>`_ is used for
:ref:`deployment <aiohttp-deployment-gunicorn>`, its default access log format
will be automatically replaced with the default aiohttp's access log format.

If Gunicorn's option access_logformat_ is
specified explicitly, it should use aiohttp's format specification.

Gunicorn's access log works only if accesslog_ is specified explicitly in your
config or as a command line option.
This configuration can be either a path or ``'-'``. If the application uses
a custom logging setup intercepting the ``'gunicorn.access'`` logger,
accesslog_ should be set to ``'-'`` to prevent Gunicorn to create an empty
access log file upon every startup.

Error logs
----------

:mod:`aiohttp.web` uses a logger named ``'aiohttp.server'`` to store errors
given on web requests handling.

This log is enabled by default.

To use a different logger name, pass *logger* (:class:`logging.Logger`
instance) to the :meth:`aiohttp.web.AppRunner` constructor.


.. _access_logformat:
    http://docs.gunicorn.org/en/stable/settings.html#access-log-format

.. _accesslog:
    http://docs.gunicorn.org/en/stable/settings.html#accesslog
