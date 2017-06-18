=========================
aiohttp server deployment
=========================

There are several options for aiohttp server deployment:

* Standalone server

* Running a pool of backend servers behind of :term:`nginx`, HAProxy
  or other *reverse proxy server*

* Using :term:`gunicorn` behind of *reverse proxy*

Every method has own benefits and disadvantages.


.. _aiohttp-deployment-standalone:

Standalone
==========

Just call :func:`aiohttp.web.run_app` function passing
:class:`aiohttp.web.Application` instance.


The method is very simple and could be the best solution in some
trivial cases. But it does not utilize all CPU cores.

For running multiple aiohttp server instances use *reverse proxies*.

.. _aiohttp-deployment-nginx-supervisord:

Nginx+supervisord
=================

Running aiohttp servers behind :term:`nginx` makes several advantages.

At first, nginx is the perfect frontend server. It may prevent many
attacks based on malformed http protocol etc.

Second, running several aiohttp instances behind nginx allows to
utilize all CPU cores.

Third, nginx serves static files much faster than built-in aiohttp
static file support.

But this way requires more complex configuration.

Nginx configuration
--------------------

Here is short extraction about writing Nginx configuration file.
It does not cover all available Nginx options.

For full reference read `Nginx tutorial
<https://www.nginx.com/resources/admin-guide/>`_ and `official Nginx
documentation
<http://nginx.org/en/docs/http/ngx_http_proxy_module.html>`_.

First configure HTTP server itself:

.. code-block:: nginx

   http {
     server {
       listen 80;
       client_max_body_size 4G;

       server_name example.com;

       location / {
         proxy_set_header Host $http_host;
         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
         proxy_redirect off;
         proxy_buffering off;
         proxy_pass http://aiohttp;
       }

       location /static {
         # path for static files
         root /path/to/app/static;
       }

     }
   }

This config listens on port ``80`` for server named ``example.com``
and redirects everything to ``aiohttp`` backend group.

Also it serves static files from ``/path/to/app/static`` path as
``example.com/static``.

Next we need to configure *aiohttp upstream group*:

.. code-block:: nginx

   http {
     upstream aiohttp {
       # fail_timeout=0 means we always retry an upstream even if it failed
       # to return a good HTTP response

       # Unix domain servers
       server unix:/tmp/example_1.sock fail_timeout=0;
       server unix:/tmp/example_2.sock fail_timeout=0;
       server unix:/tmp/example_3.sock fail_timeout=0;
       server unix:/tmp/example_4.sock fail_timeout=0;

       # Unix domain sockets are used in this example due to their high performance,
       # but TCP/IP sockets could be used instead:
       # server 127.0.0.1:8081 fail_timeout=0;
       # server 127.0.0.1:8082 fail_timeout=0;
       # server 127.0.0.1:8083 fail_timeout=0;
       # server 127.0.0.1:8084 fail_timeout=0;
     }
   }

All HTTP requests for ``http://example.com`` except ones for
``http://example.com/static`` will be redirected to ``example1.sock``,
``example2.sock``, ``example3.sock`` or ``example4.sock``
backend servers. By default, Nginx uses round-robin algorithm for backend
selection.

.. note::

   Nginx is not the only existing *reverse proxy server* but the most
   popular one.  Alternatives like HAProxy may be used as well.

Supervisord
-----------

After configuring Nginx we need to start our aiohttp backends. Better
to use some tool for starting them automatically after system reboot
or backend crash.

There are very many ways to do it: Supervisord, Upstart, Systemd,
Gaffer, Circus, Runit etc.

Here we'll use `Supervisord <http://supervisord.org/>`_ for example:

.. code-block:: cfg

   [program:aiohttp]
   numprocs = 4
   numprocs_start = 1
   process_name = example_%(process_num)s

   ; Unix socket paths are specified by command line.
   commmand=/path/to/aiohttp_example.py --path=/tmp/example_%(process_num)s.sock

   ; We can just as easily pass TCP port numbers:
   ; command=/path/to/aiohttp_example.py --port=808%(process_num)s

   user=nobody
   autostart=true
   autorestart=true

aiohttp server
--------------

The last step is preparing aiohttp server for working with supervisord.

Assuming we have properly configured :class:`aiohttp.web.Application`
and port is specified by command line, the task is trivial:

.. code-block:: python3

   # aiohttp_example.py
   import argparse
   from aiohttp import web

   parser = argparse.ArgumentParser(description="aiohttp server example")
   parser.add_argument('--path')
   parser.add_argument('--port')


   if __name__ == '__main__':
       app = web.Application()
       # configure app

       args = parser.parse_args()
       web.run_app(app, path=args.path, port=args.port)

For real use cases we perhaps need to configure other things like
logging etc., but it's out of scope of the topic.


.. _aiohttp-deployment-gunicorn:

Nginx+Gunicorn
==============

aiohttp can be deployed using `Gunicorn
<http://docs.gunicorn.org/en/latest/index.html>`_, which is based on a
pre-fork worker model.  Gunicorn launches your app as worker processes
for handling incoming requests.

In opposite to deployment with :ref:`bare Nginx
<aiohttp-deployment-nginx-supervisord>` the solution does not need to
manually run several aiohttp processes and use tool like supervisord
for monitoring it. But nothing is for free: running aiohttp
application under gunicorn is slightly slower.


Prepare environment
-------------------

You firstly need to setup your deployment environment. This example is
based on `Ubuntu` 14.04.

Create a directory for your application::

  >> mkdir myapp
  >> cd myapp

`Ubuntu` has a bug in pyenv, so to create virtualenv you need to do some
extra manipulation::

  >> pyvenv-3.4 --without-pip venv
  >> source venv/bin/activate
  >> curl https://bootstrap.pypa.io/get-pip.py | python
  >> deactivate
  >> source venv/bin/activate

Now that the virtual environment is ready, we'll proceed to install
aiohttp and gunicorn::

  >> pip install gunicorn
  >> pip install -e git+https://github.com/aio-libs/aiohttp.git#egg=aiohttp


Application
-----------

Lets write a simple application, which we will save to file. We'll
name this file *my_app_module.py*::

   from aiohttp import web

   def index(request):
       return web.Response(text="Welcome home!")


   my_web_app = web.Application()
   my_web_app.router.add_get('/', index)


Start Gunicorn
--------------

When `Running Gunicorn
<http://docs.gunicorn.org/en/latest/run.html>`_, you provide the name
of the module, i.e. *my_app_module*, and the name of the app,
i.e. *my_web_app*, along with other `Gunicorn Settings
<http://docs.gunicorn.org/en/latest/settings.html>`_ provided as
command line flags or in your config file.

In this case, we will use:

* the *'--bind'* flag to set the server's socket address;
* the *'--worker-class'* flag to tell Gunicorn that we want to use a
  custom worker subclass instead of one of the Gunicorn default worker
  types;
* you may also want to use the *'--workers'* flag to tell Gunicorn how
  many worker processes to use for handling requests. (See the
  documentation for recommendations on `How Many Workers?
  <http://docs.gunicorn.org/en/latest/design.html#how-many-workers>`_)

The custom worker subclass is defined in
*aiohttp.GunicornWebWorker* and should be used instead of the
*gaiohttp* worker provided by Gunicorn, which supports only
aiohttp.wsgi applications::

  >> gunicorn my_app_module:my_web_app --bind localhost:8080 --worker-class aiohttp.GunicornWebWorker
  [2015-03-11 18:27:21 +0000] [1249] [INFO] Starting gunicorn 19.3.0
  [2015-03-11 18:27:21 +0000] [1249] [INFO] Listening at: http://127.0.0.1:8080 (1249)
  [2015-03-11 18:27:21 +0000] [1249] [INFO] Using worker: aiohttp.worker.GunicornWebWorker
  [2015-03-11 18:27:21 +0000] [1253] [INFO] Booting worker with pid: 1253

Gunicorn is now running and ready to serve requests to your app's
worker processes.

.. note::

   If you want to use an alternative asyncio event loop
   `uvloop <https://github.com/MagicStack/uvloop>`_, you can use the
   ``aiohttp.GunicornUVLoopWebWorker`` worker class.


More information
----------------

The Gunicorn documentation recommends deploying Gunicorn behind an
Nginx proxy server. See the `official documentation
<http://docs.gunicorn.org/en/latest/deploy.html>`_ for more
information about suggested nginx configuration.


Logging configuration
---------------------

``aiohttp`` and ``gunicorn`` use different format for specifying access log.

By default aiohttp uses own defaults::

   '%a %l %u %t "%r" %s %b "%{Referrer}i" "%{User-Agent}i"'

For more information please read :ref:`Format Specification for Access
Log <aiohttp-logging-access-log-format-spec>`.

.. disqus::
  :title: aiohttp deployment with gunicorn
