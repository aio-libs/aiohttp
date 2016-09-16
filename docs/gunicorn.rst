.. _deployment-using-gunicorn:

Deployment using Gunicorn
=========================

aiohttp can be deployed using `Gunicorn
<http://docs.gunicorn.org/en/latest/index.html>`_, which is based on a
pre-fork worker model.  Gunicorn launches your app as worker processes
for handling incoming requests.

Prepare environment
-------------------

You firstly need to setup your deployment environment. This example is
based on Ubuntu 14.04.

Create a directory for your application::

  >> mkdir myapp
  >> cd myapp

Ubuntu has a bug in pyenv, so to create virtualenv you need to do some
extra manipulation::

  >> pyvenv-3.4 --without-pip venv
  >> source venv/bin/activate
  >> curl https://bootstrap.pypa.io/get-pip.py | python
  >> deactivate
  >> source venv/bin/activate

Now that the virtual environment is ready, we'll proceed to install
aiohttp and gunicorn::

  >> pip install gunicorn
  >> pip install -e git+https://github.com/KeepSafe/aiohttp.git#egg=aiohttp


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
*aiohttp.worker.GunicornWebWorker* and should be used instead of the
*gaiohttp* worker provided by Gunicorn, which supports only
aiohttp.wsgi applications::

  >> gunicorn my_app_module:my_web_app --bind localhost:8080 --worker-class aiohttp.worker.GunicornWebWorker
  [2015-03-11 18:27:21 +0000] [1249] [INFO] Starting gunicorn 19.3.0
  [2015-03-11 18:27:21 +0000] [1249] [INFO] Listening at: http://127.0.0.1:8080 (1249)
  [2015-03-11 18:27:21 +0000] [1249] [INFO] Using worker: aiohttp.worker.GunicornWebWorker
  [2015-03-11 18:27:21 +0000] [1253] [INFO] Booting worker with pid: 1253

Gunicorn is now running and ready to serve requests to your app's
worker processes.

.. note::

   If you want to use an alternative asyncio event loop
   `uvloop <https://github.com/MagicStack/uvloop>`_, you can use the
   ``aiohttp.worker.GunicornUVLoopWebWorker`` worker class.


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

For more information please read :ref:`Format Specification for Accees
Log <aiohttp-logging-access-log-format-spec>`.

.. disqus::
  :title: aiohttp deployment with gunicorn
