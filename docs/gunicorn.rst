aiohttp web application with Gunicorn
=====================================

Launching your aiohttp web application on Ubuntu Linux with Gunicorn


Prepare environment
-------------------

Everything was tested on Ubuntu 14.04::

  >> mkdir myapp
  >> cd myapp

Ubuntu has a bug in pyenv, so to create virtualenv you need to do some
extra manipulation::
 
  >> pyvenv-3.4 --without-pip venv
  >> source venv/bin/activate
  >> curl https://bootstrap.pypa.io/get-pip.py | python
  >> deactivate
  >> source venv/bin/activate

The Virtual environment should be ready, now we need to install aiohttp and gunicorn::

  >> pip install gunicorn
  >> pip install -e git+https://github.com/KeepSafe/aiohttp.git#egg=aiohttp


Application
-----------

Lets write a simple application:

.. code-block:: python

   from aiohttp import web

   def index(request):
       return web.Response(text="Welcome home!")


   app = web.Application()
   app.router.add_route('GET', '/', index)


Save this code to *app.py* file.


Start Gunicorn
--------------

You can not use *gaiohttp* worker from gunicorn because it supports only
aiohttp.wsgi applications. Instead of *gaiohttp* you should
use *aiohttp.worker.GunicornWebWorker*::

  >> gunicorn app:app -k aiohttp.worker.GunicornWebWorker -b localhost:8080
  [2015-03-11 18:27:21 +0000] [1249] [INFO] Starting gunicorn 19.3.0
  [2015-03-11 18:27:21 +0000] [1249] [INFO] Listening at: http://127.0.0.1:8080 (1249)
  [2015-03-11 18:27:21 +0000] [1249] [INFO] Using worker: aiohttp.worker.GunicornWebWorker
  [2015-03-11 18:27:21 +0000] [1253] [INFO] Booting worker with pid: 1253

It is up and ready to serve requests.


More information
----------------

Please refer `official documentation <http://docs.gunicorn.org/en/latest/deploy.html>`_ for more information about *Gunicorn* production deployment.
