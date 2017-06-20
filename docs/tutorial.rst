.. _aiohttp-tutorial:

Server Tutorial
===============

Are you going to learn *aiohttp* but don't know where to start? We have
example for you. Polls application is a great example for getting
started with aiohttp.

If you want the full source code in advance or for comparison, check out
the `demo source`_.

.. _demo source:
   https://github.com/aio-libs/aiohttp/tree/master/demos/polls/


.. _aiohttp-tutorial-setup:

Setup your environment
----------------------

First of all check you python version:

.. code-block:: shell

 $ python -V
 Python 3.5.0

Tutorial requires Python 3.5.0 or newer.

We’ll assume that you have already installed *aiohttp* library. You can check
aiohttp is installed and which version by running the following
command:

.. code-block:: shell

 $ python3 -c 'import aiohttp; print(aiohttp.__version__)'
 2.0.5

Project structure looks very similar to other python based web projects:

.. code-block:: none

    .
    ├── README.rst
    └── polls
        ├── Makefile
        ├── README.rst
        ├── aiohttpdemo_polls
        │   ├── __init__.py
        │   ├── __main__.py
        │   ├── db.py
        │   ├── main.py
        │   ├── routes.py
        │   ├── templates
        │   ├── utils.py
        │   └── views.py
        ├── config
        │   └── polls.yaml
        ├── images
        │   └── example.png
        ├── setup.py
        ├── sql
        │   ├── create_tables.sql
        │   ├── install.sh
        │   └── sample_data.sql
        └── static
            └── style.css


.. _aiohttp-tutorial-introduction:

Getting started with aiohttp first app
--------------------------------------

This tutorial based on Django polls tutorial.


Application
-----------

All aiohttp server is built around :class:`aiohttp.web.Application` instance.
It is used for registering *startup*/*cleanup* signals, connecting routes etc.

The following code creates an application::

   from aiohttp import web


   app = web.Application()
   web.run_app(app, host='127.0.0.1', port=8080)

Save it under ``aiohttpdemo_polls/main.py`` and start the server:

.. code-block:: shell

   $ python3 main.py  
   
You'll see the following output on the command line:

.. code-block:: shell

   ======== Running on http://127.0.0.1:8080 ========
   (Press CTRL+C to quit)

Open ``http://127.0.0.1:8080`` in browser or do

.. code-block:: shell

   $ curl -X GET localhost:8080

Alas, for now both return only ``404: Not Found``.
To show something more meaningful let's create a route and a view.

.. _aiohttp-tutorial-views:

Views
-----

Let's start from first views. Create the file ``aiohttpdemo_polls/views.py`` with the following::

    from aiohttp import web


    async def index(request):
        return web.Response(text='Hello Aiohttp!')

This is the simplest view possible in Aiohttp. 
Now we should create a route for this ``index`` view. Put this into ``aiohttpdemo_polls/routes.py`` (it is a good practice to separate views, routes, models etc. You'll have more of each, and it is nice to have them in different places)::

    from views import index


    def setup_routes(app):
        app.router.add_get('/', index)


Also, we should call ``setup_routes`` function somewhere, and the best place is in the ``main.py`` ::

   from aiohttp import web
   from routes import setup_routes


   app = web.Application()
   setup_routes(app)
   web.run_app(app, host='127.0.0.1', port=8080)

Start server again. Now if we open browser we can see:

.. code-block:: shell

    $ curl -X GET localhost:8080
    Hello Aiohttp!

Success! For now your working directory should look like this:

.. code-block:: none

    .
    ├── ..
    └── polls
        ├── aiohttpdemo_polls
        │   ├── main.py
        │   ├── routes.py
        │   └── views.py

.. _aiohttp-tutorial-config:

Configuration files
-------------------

aiohttp is configuration agnostic. It means the library does not
require any configuration approach and does not have builtin support
for any config schema.

But please take into account these facts:

   1. 99% of servers have configuration files.

   2. Every product (except Python-based solutions like Django and
      Flask) does not store config files as part as source code.

      For example Nginx has own configuration files stored by default
      under ``/etc/nginx`` folder.

      Mongo pushes config as ``/etc/mongodb.conf``.

   3. Config files validation is good idea, strong checks may prevent
      silly errors during product deployment.

Thus we **suggest** to use the following approach:

   1. Pushing configs as ``yaml`` files (``json`` or ``ini`` is also
      good but ``yaml`` is the best).

   2. Loading ``yaml`` config from a list of predefined locations,
      e.g. ``./config/app_cfg.yaml``, ``/etc/app_cfg.yaml``.

   3. Keeping ability to override config file by command line
      parameter, e.g. ``./run_app --config=/opt/config/app_cfg.yaml``.

   4. Applying strict validation checks to loaded dict. `trafaret
      <http://trafaret.readthedocs.io/en/latest/>`_, `colander
      <http://docs.pylonsproject.org/projects/colander/en/latest/>`_
      or `JSON schema
      <http://python-jsonschema.readthedocs.io/en/latest/>`_ are good
      candidates for such job.


Load config and push into application::

    # load config from yaml file in current dir
    conf = load_config(str(pathlib.Path('.') / 'config' / 'polls.yaml'))
    app['config'] = conf

.. _aiohttp-tutorial-database:

Database
--------

Setup
^^^^^

In this tutorial we will use the latest PostgreSQL database.  You can install
PostgreSQL using this instruction http://www.postgresql.org/download/

Database schema
^^^^^^^^^^^^^^^

We use SQLAlchemy to describe database schemas.
For this tutorial we can use two simple models ``question`` and ``choice``::

    import sqlalchemy as sa

    meta = sa.MetaData()

    question = sa.Table(
        'question', meta,
        sa.Column('id', sa.Integer, nullable=False),
        sa.Column('question_text', sa.String(200), nullable=False),
        sa.Column('pub_date', sa.Date, nullable=False),

        # Indexes #
        sa.PrimaryKeyConstraint('id', name='question_id_pkey'))

    choice = sa.Table(
        'choice', meta,
        sa.Column('id', sa.Integer, nullable=False),
        sa.Column('question_id', sa.Integer, nullable=False),
        sa.Column('choice_text', sa.String(200), nullable=False),
        sa.Column('votes', sa.Integer, server_default="0", nullable=False),

        # Indexes #
        sa.PrimaryKeyConstraint('id', name='choice_id_pkey'),
        sa.ForeignKeyConstraint(['question_id'], [question.c.id],
                                name='choice_question_id_fkey',
                                ondelete='CASCADE'),
    )



You can find below description of tables in database:

First table is question:

+---------------+
| question      |
+===============+
| id            |
+---------------+
| question_text |
+---------------+
| pub_date      |
+---------------+

and second table is choice table:

+---------------+
| choice        |
+===============+
| id            |
+---------------+
| choice_text   |
+---------------+
| votes         |
+---------------+
| question_id   |
+---------------+

Creating connection engine
^^^^^^^^^^^^^^^^^^^^^^^^^^

For making DB queries we need an engine instance. Assuming ``conf`` is
a :class:`dict` with configuration info Postgres connection could be
done by the following coroutine::

   async def init_pg(app):
       conf = app['config']
       engine = await aiopg.sa.create_engine(
           database=conf['database'],
           user=conf['user'],
           password=conf['password'],
           host=conf['host'],
           port=conf['port'],
           minsize=conf['minsize'],
           maxsize=conf['maxsize'])
       app['db'] = engine

The best place for connecting to DB is
:attr:`~aiohtp.web.Application.on_startup` signal::

   app.on_startup.append(init_pg)


Graceful shutdown
^^^^^^^^^^^^^^^^^

There is a good practice to close all resources on program exit.

Let's close DB connection in :attr:`~aiohtp.web.Application.on_cleanup` signal::

   async def close_pg(app):
       app['db'].close()
       await app['db'].wait_closed()


   app.on_cleanup.append(close_pg)



.. _aiohttp-tutorial-templates:

Templates
---------

Let's add more useful views::

   @aiohttp_jinja2.template('detail.html')
   async def poll(request):
       async with request['db'].acquire() as conn:
           question_id = request.match_info['question_id']
           try:
               question, choices = await db.get_question(conn,
                                                         question_id)
           except db.RecordNotFound as e:
               raise web.HTTPNotFound(text=str(e))
           return {
               'question': question,
               'choices': choices
           }

Templates are very convenient way for web page writing. We return a
dict with page content, ``aiohttp_jinja2.template`` decorator
processes it by jinja2 template renderer.

For setting up template engine we need to install ``aiohttp_jinja2``
library first:

.. code-block:: shell

   $ pip install aiohttp_jinja2

After installing we need to setup the library::

    import aiohttp_jinja2
    import jinja2

    aiohttp_jinja2.setup(
        app, loader=jinja2.PackageLoader('aiohttpdemo_polls', 'templates'))


In the tutorial we push template files under
``polls/aiohttpdemo_polls/templates`` folder.


.. _aiohttp-tutorial-static:

Static files
------------

Any web site has static files: images, JavaScript sources, CSS files etc.

The best way to handle static in production is setting up reverse
proxy like NGINX or using CDN services.

But for development handling static files by aiohttp server is very convenient.

Fortunately it can be done easy by single call::

    app.router.add_static('/static/',
                          path=str(project_root / 'static'),
                          name='static')


where ``project_root`` is the path to root folder.


.. _aiohttp-tutorial-middlewares:

Middlewares
-----------

Middlewares are stacked around every web-handler.  They are called
*before* handler for pre-processing request and *after* getting
response back for post-processing given response.

Here we'll add a simple middleware for displaying pretty looking pages
for *404 Not Found* and *500 Internal Error*.

Middlewares could be registered in ``app`` by adding new middleware to
``app.middlewares`` list::

   def setup_middlewares(app):
       error_middleware = error_pages({404: handle_404,
                                       500: handle_500})
       app.middlewares.append(error_middleware)

Middleware itself is a factory which accepts *application* and *next
handler* (the following middleware or *web-handler* in case of the
latest middleware in the list).

The factory returns *middleware handler* which has the same signature
as regular *web-handler* -- it accepts *request* and returns
*response*.

Middleware for processing HTTP exceptions::

   def error_pages(overrides):
       async def middleware(app, handler):
           async def middleware_handler(request):
               try:
                   response = await handler(request)
                   override = overrides.get(response.status)
                   if override is None:
                       return response
                   else:
                       return await override(request, response)
               except web.HTTPException as ex:
                   override = overrides.get(ex.status)
                   if override is None:
                       raise
                   else:
                       return await override(request, ex)
           return middleware_handler
       return middleware

Registered overrides are trivial Jinja2 template renderers::


   async def handle_404(request, response):
       response = aiohttp_jinja2.render_template('404.html',
                                                 request,
                                                 {})
       return response


   async def handle_500(request, response):
       response = aiohttp_jinja2.render_template('500.html',
                                                 request,
                                                 {})
       return response

.. seealso:: :ref:`aiohttp-web-middlewares`

.. disqus::
  :title: aiohttp server tutorial
