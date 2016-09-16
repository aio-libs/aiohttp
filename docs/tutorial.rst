.. _aiohttp-tutorial:

HTTP Server Tutorial
====================

Are you going to learn *aiohttp* but don't where to start? We have
example for you. Polls application is a great example for getting
started with aiohttp.

If you want the full source code in advance or for comparison, check out
the `demo source`_.

.. _demo source:
   https://github.com/KeepSafe/aiohttp/tree/master/demos/polls/


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

 $ python -c 'import aiohttp; print(aiohttp.__version__)'
 0.22.0

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

.. _aiohttp-tutorial-config:

Configuration files
-------------------

aiohttp is configuration agnostic. It means the library doesn't
require any configuration approach and doesn't have builtin support
for any config schema.

But please take into account these facts:

   1. 99% of servers have configuration files.

   2. Every product (except Python-based solutions like Django and
      Flask) doesn't store config files as part as source code.

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
      <https://github.com/Deepwalker/trafaret>`_, `collander
      <http://docs.pylonsproject.org/projects/colander/en/latest/>`_
      or `JSON schema
      <http://python-jsonschema.readthedocs.io/en/latest/>`_ are good
      candidates for such job.

.. _aiohttp-tutorial-database:

Database
--------

Setup
^^^^^

In this tutorial we use latest PostgreSQL database.  You can install
PostgreSQL using this instruction http://www.postgresql.org/download/

Database schema
^^^^^^^^^^^^^^^

We use SQLAlchemy for describe database schema.
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

TBD: aiopg.sa.create_engine and pushing it into app's storage

TBD: graceful cleanup


.. _aiohttp-tutorial-views:

Views
-----

Let's start from first views. Open polls/aiohttpdemo_polls/views.py and put
next Python code inside file (``polls/aiohttpdemo_polls/views.py``)::

    from aiohttp import web


    async def index(self, request):
        return web.Response(text='Hello Aiohttp!')

This is the simplest view possible in Aiohttp. Now we should add ``index`` view
to ``polls/aiohttpdemo_polls/routes.py``::

    from .views import index


    def setup_routes(app, project_root):
        app.router.add_get('/', index)

Now if we open browser we can see:

.. code-block:: shell

    $ curl -X GET localhost:8080
    Hello Aiohttp!


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


Middlewares
-----------

TBD

.. disqus::
  :title: aiohttp server tutorial
