.. _aiohttp-tutorial:

Tutorial
========

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

First of all check you python version::

 $ python -V
 Python 3.5.0

Tutorial requires Python 3.5.0 or newer.

We’ll assume that you have already installed *aiohttp* library. You can check
aiohttp is installed and which version by running the following
command::

 $ python -c 'import aiohttp; print(aiohttp.__version__)'
 0.22.0

Project structure looks very similar to other python based web projects::

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


.. _aiohttp-tutorial-views:

Views
-----

Let's start from first views. Open polls/aiohttpdemo_polls/views.py and put
next Python code inside file (``polls/aiohttpdemo_polls/views.py``)::

    from aiohttp import web


    class SiteHandler:
        async def index(self, request):
            return web.Response(text='Hello Aiohttp!')

This is the simplest view possible in Aiohttp. Now we should add ``index`` view
to ``polls/aiohttpdemo_polls/routes.py``::

    def setup_routes(app, handler, project_root):
        add_route = app.router.add_route
        add_route('GET', '/', handler.index)

Now if we open browser we can see::

    $ curl -X GET localhost:8080
    Hello Aiohttp!


.. _aiohttp-tutorial-templates:

Templates
---------

Let's add more useful views::

   @aiohttp_jinja2.template('detail.html')
   async def poll(self, request):
       question_id = request.match_info['question_id']
       try:
           question, choices = await db.get_question(self.postgres,
                                                     question_id)
       except db.RecordNotFound as e:
           raise web.HTTPNotFound(text=str(e))
       return {
           'question': question,
           'choices': choices
       }

Templates are very convinient way forweb page writing. We return a
dict with page content, ``aiohttp_jinja2.template`` decorator
processes it by jinja2 template renderer.

For setting up template engine we need to install ``aiohttp_jinja2``
library first::

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

But for development handling static files by aiohttp server is very convinient.

Fortunatelly it can be done easy by single call::

    app.router.add_static('/static/',
                          path=str(project_root / 'static'),
                          name='static')


where ``project_root`` is the path to root folder.
