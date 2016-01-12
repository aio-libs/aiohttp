aiohttp_polls
=============

Example of polls project using aiohttp_, aiopg_ and aiohttp_jinja2_,
similar to django one.

Installation
============

Install the app::

    $ git clone git@github.com:KeepSafe/aiohttp.git
    $ cd aiohttp/demos/polls
    $ pip install -e .

Create database for your project::

    sudo -u postgres psql -c "CREATE USER aiohttp_user WITH PASSWORD 'aiohttp_user';" \
                             "CREATE DATABASE aiohttp_polls ENCODING 'UTF8';" \
                             "GRANT ALL PRIVILEGES ON DATABASE aiohttp_polls TO aiohttp_user;"


Create tables for your project::

    sudo -u postgres psql -d aiohttp_polls -a -f sql/create_tables.sql
    sudo -u postgres psql -d aiohttp_polls -a -f sql/sample_data.sql


Run application::

    $ python aiohttp_polls/main.py


Open browser::

    http://localhost:8080/

.. image:: https://raw.githubusercontent.com/andriisoldatenko/aiohttp_polls/master/images/example.png
    :align: center


Requirements
============
* aiohttp_
* aiopg_
* aiohttp_jinja2_


.. _Python: https://www.python.org
.. _aiohttp: https://github.com/KeepSafe/aiohttp
.. _aiopg: https://github.com/aio-libs/aiopg
.. _aiohttp_jinja2: https://github.com/aio-libs/aiohttp_jinja2
