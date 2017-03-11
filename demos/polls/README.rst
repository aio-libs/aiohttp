Polls (demo for aiohttp)
========================

Example of polls project using aiohttp_, aiopg_ and aiohttp_jinja2_,
similar to django one.

Installation
============

Install the app::

    $ cd demos/polls
    $ pip install -e .

Create database for your project::

    bash sql/install.sh

Run application::

    $ python -m aiohttpdemo_polls


Open browser::

    http://localhost:8080/

.. image:: https://raw.githubusercontent.com/andriisoldatenko/aiohttp_polls/master/images/example.png
    :align: center


Run integration tests::

  pip install tox
  tox


Requirements
============
* aiohttp_
* aiopg_
* aiohttp_jinja2_


.. _Python: https://www.python.org
.. _aiohttp: https://github.com/aio-libs/aiohttp
.. _aiopg: https://github.com/aio-libs/aiopg
.. _aiohttp_jinja2: https://github.com/aio-libs/aiohttp_jinja2
