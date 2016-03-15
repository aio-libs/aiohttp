.. _tutorial-setup:

Setup your environment
======================

First of all check you python version: ::

 $ python -V
 Python 3.5.0


We’ll assume that you have already installed `aiohttp`. You can check aiohttp is installed and which version by running the following command: ::

 $ python -c 'import aiohttp; print(aiohttp.__version__)'
 0.21.4

Project structure looks very similar to other python based web projects: ::

    $ tree -L 3
    .
    ├── README.rst
    └── polls
        ├── Makefile
        ├── README.rst
        ├── aiohttpdemo_polls
        │   ├── __init__.py
        │   ├── __main__.py
        │   ├── db.py
        │   ├── main.py
        │   ├── routes.py
        │   ├── templates
        │   ├── utils.py
        │   └── views.py
        ├── config
        │   └── polls.yaml
        ├── images
        │   └── example.png
        ├── setup.py
        ├── sql
        │   ├── create_tables.sql
        │   ├── install.sh
        │   └── sample_data.sql
        └── static
            └── style.css

