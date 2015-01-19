.. _aiohttp-contributing:

Contributing
============

.. _GitHub: https://github.com/KeepSafe/aiohttp

Instruction for contributors
----------------------------


At first make a clone of _GitHub repo: open the link and press "Fork"
button on upper-right side of web page.

I hope everybody know how to work with git and github for todays :)

Make a change.

**But**, before sending pull request please run test suite at least.

Preconditions for running aiohttp test suite
--------------------------------------------

We expect existing python virtual environment for running our tests.

There are several ways for making virtual environment.

If you like to use *virtualenv* please run::

   $ cd aiohttp
   $ virtualenv --python=`which python3` venv

For standard python *venv*::

   $ cd aiohttp
   $ python3 -m venv venv

For *virtualenvwrapper* (my choice)::

   $ cd aiohttp
   $ mkvirtualenv --python=`which python3` aiohttp

There are other tools like *pyvenv* but you know the rule of thumb
now: create python3 virtual environment and activate it.

After that please install libraries requered for development::

   $ pip install -r requirements-dev.txt

We also recommend to install *ipdb* but it's on your own::

   $ pip install ipdb

Congratulations, you are ready to run test suite


Run aiohhtp test suite
----------------------

After all preconditions are done you can run tests::

   $ make test

The command at first will run *flake8* tool (sorry, we don't accept
pull requests with pep8 of pyflakes errors).

On *flake8* success the tests will be run.

Please take a look on produced output.

Any extra texts (print statements and so on) should be removed.


Tests coverage
--------------

We are strongly keeping our test coverage, please don't make it worse.

Use::

   $ make cov

to run test suite and collect coverage information. At the end command
execution prints line like
``open file:///.../aiohttp/coverage/index.html``

Please go to the link and make sure that your code change is good covered.


Documentation
-------------

We are encourage documentation improvements.

Please before making Pull Request about documentation changes do run::

   $ make doc

It's finished by print
``open file:///.../aiohttp/docs/_build/html/index.html``
, like :command:`make cov` does.

Go to the link and make sure your docs change looks good.

The End
-------

After finishing all steps make GutHub Pull Request, thanks.
