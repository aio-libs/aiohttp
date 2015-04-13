.. _aiohttp-contributing:

Contributing
============

.. _GitHub: https://github.com/KeepSafe/aiohttp

Instructions for contributors
-----------------------------


In order to make a clone of the GitHub_ repo: open the link and press the
"Fork" button on the upper-right menu of the web page.

I hope everybody knows how to work with git and github nowadays :)

Make a change.

**But**, before sending a pull request please at least run the test suite.

Preconditions for running aiohttp test suite
--------------------------------------------

We expect you to use a python virtual environment to run our tests.

There are several ways to make a virtual environment.

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
now: create a python3 virtual environment and activate it.

After that please install libraries required for development::

   $ pip install -r requirements-dev.txt

We also recommend to install *ipdb* but it's on your own::

   $ pip install ipdb

Congratulations, you are ready to run the test suite


Run aiohttp test suite
----------------------

After all the preconditions are met you can run tests typing the next
command::

   $ make test

The command at first will run the *flake8* tool (sorry, we don't accept
pull requests with pep8 or pyflakes errors).

On *flake8* success the tests will be run.

Please take a look on the produced output.

Any extra texts (print statements and so on) should be removed.


Tests coverage
--------------

We are trying hard to have good test coverage; please don't make it worse.

Use::

   $ make cov

to run test suite and collect coverage information. Once the command
has finished check your coverage at the file that appears in the last
line of the output:
``open file:///.../aiohttp/coverage/index.html``

Please go to the link and make sure that your code change is covered.


Documentation
-------------

We encourage documentation improvements.

Please before making a Pull Request about documentation changes run::

   $ make doc

Once it finishes it will output the index html page
``open file:///.../aiohttp/docs/_build/html/index.html``
, like :command:`make cov` does.

Go to the link and make sure your doc changes looks good.

The End
-------

After finishing all steps make a GitHub_ Pull Request, thanks.
