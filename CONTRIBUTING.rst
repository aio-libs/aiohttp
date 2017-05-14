Contributing
============

Instructions for contributors
-----------------------------


In order to make a clone of the GitHub_ repo: open the link and press the
"Fork" button on the upper-right menu of the web page.

I hope everybody knows how to work with git and github nowadays :)

Workflow is pretty straightforward:

  1. Clone the GitHub_ repo

  2. Make a change

  3. Make sure all tests passed

  4. Commit changes to own aiohttp clone

  5. Make pull request from github page for your clone against master branch

  .. note::
     If your PR has long history or many commits
     please rebase it from main repo before creating PR.

Preconditions for running aiohttp test suite
--------------------------------------------

We expect you to use a python virtual environment to run our tests.

There are several ways to make a virtual environment.

If you like to use *virtualenv* please run:

.. code-block:: shell

   $ cd aiohttp
   $ virtualenv --python=`which python3` venv
   $ . venv/bin/activate

For standard python *venv*:

.. code-block:: shell

   $ cd aiohttp
   $ python3 -m venv venv
   $ . venv/bin/activate

For *virtualenvwrapper* (my choice):

.. code-block:: shell

   $ cd aiohttp
   $ mkvirtualenv --python=`which python3` aiohttp

There are other tools like *pyvenv* but you know the rule of thumb
now: create a python3 virtual environment and activate it.

After that please install libraries required for development:

.. code-block:: shell

   $ pip install -r requirements-dev.txt

We also recommend to install ipdb_ but it's on your own:

.. code-block:: shell

   $ pip install ipdb

.. note::
  If you plan to use ``ipdb`` within the test suite, execute:

.. code-block:: shell

    $ py.test tests -s -p no:timeout

  command to run the tests with disabled timeout guard and output
  capturing.

Congratulations, you are ready to run the test suite


Run aiohttp test suite
----------------------

After all the preconditions are met you can run tests typing the next
command:

.. code-block:: shell

   $ make test

The command at first will run the *flake8* tool (sorry, we don't accept
pull requests with pep8 or pyflakes errors).

On *flake8* success the tests will be run.

Please take a look on the produced output.

Any extra texts (print statements and so on) should be removed.


Tests coverage
--------------

We are trying hard to have good test coverage; please don't make it worse.

Use:

.. code-block:: shell

   $ make cov

to run test suite and collect coverage information. Once the command
has finished check your coverage at the file that appears in the last
line of the output:
``open file:///.../aiohttp/coverage/index.html``

Please go to the link and make sure that your code change is covered.


Documentation
-------------

We encourage documentation improvements.

Please before making a Pull Request about documentation changes run:

.. code-block:: shell

   $ make doc

Once it finishes it will output the index html page
``open file:///.../aiohttp/docs/_build/html/index.html``.

Go to the link and make sure your doc changes looks good.

Spell checking
--------------

We use ``pyenchant`` and ``sphinxcontrib-spelling`` for running spell
checker for documentation:

.. code-block:: shell

   $ make doc-spelling

Unfortunately there are problems with running spell checker on MacOS X.

To run spell checker on Linux box you should install it first:

.. code-block:: shell

   $ sudo apt-get install enchant
   $ pip install sphinxcontrib-spelling

The End
-------

After finishing all steps make a GitHub_ Pull Request, thanks.


.. _GitHub: https://github.com/aio-libs/aiohttp

.. _ipdb: https://pypi.python.org/pypi/ipdb
