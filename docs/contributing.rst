.. _aiohttp-contributing:

Contributing
============

Instructions for contributors
-----------------------------

In order to make a clone of the GitHub_ repo: open the link and press the "Fork" button on the upper-right menu of the web page.

I hope everybody knows how to work with git and github nowadays :)

Workflow is pretty straightforward:

  0. Make sure you are reading the latest version of this document.
     It can be found in the GitHub_ repo in the ``docs`` subdirectory.

  1. Clone the GitHub_ repo using the ``--recurse-submodules`` argument

  2. Setup your machine with the required dev environment

  3. Make a change

  4. Make sure all tests passed

  5. Add a file into the ``CHANGES`` folder (see `Changelog update`_ for how).

  6. Commit changes to your own aiohttp clone

  7. Make a pull request from the github page of your clone against the master branch

  8. Optionally make backport Pull Request(s) for landing a bug fix into released aiohttp versions.

.. note::

   The project uses *Squash-and-Merge* strategy for *GitHub Merge* button.

   Basically it means that there is **no need to rebase** a Pull Request against
   *master* branch. Just ``git merge`` *master* into your working copy (a fork) if
   needed. The Pull Request is automatically squashed into the single commit
   once the PR is accepted.

.. note::

   GitHub issue and pull request threads are automatically locked when there has
   not been any recent activity for one year.  Please open a `new issue
   <https://github.com/aio-libs/aiohttp/issues/new>`_ for related bugs.

   If you feel like there are important points in the locked discussions,
   please include those excerpts into that new issue.


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

For *virtualenvwrapper*:

.. code-block:: shell

   $ cd aiohttp
   $ mkvirtualenv --python=`which python3` aiohttp

There are other tools like *pyvenv* but you know the rule of thumb now: create a python3 virtual environment and activate it.

After that please install libraries required for development:

.. code-block:: shell

   $ pip install -r requirements/dev.txt

.. note::

  For now, the development tooling depends on ``make`` and assumes an Unix OS If you wish to contribute to aiohttp from a Windows machine, the easiest way is probably to `configure the WSL <https://docs.microsoft.com/en-us/windows/wsl/install-win10>`_ so you can use the same instructions. If it's not possible for you or if it doesn't work, please contact us so we can find a solution together.

Install pre-commit hooks:

.. code-block:: shell

   $ pre-commit install

.. warning::

  If you plan to use temporary ``print()``, ``pdb`` or ``ipdb`` within the test suite, execute it with ``-s``:

  .. code-block:: shell

     $ pytest tests -s

  in order to run the tests without output capturing.

Congratulations, you are ready to run the test suite!


Run autoformatter
-----------------

The project uses black_ + isort_ formatters to keep the source code style.
Please run `make fmt` after every change before starting tests.

  .. code-block:: shell

     $ make fmt


Run aiohttp test suite
----------------------

After all the preconditions are met you can run tests typing the next
command:

.. code-block:: shell

   $ make test

The command at first will run the *linters* (sorry, we don't accept
pull requests with pyflakes, black, isort, or mypy errors).

On *lint* success the tests will be run.

Please take a look on the produced output.

Any extra texts (print statements and so on) should be removed.


Tests coverage
--------------

We are trying hard to have good test coverage; please don't make it worse.

Use:

.. code-block:: shell

   $ make cov-dev

to run test suite and collect coverage information. Once the command
has finished check your coverage at the file that appears in the last
line of the output:
``open file:///.../aiohttp/htmlcov/index.html``

Please go to the link and make sure that your code change is covered.


The project uses *codecov.io* for storing coverage results. Visit
https://codecov.io/gh/aio-libs/aiohttp for looking on coverage of
master branch, history, pull requests etc.

The browser extension https://docs.codecov.io/docs/browser-extension
is highly recommended for analyzing the coverage just in *Files
Changed* tab on *GitHub Pull Request* review page.

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

Changelog update
----------------

The ``CHANGES.rst`` file is managed using `towncrier
<https://github.com/hawkowl/towncrier>`_ tool and all non trivial
changes must be accompanied by a news entry.

To add an entry to the news file, first you need to have created an
issue describing the change you want to make. A Pull Request itself
*may* function as such, but it is preferred to have a dedicated issue
(for example, in case the PR ends up rejected due to code quality
reasons).

Once you have an issue or pull request, you take the number and you
create a file inside of the ``CHANGES/`` directory named after that
issue number with an extension of ``.removal``, ``.feature``,
``.bugfix``, or ``.doc``.  Thus if your issue or PR number is ``1234`` and
this change is fixing a bug, then you would create a file
``CHANGES/1234.bugfix``. PRs can span multiple categories by creating
multiple files (for instance, if you added a feature and
deprecated/removed the old feature at the same time, you would create
``CHANGES/NNNN.feature`` and ``CHANGES/NNNN.removal``). Likewise if a PR touches
multiple issues/PRs you may create a file for each of them with the
exact same contents and *Towncrier* will deduplicate them.

The contents of this file are *reStructuredText* formatted text that
will be used as the content of the news file entry. You do not need to
reference the issue or PR numbers here as *towncrier* will automatically
add a reference to all of the affected issues when rendering the news
file.



Making a Pull Request
---------------------

After finishing all steps make a GitHub_ Pull Request with *master* base branch.


Backporting
-----------

All Pull Requests are created against *master* git branch.

If the Pull Request is not a new functionality but bug fixing
*backport* to maintenance branch would be desirable.

*aiohttp* project committer may ask for making a *backport* of the PR
into maintained branch(es), in this case he or she adds a github label
like *needs backport to 3.1*.

*Backporting* is performed *after* main PR merging into master.
 Please do the following steps:

1. Find *Pull Request's commit* for cherry-picking.

   *aiohttp* does *squashing* PRs on merging, so open your PR page on
   github and scroll down to message like ``asvetlov merged commit
   f7b8921 into master 9 days ago``.  ``f7b8921`` is the required commit number.

2. Run `cherry_picker
   <https://github.com/python/core-workflow/tree/master/cherry_picker>`_
   tool for making backport PR (the tool is already pre-installed from
   ``./requirements/dev.txt``), e.g. ``cherry_picker f7b8921 3.1``.

3. In case of conflicts fix them and continue cherry-picking by
   ``cherry_picker --continue``.

   ``cherry_picker --abort`` stops the process.

   ``cherry_picker --status`` shows current cherry-picking status
   (like ``git status``)

4. After all conflicts are done the tool opens a New Pull Request page
   in a browser with pre-filed information.  Create a backport Pull
   Request and wait for review/merging.

5. *aiohttp* *committer* should remove *backport Git label* after
   merging the backport.

How to become an aiohttp committer
----------------------------------

Contribute!

The easiest way is providing Pull Requests for issues in our bug
tracker.  But if you have a great idea for the library improvement
-- please make an issue and Pull Request.



The rules for committers are simple:

1. No wild commits! Everything should go through PRs.
2. Take a part in reviews. It's very important part of maintainer's activity.
3. Pickup issues created by others, especially if they are simple.
4. Keep test suite comprehensive. In practice it means leveling up
   coverage. 97% is not bad but we wish to have 100% someday. Well, 99%
   is good target too.
5. Don't hesitate to improve our docs. Documentation is very important
   thing, it's the key for project success. The documentation should
   not only cover our public API but help newbies to start using the
   project and shed a light on non-obvious gotchas.



After positive answer aiohttp committer creates an issue on github
with the proposal for nomination.  If the proposal will collect only
positive votes and no strong objection -- you'll be a new member in
our team.


.. _GitHub: https://github.com/aio-libs/aiohttp

.. _ipdb: https://pypi.python.org/pypi/ipdb

.. _black: https://pypi.python.org/pypi/black

.. _isort: https://pypi.python.org/pypi/isort
