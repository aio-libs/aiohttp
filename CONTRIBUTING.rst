Instructions for contributors
-----------------------------

In order to make a clone of the `GitHub <https://github.com/aio-libs/aiohttp>`_ repo: open the link and press the "Fork" button on the upper-right menu of the web page.

If you'd like to learn more about Git and GitHub, `check out GitHub's helpful introduction
<https://docs.github.com/en/get-started/using-git/about-git>`_.

Workflow is pretty straightforward:

  0. Make sure you are reading the latest version of this document.
     It can be found in the GitHub_ repo in the ``docs`` subdirectory.

  1. Clone your forked GitHub_ repo with the ``--recurse-submodules`` flag as shown in the command below,
     ensuring to replace the placeholder with your github username:

      .. code-block:: shell

         $ git clone \
            https://github.com/<your_github_username>/aiohttp.git \
            --recurse-submodules


  2. Setup your machine with the required development environment

  3. Make a change

  4. Make sure all tests passed

  5. Add a file into the ``CHANGES`` folder (see `Changelog update <CHANGES>`_ for how).

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

.. export-point-instructions-for-contributors
