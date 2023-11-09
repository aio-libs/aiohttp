Contributing
============

Instructions for contributors
-----------------------------


In order to make a clone of the GitHub_ repo: open the link and press the
"Fork" button on the upper-right menu of the web page.

I hope everybody knows how to work with git and github nowadays :)

Workflow is pretty straightforward:

  1. Clone the GitHub_ repo using the ``--recurse-submodules`` argument

  2. Setup your machine with the required development environment

  3. Make a change

  4. Make sure all tests passed

  5. Add a file into the ``CHANGES`` folder, named after the ticket or PR number

  6. Commit changes to your own aiohttp clone

  7. Make a pull request from the github page of your clone against the master branch

  8. Optionally make backport Pull Request(s) for landing a bug fix into released aiohttp versions.

.. important::

    Please open the "`contributing <https://docs.aiohttp.org/en/stable/contributing.html>`_"
    documentation page to get detailed information about all steps.

.. _GitHub: https://github.com/aio-libs/aiohttp
