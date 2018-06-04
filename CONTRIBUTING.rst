Contributing
============

Instructions for contributors
-----------------------------


In order to make a clone of the GitHub_ repo: open the link and press the
"Fork" button on the upper-right menu of the web page.

I hope everybody knows how to work with git and github nowadays :)

Workflow is pretty straightforward:

  1. Clone the GitHub_ repo using ``--recurse-submodules`` argument

  2. Make a change

  3. Make sure all tests passed

  4. Add a file into ``CHANGES`` folder.

  5. Commit changes to own aiohttp clone

  6. Make pull request from github page for your clone against master branch

  7. Optionally make backport Pull Request(s) for landing a bug fix
     into released aiohttp versions.

Please open https://docs.aiohttp.org/en/stable/contributing.html
documentation page for getting detailed information about all steps.

.. _GitHub: https://github.com/aio-libs/aiohttp
