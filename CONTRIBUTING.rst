Contributing
============

Instructions for contributors
-----------------------------


In order to make a clone of the GitHub_ repo: open the link and press the
"Fork" button on the upper-right menu of the web page.

I hope everybody knows how to work with git and github nowadays :)

Workflow is pretty straightforward:

Clone the Repository:
- 1.Open the provided GitHub link and click the "Fork" button on the upper-right of the web page to create your fork.
- 2.Clone your forked repository using the --recurse-submodules argument to ensure submodules are also cloned.

Set Up Development Environment:
- 1.Configure your machine with the necessary development environment as specified in the project's documentation.

Make Changes:
- 1.Implement the desired changes in your local clone.

Run Tests:
- 1.Ensure all tests pass before proceeding to the next step.

Update Changes File:
- 1.Add a file to the CHANGES folder, naming it after the ticket or pull request number.

Commit Changes:
- 1.Commit your changes to your own aiohttp clone.

Create Pull Request:
- 1.Make a pull request from the GitHub page of your clone against the master branch of the original repository.
Optional Backport:

Optionally, create backport pull requests if you are fixing a bug that needs to be applied to released aiohttp versions.

.. important::

    Please open the "`contributing <https://docs.aiohttp.org/en/stable/contributing.html>`_"
    documentation page to get detailed information about all steps.

.. _GitHub: https://github.com/aio-libs/aiohttp
