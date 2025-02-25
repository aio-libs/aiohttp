:orphan:

Instructions for aiohttp admins
===============================

This page is intended to document certain processes for admins of the aiohttp repository.
For regular contributors, return to :doc:`contributing`.

.. contents::
   :local:

Creating a new release
----------------------

.. note:: The example commands assume that ``origin`` refers to the ``aio-libs`` repository.

To create a new release:

#. Start on the branch for the release you are planning (e.g. ``3.8`` for v3.8.6): ``git checkout 3.8 && git pull``
#. Update the version number in ``__init__.py``.
#. Run ``towncrier``.
#. Check and cleanup the changes in ``CHANGES.rst``.
#. Checkout a new branch: e.g. ``git checkout -b release/v3.8.6``
#. Commit and create a PR. Verify the changelog and release notes look good on Read the Docs. Once PR is merged, continue.
#. Go back to the release branch: e.g. ``git checkout 3.8 && git pull``
#. Add a tag: e.g. ``git tag -a v3.8.6 -m 'Release 3.8.6' -s``
#. Push the tag: e.g. ``git push origin v3.8.6``
#. Monitor CI to ensure release process completes without errors.

Once released, we need to complete some cleanup steps (no further steps are needed for
non-stable releases though). If doing a patch release, we need to do the below steps twice,
first merge into the newer release branch (e.g. 3.8 into 3.9) and then to master
(e.g. 3.9 into master). If a new minor release, then just merge to master.

#. Switch to target branch: e.g. ``git checkout 3.9 && git pull``
#. Start a merge: e.g. ``git merge 3.8 --no-commit --no-ff --gpg-sign``
#. Carefully review the changes and revert anything that should not be included (most
   things outside the changelog).
#. To ensure change fragments are cleaned up properly, run: ``python tools/cleanup_changes.py``
#. Commit the merge (must be a normal merge commit, not squashed).
#. Push the branch directly to Github (because a PR would get squashed). When pushing,
   you may get a rejected message. Follow these steps to resolve:

  #. Checkout to a new branch and push: e.g. ``git checkout -b do-not-merge && git push``
  #. Open a *draft* PR with a title of 'DO NOT MERGE'.
  #. Once the CI has completed on that branch, you should be able to switch back and push
     the target branch (as tests have passed on the merge commit now).
  #. This should automatically consider the PR merged and delete the temporary branch.

Back on the original release branch, bump the version number and append ``.dev0`` in ``__init__.py``.

Post the release announcement to social media.

If doing a minor release:

#. Create a new release branch for future features to go to: e.g. ``git checkout -b 3.10 3.9 && git push``
#. Update both ``target-branch`` backports for Dependabot to reference the new branch name in ``.github/dependabot.yml``.
#. Delete the older backport label (e.g. backport-3.8): https://github.com/aio-libs/aiohttp/labels
#. Add a new backport label (e.g. backport-3.10).
