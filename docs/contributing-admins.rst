:orphan:

Instructions for aiohttp admins
===============================

This page is intended to document certain processes for admins of the aiohttp repository.
For regular contributors, return to :doc:`contributing`.

.. contents::
   :local:

Running reproducer code
-----------------------

.. warning::

   When evaluating a bug report or vulnerability report, treat reproducer code as
   untrusted. If you don't understand what it does or are unfamiliar with a library
   it imports *do not run it* (and ask the reporter to provide a simpler reproducer).
   We also recommend that any reproducers you do run are executed in a container.

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
   things outside the changelog). Use `git checkout 3.9 path/to/file` to revert files
   without aborting the merge.
#. To ensure change fragments are cleaned up properly, run: ``python tools/cleanup_changes.py``
#. Complete the merge: `git merge --continue`.
#. Push the branch directly to Github (because a PR would get squashed). When pushing,
   you may get a rejected message. Follow these steps to resolve:

  #. Checkout to a new branch and push: e.g. ``git checkout -b do-not-merge && git push``
  #. Open a *draft* PR with a title of 'DO NOT MERGE'.
  #. Once the CI has completed on that branch, you should be able to switch back and push
     the target branch (as tests have passed on the merge commit now).
  #. This should automatically consider the PR merged and delete the temporary branch.

Back on the original release branch, bump the version number and append ``.dev0`` in ``__init__.py``.

Post the release announcement to social media:
 - BlueSky: https://bsky.app/profile/aiohttp.org and re-post to https://bsky.app/profile/aio-libs.org
 - Mastodon: https://fosstodon.org/@aiohttp and re-post to https://fosstodon.org/@aio_libs

If doing a minor release:

#. Create a new release branch for future features to go to: e.g. ``git checkout -b 3.10 3.9 && git push``
#. Update both ``target-branch`` backports for Dependabot to reference the new branch name in ``.github/dependabot.yml``.
#. Delete the older backport label (e.g. backport-3.8): https://github.com/aio-libs/aiohttp/labels
#. Add a new backport label (e.g. backport-3.10).

Incident response
-----------------

This section covers responding to a reported security vulnerability and to
three classes of compromise -- of the supply chain, of a maintainer account,
and of the project infrastructure. It picks up *after* a report or a problem
is in hand.

.. note::

   Vulnerability reports arrive through the aio-libs organization ``SECURITY.md``
   -- GitHub private vulnerability reporting, or email to the security coordinators.
   Never triage a suspected vulnerability in a public issue or pull request.

The security coordinator who first triages a report is its *incident lead*,
and may explicitly hand off to another coordinator. The lead owns the GitHub
Security Advisory (GHSA) draft, fix coordination, the release, and notification.

Severity tiers
~~~~~~~~~~~~~~

aiohttp is volunteer-maintained, so there is no response-time commitment. The
tier guides prioritization, the release decision, and how widely the fix is
announced. All security fixes -- regardless of tier -- land on ``master`` and
are backported to the currently supported ``x.y`` branch (and the next
``x.y`` branch, if one is in development).

High
   A concrete remote impact an attacker can actually achieve against a
   default deployment. Examples: a single request that stops the server from
   handling further requests (a server-wide denial of service), reading files
   on the server outside the project root, remote code execution,
   authentication bypass. Cut a dedicated security release once the fix lands.

Medium
   Bounded impact, or impact that needs a non-default option, an unusual
   configuration, or a local position. Examples: request smuggling demonstrated
   to cause a real issue against a common proxy, or a DoS that use significant server
   resources with a low effort sustained attack.
   Cut a dedicated security release.

Low
   Limited or hard-to-exploit impact, or impact confined to debug or
   non-default paths. Examples: minor version or error-message disclosure,
   parser leniency with no demonstrated security impact, or request smuggling
   that has not been demonstrated to cause a real issue against a common
   proxy. May ride the next routine release rather than cutting a dedicated
   security release.

Severity is rated by demonstrated attacker impact. A denial of service that
disables further request handling for the whole server from a single request
leans High; one that requires sustained low-effort traffic to consume
significant server resources leans Medium. Request smuggling and parser bugs
are rated by what an attacker can actually achieve against a common proxy or
in a realistic deployment, not by the shape of the bug.

Responding to a reported vulnerability
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. **Acknowledge and confirm.** Reply to the reporter in the GitHub private
   report or the email thread. Reproduce the issue
   (`but don't run untrusted code <Running reproducer code_>`_) against
   ``master`` and the maintained ``x.y`` branches. If it is not reproducible
   or is out of scope, record the decision and close the report.
#. **Open the GHSA draft.** For an email report, if the reporter can't use Github
   for some reason, then open a new advisory to track the issue.
#. **Develop the fix privately** in the GHSA's temporary private fork ("Start a
   temporary private fork" in the draft) -- never on a public branch or in a
   public pull request. Include a regression test unless it would provide too
   much information for an attacker to replicate.
#. **Title the advisory** with the vulnerability class and affected component.
#. **Write the description** using the GHSA description template::

      ### Summary

      <one or two sentences describing the vulnerability>

      ### Impact

      <who is affected, prerequisites, and what an attacker achieves>

      ### Workaround

      <if relevant, any workarounds for users unable to upgrade>

      ---

      Patch: <link to commit fixing the issue on the stable x.y branch>

   An important detail that Github will use to decide the CVE severity is exploit
   maturity. Try to clarify the likelihood of a vulnerability being attacked
   (e.g. if exploit code is available, or active attacks in-the-wild already exist).
#. **Set the affected and fixed versions**.
#. **Assign a severity tier** (see `Severity tiers`_).
#. **Credit the reporter** (if report came by email) in the GHSA Credits field.
#. **Credit the developer** using "Remediation developer" if different from Reporter.
#. **Request a CVE** by clicking the button in the advisory.
#. **Get the fix reviewed** in the private fork by at least one other maintainer.
#. **Consider early notify** for high severity issues
   (see `Notifying about a disclosed vulnerability`_).
#. **Coordinate a release.**

  #. **Agree the timing.** For an embargoed high-severity incident, set the
     release date to align with the lift of any private-list embargo.
  #. **Merge all the private forks** and create and merge the backports for each.
  #. **Create the release.** Follow `Creating a new release`_.
#. **Update patch link** in GHSA description.
#. **Publish the GHSA** usually around 1 day after release.
#. **Notify** according to the severity tier
   (see `Notifying about a disclosed vulnerability`_).
#. **Run the post-incident steps** (see `Post-incident`_).

Notifying about a disclosed vulnerability
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Notification is cumulative -- each tier adds to the ones below it. Mind the
timing: the ``linux-distros`` pre-notification happens under embargo, *before*
the release, while everything else happens at or after the release.

Baseline (all severities)
   The published GHSA (which feeds the CVE and the GitHub Advisory Database).

Higher (Medium-High)
   For most high severity issues, additionally post to the public oss-security
   mailing list once the advisory is public.

Highest (High-Critical)
   For the most serious issues, additionally *before* the public release, send
   an embargoed pre-notification to the private distribution-security lists -- primarily
   ``linux-distros`` -- and attempt to notify affected downstreams. Use the
   `vuln_search.py dependents-enumeration script
   <https://gist.github.com/Dreamsorcerer/70285fac0a11c3d9c26b577f7dd989a7>`_
   to search aiohttp's GitHub dependents; it needs a GitHub token and may need to be
   run over a few days, so start it early.

Keep the embargo as short as practical. Typically an embargo of 1 or 2 days is expected.

Template for the embargoed ``linux-distros`` pre-notification::

    To: linux-distros@vs.openwall.org
    Subject: aiohttp: <one-line summary of the vulnerability>

    We are coordinating disclosure of a security vulnerability in aiohttp
    (https://github.com/aio-libs/aiohttp), the asyncio HTTP client/server
    library.

    Summary
      <2-3 sentences: the flaw and its impact>

    Affected versions
      <e.g. aiohttp < 3.12.15 (all 3.11.x and 3.12.x)>

    CVE
      <CVE-XXXX-XXXXX, or "requested via GitHub Security Advisory, ID pending">

    Fix
      <link to the patch, or attach the diff>

    Proposed public disclosure date
      <YYYY-MM-DD> -- as short as practical. On that date we will publish the
      GitHub Security Advisory, ship a patched PyPI release, and post to
      oss-security.

    This issue is not yet public; please observe the embargo until that date.

    Contact: <incident lead name and security email>

Template for the public oss-security disclosure::

    To: oss-security@lists.openwall.com
    Subject: CVE-XXXX-XXXXX: aiohttp <one-line summary>

    A security vulnerability has been fixed in aiohttp, the asyncio HTTP
    client/server library (https://github.com/aio-libs/aiohttp).

    CVE: CVE-XXXX-XXXXX
    Advisory: <GHSA URL>

    Affected versions: <...>
    Fixed versions:    <...>

    Description
      <what the flaw is>

    Impact
      <what an attacker can achieve, and any prerequisites>

    Mitigation
      <workaround, or "upgrade to <version>">

Post-incident
~~~~~~~~~~~~~

#. **Update** ``THREAT_MODEL.md``. Have an AI coding agent fetch the new advisories
   and update the document. Review the changes.
#. **File follow-up hardening** as ordinary public issues or pull requests.

Supply-chain or release compromise
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A malicious or tampered release on PyPI, or a compromised publish pipeline.

#. **Pull the bad artifact.** On PyPI, *yank* the affected release -- this
   hides it from new resolves while keeping existing pins working. *Delete* it
   only if it is actively malicious and removal is the safer choice. This needs
   a PyPI project owner or maintainer account.
#. **Verify the legitimate artifacts with Sigstore.** Every genuine release is
   signed by the release pipeline, with the ``.sigstore`` bundles attached to
   the GitHub Release. Verify the sdist and wheels; a divergence from what is on
   PyPI localizes the tampering.
#. **Lock the publish path.** Publishing uses a PyPI OIDC trusted publisher, so
   there is no long-lived token to rotate. Instead, on PyPI temporarily remove
   the trusted-publisher binding, and on GitHub restrict or pause the ``pypi``
   deployment environment used by the release job.
#. **Audit the release inputs.** Review recent changes to the release workflow,
   its tag trigger, and the third-party action versions it uses.
#. **Audit the committed Cython sources.** The generated ``.c`` files ship in
   the sdist and are not checked against their ``.pyx`` sources in CI (see
   ``THREAT_MODEL.md`` section 5.19). Regenerate them with ``make cythonize``
   and ``git diff`` against the released revision. Re-verify the
   ``vendor/llhttp`` submodule pin and ``package-lock.json``.
#. **Reissue a clean release** via `Creating a new release`_ once the cause is
   fixed. Never re-publish over a yanked version number.
#. **Notify** per severity -- a malicious published release is High.

Maintainer account compromise
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A GitHub or PyPI account takeover, or leaked publishing or signing material.

#. **Suspend the account.** Another GitHub organization owner can suspend it,
   revoke its repository access, and start the audit-log review. If the
   compromised account is the sole organization owner, or no other owner is
   reachable, contact GitHub Support at https://support.github.com/contact
   for emergency account lockdown and organization recovery.
#. **Kill sessions and credentials** on the affected account. On GitHub: change
   the password, sign out all sessions, revoke every personal access token,
   OAuth app, and SSH or GPG key, then re-enroll two-factor authentication.
   On PyPI: change the password, re-enroll two-factor authentication,
   and revoke API tokens.
#. **Audit PyPI project ownership.** OIDC publishing means there is usually no
   long-lived PyPI token to leak, but a compromised project owner can add a
   trusted publisher or upload directly. Review the project collaborators and
   trusted-publisher bindings, and remove anything unrecognized.
#. **Audit what the account could have done** from the GitHub audit log:
   pushes, tag creation, branch-protection or settings changes, new secrets or
   deploy keys, new collaborators, and workflow edits.
#. **Revert and re-verify.** Force-revert any unauthorized commits or tags, and
   re-verify recent releases against their Sigstore bundles. If a malicious
   release shipped, escalate to `Supply-chain or release compromise`_.
#. **Handle signing material.** Sigstore signing is keyless, so there is no
   static signing key to rotate. Any separate GPG key used for signed tags must
   be treated as compromised, then revoked and rotated.

CI or infrastructure compromise
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A compromise of GitHub Actions, repository settings, or branch protections.

#. **Freeze the release path.** Pause the ``pypi`` deployment environment and
   stop tag-triggered deploys until the compromise is scoped.
#. **Review branch protection and required reviews** on ``master`` and the
   ``x.y`` branches. These are enforced on GitHub and are not visible in the
   repository; confirm nothing was relaxed and restore the known-good
   configuration.
#. **Audit Actions secrets and environments** -- the repository and
   organization secrets, the ``pypi`` environment's protection rules and
   reviewers, and any new deploy keys. Confirm the workflow keeps empty
   top-level permissions and that ``id-token: write`` is scoped to the deploy
   job only.
#. **Diff recently changed workflows** with ``git log -- .github/workflows/``,
   especially the release workflow, the auto-merge workflow (which runs in the
   privileged ``pull_request_target`` context), and the CodeQL workflow. Look
   for added steps, changed action references, or new triggers.
#. **Check the committed Cython sources** as in `Supply-chain or release
   compromise`_ -- regenerate them and ``git diff``.
#. **Re-pin and rebuild.** If a third-party action was compromised, pin the
   affected actions by full commit hash, re-run CI from a clean known-good
   revision, and re-verify with Sigstore any release made during the suspected
   window.
#. **Escalate** to `Supply-chain or release compromise`_ if a release shipped
   through the compromised pipeline.
