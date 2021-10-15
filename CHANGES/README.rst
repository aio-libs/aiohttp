.. _Adding change notes with your PRs:

Adding change notes with your PRs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

It is very important to maintain a log for news of how
updating to the new version of the software will affect
end-users. This is why we enforce collection of the change
fragment files in pull requests as per `Towncrier philosophy`_.

The idea is that when somebody makes a change, they must record
the bits that would affect end-users only including information
that would be useful to them. Then, when the maintainers publish
a new release, they'll automatically use these records to compose
a change log for the respective version. It is important to
understand that including unnecessary low-level implementation
related details generates noise that is not particularly useful
to the end-users most of the time. And so such details should be
recorded in the Git history rather than a changelog.

Alright! So how to add a news fragment?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``aiohttp`` uses `towncrier <https://pypi.org/project/towncrier/>`_
for changelog management.
To submit a change note about your PR, add a text file into the
``CHANGES/`` folder. It should contain an
explanation of what applying this PR will change in the way
end-users interact with the project. One sentence is usually
enough but feel free to add as many details as you feel necessary
for the users to understand what it means.

**Use the past tense** for the text in your fragment because,
combined with others, it will be a part of the "news digest"
telling the readers **what changed** in a specific version of
the library *since the previous version*. You should also use
reStructuredText syntax for highlighting code (inline or block),
linking parts of the docs or external sites.
If you wish to sign your change, feel free to add ``-- by
:user:`github-username``` at the end (replace ``github-username``
with your own!).

Finally, name your file following the convention that Towncrier
understands: it should start with the number of an issue or a
PR followed by a dot, then add a patch type, like ``feature``,
``doc``, ``misc`` etc., and add ``.rst`` as a suffix. If you
need to add more than one fragment, you may add an optional
sequence number (delimited with another period) between the type
and the suffix.

In general the name will follow ``<pr_number>.<category>.rst`` pattern,
where the categories are:

- ``feature``: Any new feature
- ``bugfix``: A bug fix
- ``doc``: A change to the documentation
- ``misc``: Changes internal to the repo like CI, test and build changes
- ``removal``: For deprecations and removals of an existing feature or behavior

A pull request may have more than one of these components, for example
a code change may introduce a new feature that deprecates an old
feature, in which case two fragments should be added. It is not
necessary to make a separate documentation fragment for documentation
changes accompanying the relevant code changes.

Examples for adding changelog entries to your Pull Requests
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

File :file:`CHANGES/6045.doc.1.rst`:

.. code-block:: rst

    Added a ``:user:`` role to Sphinx config -- by :user:`webknjaz`

File :file:`CHANGES/4431.bugfix.rst`:

.. code-block:: rst

    Fixed HTTP client requests to honor ``no_proxy`` environment
    variables -- by :user:`scirelli`

File :file:`CHANGES/4594.feature.rst`:

.. code-block:: rst

    Added support for ``ETag`` to :py:class:`~aiohttp.web.FileResponse`
    -- by :user:`greshilov`, :user:`serhiy-storchaka` and :user:`asvetlov`

.. tip::

   See :file:`pyproject.toml` for all available categories
   (``tool.towncrier.type``).

.. _Towncrier philosophy:
   https://towncrier.readthedocs.io/en/actual-freaking-docs/#philosophy
