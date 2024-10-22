LLHTTP
------

When building aiohttp from source, there is a pure Python parser used by default.
For better performance, you may want to build the higher performance C parser.

To build this ``llhttp`` parser, first get/update the submodules (to update to a
newer release, add ``--remote``)::

    git submodule update --init --recursive

Then build ``llhttp``::

    cd vendor/llhttp/
    npm ci
    make

Then build our parser::

    cd -
    make cythonize

Then you can build or install it with ``python -m build`` or ``pip install -e .``
