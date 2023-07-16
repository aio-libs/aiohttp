LLHTTP
======

To build the llhttp parser, first get/update the submodule (to update to a
newer release, add ``--remote`` and check the branch in .gitmodules):

    git submodule update --init --recursive

Then build llhttp:

    cd vendor/llhttp/
    npm install
    make

Then build our parser:

    cd -
    make cythonize

Then you can build or install it with ``python -m build`` or ``pip install .``
