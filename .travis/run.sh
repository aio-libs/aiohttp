#!/bin/bash
set -e
set -x

if [[ "$(uname -s)" == "darwin" ]]; then
    # initialize our pyenv
    pyenv_root="$home/.pyenv"
    path="$pyenv_root/bin:$path"
    eval "$(pyenv init -)"
fi

source ~/.venv/bin/activate

make cov-dev-full
