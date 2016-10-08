#!/bin/bash
set -e
set -x

if [[ "$(uname -s)" == 'Darwin' ]]; then
  sw_vers
  brew update || brew update

  git clone --depth 1 https://github.com/yyuu/pyenv.git ~/.pyenv
  PYENV_ROOT="$HOME/.pyenv"
  PATH="$PYENV_ROOT/bin:$PATH"
  eval "$(pyenv init -)"

  case "${TOXENV}" in
    py34)
        pyenv install 3.4.5
        pyenv global 3.4.5
        ;;
    py35)
        pyenv install 3.5.2
        pyenv global 3.5.2
        ;;
  esac
  pyenv rehash
  python -m pip install virtualenv
else
  pip install virtualenv
fi

python -m virtualenv ~/.venv
source ~/.venv/bin/activate

python --version
#pip install -U py.test

pip install --upgrade pip wheel
pip install --upgrade setuptools
pip install -r requirements-ci.txt
pip install aiodns
pip install codecov
if python -c "import sys; sys.exit(sys.version_info < (3,5))"; then
  pip install uvloop;
fi
pip install sphinxcontrib-spelling

which py.test
py.test --version
