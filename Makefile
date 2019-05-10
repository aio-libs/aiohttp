# Some simple testing tasks (sorry, UNIX only).

PYXS = $(wildcard aiohttp/*.pyx)

all: test

.install-cython:
	pip install -r requirements/cython.txt
	touch .install-cython

aiohttp/%.c: aiohttp/%.pyx
	cython -3 -o $@ $< -I aiohttp

cythonize: .install-cython $(PYXS:.pyx=.c)

.install-deps: cythonize $(shell find requirements -type f)
	pip install -r requirements/dev.txt
	@touch .install-deps

isort:
	isort -rc aiohttp
	isort -rc tests
	isort -rc examples

flake: .flake

.flake: .install-deps $(shell find aiohttp -type f) \
                      $(shell find tests -type f) \
                      $(shell find examples -type f)
	flake8 aiohttp examples tests
	python setup.py check -rms
	@if ! isort -c -rc aiohttp tests examples; then \
            echo "Import sort errors, run 'make isort' to fix them!!!"; \
            isort --diff -rc aiohttp tests examples; \
            false; \
	fi
	@if ! LC_ALL=C sort -c CONTRIBUTORS.txt; then \
            echo "CONTRIBUTORS.txt sort error"; \
	fi
	@touch .flake

check_changes:
	./tools/check_changes.py

mypy: .flake
	if python -c "import sys; sys.exit(sys.implementation.name!='cpython')"; then \
            mypy aiohttp; \
	fi

.develop: .install-deps $(shell find aiohttp -type f) .flake check_changes mypy
	# pip install -e .
	@touch .develop

test: .develop
	@pytest -c pytest.ci.ini -q

vtest: .develop
	@pytest -c pytest.ci.ini -s -v

cov cover coverage:
	tox

cov-dev: .develop
	@pytest -c pytest.ci.ini --cov-report=html
	@echo "open file://`pwd`/htmlcov/index.html"

cov-ci-run: .develop
	@echo "Regular run"
	@pytest -c pytest.ci.ini --cov-report=html

cov-dev-full: cov-ci-run
	@echo "open file://`pwd`/htmlcov/index.html"

clean:
	@rm -rf `find . -name __pycache__`
	@rm -f `find . -type f -name '*.py[co]' `
	@rm -f `find . -type f -name '*~' `
	@rm -f `find . -type f -name '.*~' `
	@rm -f `find . -type f -name '@*' `
	@rm -f `find . -type f -name '#*#' `
	@rm -f `find . -type f -name '*.orig' `
	@rm -f `find . -type f -name '*.rej' `
	@rm -f .coverage
	@rm -rf htmlcov
	@rm -rf build
	@rm -rf cover
	@make -C docs clean
	@python setup.py clean
	@rm -f aiohttp/_frozenlist.html
	@rm -f aiohttp/_frozenlist.c
	@rm -f aiohttp/_frozenlist.*.so
	@rm -f aiohttp/_frozenlist.*.pyd
	@rm -f aiohttp/_http_parser.html
	@rm -f aiohttp/_http_parser.c
	@rm -f aiohttp/_http_parser.*.so
	@rm -f aiohttp/_http_parser.*.pyd
	@rm -f aiohttp/_multidict.html
	@rm -f aiohttp/_multidict.c
	@rm -f aiohttp/_multidict.*.so
	@rm -f aiohttp/_multidict.*.pyd
	@rm -f aiohttp/_websocket.html
	@rm -f aiohttp/_websocket.c
	@rm -f aiohttp/_websocket.*.so
	@rm -f aiohttp/_websocket.*.pyd
	@rm -f aiohttp/_parser.html
	@rm -f aiohttp/_parser.c
	@rm -f aiohttp/_parser.*.so
	@rm -f aiohttp/_parser.*.pyd
	@rm -rf .tox
	@rm -f .develop
	@rm -f .flake
	@rm -f .install-deps
	@rm -rf aiohttp.egg-info

doc:
	@make -C docs html SPHINXOPTS="-W -E"
	@echo "open file://`pwd`/docs/_build/html/index.html"

doc-spelling:
	@make -C docs spelling SPHINXOPTS="-W -E"

install:
	@pip install -U pip
	@pip install -Ur requirements/dev.txt

.PHONY: all build flake test vtest cov clean doc
