# Some simple testing tasks (sorry, UNIX only).

PYXS = $(wildcard aiohttp/*.pyx)
SRC = aiohttp examples tests setup.py

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

lint: flake8 mypy isort-check


isort:
	isort $(SRC)

flake: .flake

.flake: .install-deps $(shell find aiohttp -type f) \
                      $(shell find tests -type f) \
                      $(shell find examples -type f)
	flake8 aiohttp examples tests
	@if ! isort -c aiohttp tests examples; then \
            echo "Import sort errors, run 'make isort' to fix them!!!"; \
            isort --diff aiohttp tests examples; \
            false; \
	fi
	@if ! LC_ALL=C sort -c CONTRIBUTORS.txt; then \
            echo "CONTRIBUTORS.txt sort error"; \
	fi
	@touch .flake


flake8:
	flake8 $(SRC)

mypy: .flake
	mypy aiohttp

isort-check:
	@if ! isort --check-only $(SRC); then \
            echo "Import sort errors, run 'make isort' to fix them!!!"; \
            isort --diff $(SRC); \
            false; \
	fi

check_changes:
	./tools/check_changes.py

.develop: .install-deps $(shell find aiohttp -type f) .flake check_changes mypy
	# pip install -e .
	@touch .develop

test: .develop
	@pytest -q

vtest: .develop
	@pytest -s -v

cov cover coverage:
	tox

cov-dev: .develop
	@pytest --cov-report=html
	@echo "open file://`pwd`/htmlcov/index.html"

cov-ci-run: .develop
	@echo "Regular run"
	@pytest --cov-report=html

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
	@pip install -U 'pip'
	@pip install -Ur requirements/dev.txt

.PHONY: all build flake test vtest cov clean doc mypy
