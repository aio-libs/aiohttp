# Some simple testing tasks (sorry, UNIX only).

PYXS = $(wildcard aiohttp/*.pyx)
SRC = aiohttp examples tests setup.py

.PHONY: all
all: test

.install-cython:
	pip install -r requirements/cython.txt
	touch .install-cython

aiohttp/%.c: aiohttp/%.pyx
	cython -3 -o $@ $< -I aiohttp

.PHONY: cythonize
cythonize: .install-cython $(PYXS:.pyx=.c)

.install-deps: cythonize $(shell find requirements -type f)
	pip install -r requirements/dev.txt
	@touch .install-deps

.PHONY: lint
lint: isort-check black-check flake8 mypy


.PHONY: black-check
black-check:
	black --check $(SRC)

.PHONY: isort
isort:
	isort $(SRC)

.PHONY: fmt format
fmt format:
	isort $(SRC)
	black $(SRC)
	pre-commit run --all-files


.PHONY: flake
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


.PHONY: flake8
flake8:
	flake8 $(SRC)

.PHONY: mypy
mypy: .flake
	mypy aiohttp

.PHONY: isort-check
isort-check:
	@if ! isort --check-only $(SRC); then \
            echo "Import sort errors, run 'make isort' to fix them!!!"; \
            isort --diff $(SRC); \
            false; \
	fi

.PHONY: check_changes
check_changes:
	./tools/check_changes.py

.develop: .install-deps $(shell find aiohttp -type f) .flake check_changes mypy
	# pip install -e .
	@touch .develop

.PHONY: test
test: .develop
	@pytest -q

.PHONY: vtest
vtest: .develop
	@pytest -s -v

.PHONY: cov cover coverage
cov cover coverage:
	tox

.PHONY: cov-dev
cov-dev: .develop
	@pytest --cov-report=html
	@echo "open file://`pwd`/htmlcov/index.html"

.PHONY: cov-ci-run
cov-ci-run: .develop
	@echo "Regular run"
	@pytest --cov-report=html

.PHONY: cov-dev-full
cov-dev-full: cov-ci-run
	@echo "open file://`pwd`/htmlcov/index.html"

.PHONY: clean
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

.PHONY: doc
doc:
	@make -C docs html SPHINXOPTS="-W -E"
	@echo "open file://`pwd`/docs/_build/html/index.html"

.PHONY: doc-spelling
doc-spelling:
	@make -C docs spelling SPHINXOPTS="-W -E"

.PHONY: install
install:
	@pip install -U 'pip'
	@pip install -Ur requirements/dev.txt

.PHONY: install-dev
install-dev: .develop
