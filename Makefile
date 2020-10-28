# Some simple testing tasks (sorry, UNIX only).

CYS = $(wildcard aiohttp/*.{pyx,pyi,pxd})
PYXS = $(wildcard aiohttp/*.pyx)
CS = $(wildcard aiohttp/*.c)
PYS = $(wildcard aiohttp/*.py)
REQS = $(wildcard requirements/*.txt)
SRC = aiohttp examples tests setup.py

.PHONY: all
all: test

.install-cython: requirements/cython.txt
	pip install -r requirements/cython.txt
	@touch .install-cython

aiohttp/_find_header.c: aiohttp/hdrs.py
	./tools/gen.py

# _find_headers generator creates _headers.pyi as well
aiohttp/%.c: aiohttp/%.pyx aiohttp/_find_header.c
	cython -3 -o $@ $< -I aiohttp


.PHONY: cythonize
cythonize: .install-cython $(PYXS:.pyx=.c)

.install-deps: .install-cython $(CYS) $(REQS)
	pip install -r requirements/dev.txt
	@touch .install-deps

.PHONY: lint
lint: fmt mypy

.PHONY: fmt format
fmt format: check_changes
	python -m pre_commit run --all-files --show-diff-on-failure

.PHONY: mypy
mypy:
	mypy aiohttp

.PHONY: check_changes
check_changes:
	./tools/check_changes.py


.develop: .install-deps $(PYS) $(CYS) $(CS)
	pip install -e .
	@touch .develop

.PHONY: test
test: .develop
	@pytest -q

.PHONY: vtest
vtest: .develop
	@pytest -s -v

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
	@rm -f aiohttp/*.so
	@rm -f aiohttp/*.pyd
	@rm -f aiohttp/*.html
	@rm -f aiohttp/_frozenlist.c
	@rm -f aiohttp/_find_header.c
	@rm -f aiohttp/_http_parser.c
	@rm -f aiohttp/_http_writer.c
	@rm -f aiohttp/_websocket.c
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
