# Some simple testing tasks (sorry, UNIX only).

to-md5 = $1 $(addsuffix .md5,$1)

CYS = $(wildcard aiohttp/*.pyx) $(wildcard aiohttp/*.pyi)  $(wildcard aiohttp/*.pxd)
PYXS = $(wildcard aiohttp/*.pyx)
CS = $(wildcard aiohttp/*.c)
PYS = $(wildcard aiohttp/*.py)
REQS = $(wildcard requirements/*.txt)
SRC = aiohttp examples tests setup.py

.PHONY: all
all: test

# Recipe from https://www.cmcrossroads.com/article/rebuilding-when-files-checksum-changes
%.md5: FORCE
	@$(if $(filter-out $(shell cat $@ 2>/dev/null),$(shell md5sum $*)),md5sum $* > $@)

FORCE:

# Enumerate intermediate files to don't remove them automatically.
# The target must exist, no need to execute it.
.PHONY: _keep-intermediate-files
_keep-intermediate-files: $(call to-md5,$(CYS) $(CS) $(PYS) $(REQS))

.install-cython: $(call to-md5,requirements/cython.txt)
	pip install -r requirements/cython.txt
	@touch .install-cython

aiohttp/_find_header.c: $(call to-md5,aiohttp/hdrs.py)
	./tools/gen.py

# _find_headers generator creates _headers.pyi as well
aiohttp/%.c: $(call to-md5,aiohttp/%.pyx) aiohttp/_find_header.c
	cython -3 -o $@ $< -I aiohttp


.PHONY: cythonize
cythonize: .install-cython $(PYXS:.pyx=.c)

.install-deps: .install-cython $(PYXS:.pyx=.c) $(call to-md5,$(CYS) $(REQS))
	pip install -r requirements/dev.txt
	@touch .install-deps

.PHONY: lint
lint: fmt mypy

.PHONY: fmt format
fmt format:
	python -m pre_commit run --all-files --show-diff-on-failure

.PHONY: mypy
mypy:
	mypy aiohttp

.develop: .install-deps $(call to-md5,$(PYS) $(CYS) $(CS))
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
	@rm -f `find . -type f -name '*.md5' `
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
	@rm -rf aiohttp.egg-info
	@rm -f .install-deps
	@rm -f .install-cython

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
