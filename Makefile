# Some simple testing tasks (sorry, UNIX only).

to-hash-one = $(dir $1).hash/$(addsuffix .hash,$(notdir $1))
to-hash = $(foreach fname,$1,$(call to-hash-one,$(fname)))

CYS := $(wildcard aiohttp/*.pyx) $(wildcard aiohttp/*.pyi)  $(wildcard aiohttp/*.pxd)
PYXS := $(wildcard aiohttp/*.pyx)
CS := $(wildcard aiohttp/*.c)
PYS := $(wildcard aiohttp/*.py)
REQS := $(wildcard requirements/*.txt)
ALLS := $(sort $(CYS) $(CS) $(PYS) $(REQS))
IN := doc-spelling lint cython dev
REQIN := $(foreach fname,$(IN),requirements/$(fname).in)


.PHONY: all
all: test

tst:
	@echo $(call to-hash,requirements/cython.txt)
	@echo $(call to-hash,aiohttp/%.pyx)


# Recipe from https://www.cmcrossroads.com/article/rebuilding-when-files-checksum-changes
FORCE:

# check_sum.py works perfectly fine but slow when called for every file from $(ALLS)
# (perhaps even several times for each file).
# That is why much less readable but faster solution exists
ifneq (, $(shell which sha256sum))
%.hash: FORCE
	$(eval $@_ABS := $(abspath $@))
	$(eval $@_NAME := $($@_ABS))
	$(eval $@_HASHDIR := $(dir $($@_ABS)))
	$(eval $@_TMP := $($@_HASHDIR)../$(notdir $($@_ABS)))
	$(eval $@_ORIG := $(subst /.hash/../,/,$(basename $($@_TMP))))
	@#echo ==== $($@_ABS) $($@_HASHDIR) $($@_NAME) $($@_TMP) $($@_ORIG)
	@if ! (sha256sum --check $($@_ABS) 1>/dev/null 2>/dev/null); then \
	  mkdir -p $($@_HASHDIR); \
	  echo re-hash $($@_ORIG); \
	  sha256sum $($@_ORIG) > $($@_ABS); \
	fi
else
%.hash: FORCE
	@./tools/check_sum.py $@ # --debug
endif

# Enumerate intermediate files to don't remove them automatically.
.SECONDARY: $(call to-hash,$(ALLS))

.update-pip:
	@python -m pip install --upgrade pip

.install-cython: .update-pip $(call to-hash,requirements/cython.txt)
	@pip install -r requirements/cython.txt
	@touch .install-cython

aiohttp/_find_header.c: $(call to-hash,aiohttp/hdrs.py ./tools/gen.py)
	./tools/gen.py

# _find_headers generator creates _headers.pyi as well
aiohttp/%.c: aiohttp/%.pyx $(call to-hash,$(CYS)) aiohttp/_find_header.c
	cython -3 -o $@ $< -I aiohttp


.PHONY: cythonize
cythonize: .install-cython $(PYXS:.pyx=.c)

.install-deps: .install-cython $(PYXS:.pyx=.c) $(call to-hash,$(CYS) $(REQS))
	@pip install -r requirements/dev.txt
	@touch .install-deps

.PHONY: lint
lint: fmt mypy

.PHONY: fmt format
fmt format:
	python -m pre_commit run --all-files --show-diff-on-failure

.PHONY: mypy
mypy:
	mypy

.develop: .install-deps $(call to-hash,$(PYS) $(CYS) $(CS))
	pip install -e .
	@touch .develop

.PHONY: test
test: .develop
	@pytest -q

.PHONY: vtest
vtest: .develop
	@pytest -s -v

.PHONY: vvtest
vvtest: .develop
	@pytest -vv

.PHONY: cov-dev
cov-dev: .develop
	@pytest --cov-report=html
	@echo "xdg-open file://`pwd`/htmlcov/index.html"

.PHONY: clean
clean:
	@rm -rf `find . -name __pycache__`
	@rm -rf `find . -name .hash`
	@rm -rf `find . -name .md5`  # old styling
	@rm -f `find . -type f -name '*.py[co]' `
	@rm -f `find . -type f -name '*~' `
	@rm -f `find . -type f -name '.*~' `
	@rm -f `find . -type f -name '@*' `
	@rm -f `find . -type f -name '#*#' `
	@rm -f `find . -type f -name '*.orig' `
	@rm -f `find . -type f -name '*.rej' `
	@rm -f `find . -type f -name '*.md5' `  # old styling
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
	@make -C docs html SPHINXOPTS="-W --keep-going -n -E"
	@echo "open file://`pwd`/docs/_build/html/index.html"

.PHONY: doc-spelling
doc-spelling:
	@make -C docs spelling SPHINXOPTS="-W --keep-going -n -E"

.PHONY: compile-deps
compile-deps: .update-pip
	@pip install pip-tools
	@$(foreach fname,$(REQIN),pip-compile --allow-unsafe -q $(fname);)

.PHONY: install
install: .update-pip
	@pip install -r requirements/dev.txt

.PHONY: install-dev
install-dev: .develop
