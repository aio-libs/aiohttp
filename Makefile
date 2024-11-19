# Some simple testing tasks (sorry, UNIX only).

to-hash-one = $(dir $1).hash/$(addsuffix .hash,$(notdir $1))
to-hash = $(foreach fname,$1,$(call to-hash-one,$(fname)))

CYS := $(wildcard aiohttp/*.pyx) $(wildcard aiohttp/*.pyi)  $(wildcard aiohttp/*.pxd) $(wildcard aiohttp/_websocket/*.pyx) $(wildcard aiohttp/_websocket/*.pyi) $(wildcard aiohttp/_websocket/*.pxd)
PYXS := $(wildcard aiohttp/*.pyx) $(wildcard aiohttp/_websocket/*.pyx)
CS := $(wildcard aiohttp/*.c) $(wildcard aiohttp/_websocket/*.c)
PYS := $(wildcard aiohttp/*.py) $(wildcard aiohttp/_websocket/*.py)
IN := doc-spelling lint cython dev
ALLS := $(sort $(CYS) $(CS) $(PYS) $(REQS))


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
ifneq (, $(shell command -v sha256sum))
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
	@python -m pip install -r requirements/cython.in -c requirements/cython.txt
	@touch .install-cython

aiohttp/_find_header.c: $(call to-hash,aiohttp/hdrs.py ./tools/gen.py)
	./tools/gen.py

# Special case for reader since we want to be able to disable
# the extension with AIOHTTP_NO_EXTENSIONS
aiohttp/_websocket/reader_c.c: aiohttp/_websocket/reader_c.py
	cython -3 -o $@ $< -I aiohttp -Werror

# _find_headers generator creates _headers.pyi as well
aiohttp/%.c: aiohttp/%.pyx $(call to-hash,$(CYS)) aiohttp/_find_header.c
	cython -3 -o $@ $< -I aiohttp -Werror

aiohttp/_websocket/%.c: aiohttp/_websocket/%.pyx $(call to-hash,$(CYS))
	cython -3 -o $@ $< -I aiohttp -Werror

vendor/llhttp/node_modules: vendor/llhttp/package.json
	cd vendor/llhttp; npm ci

.llhttp-gen: vendor/llhttp/node_modules
	$(MAKE) -C vendor/llhttp generate
	@touch .llhttp-gen

.PHONY: generate-llhttp
generate-llhttp: .llhttp-gen

.PHONY: cythonize
cythonize: .install-cython $(PYXS:.pyx=.c) aiohttp/_websocket/reader_c.c

.install-deps: .install-cython $(PYXS:.pyx=.c) aiohttp/_websocket/reader_c.c $(call to-hash,$(CYS) $(REQS))
	@python -m pip install -r requirements/dev.in -c requirements/dev.txt
	@touch .install-deps

.PHONY: lint
lint: fmt mypy

.PHONY: fmt format
fmt format:
	python -m pre_commit run --all-files --show-diff-on-failure

.PHONY: mypy
mypy:
	mypy

.develop: .install-deps generate-llhttp $(call to-hash,$(PYS) $(CYS) $(CS))
	python -m pip install -e . -c requirements/runtime-deps.txt
	@touch .develop

.PHONY: test
test: .develop
	@pytest -q

.PHONY: vtest
vtest: .develop
	@pytest -s -v
	@python -X dev -m pytest --cov-append -s -v -m dev_mode

.PHONY: vvtest
vvtest: .develop
	@pytest -vv
	@python -X dev -m pytest --cov-append -s -vv -m dev_mode

.PHONY: cov-dev
cov-dev: .develop
	@pytest --cov-report=html
	@echo "xdg-open file://`pwd`/htmlcov/index.html"


define run_tests_in_docker
	DOCKER_BUILDKIT=1 docker build --build-arg PYTHON_VERSION=$(1) --build-arg AIOHTTP_NO_EXTENSIONS=$(2) -t "aiohttp-test-$(1)-$(2)" -f tools/testing/Dockerfile .
	docker run --rm -ti -v `pwd`:/src -w /src "aiohttp-test-$(1)-$(2)" $(TEST_SPEC)
endef

.PHONY: test-3.9-no-extensions test
test-3.9-no-extensions:
	$(call run_tests_in_docker,3.9,y)
test-3.9:
	$(call run_tests_in_docker,3.9,n)
test-3.10-no-extensions:
	$(call run_tests_in_docker,3.10,y)
test-3.10:
	$(call run_tests_in_docker,3.10,n)

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
	@rm -f aiohttp/_websocket/reader_c.c
	@rm -rf .tox
	@rm -f .develop
	@rm -f .flake
	@rm -rf aiohttp.egg-info
	@rm -f .install-deps
	@rm -f .install-cython
	@rm -rf vendor/llhttp/node_modules
	@rm -f .llhttp-gen
	@$(MAKE) -C vendor/llhttp clean

.PHONY: doc
doc:
	@make -C docs html SPHINXOPTS="-W --keep-going -n -E"
	@echo "open file://`pwd`/docs/_build/html/index.html"

.PHONY: doc-spelling
doc-spelling:
	@make -C docs spelling SPHINXOPTS="-W --keep-going -n -E"

.PHONY: install
install: .update-pip
	@python -m pip install -r requirements/dev.in -c requirements/dev.txt

.PHONY: install-dev
install-dev: .develop

.PHONY: sync-direct-runtime-deps
sync-direct-runtime-deps:
	@echo Updating 'requirements/runtime-deps.in' from 'setup.cfg'... >&2
	@python requirements/sync-direct-runtime-deps.py
