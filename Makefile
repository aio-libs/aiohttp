# Some simple testing tasks (sorry, UNIX only).

all: test

.install-deps: $(shell find requirements -type f)
	@pip install -U -r requirements/dev.txt
	@touch .install-deps

isort:
	isort -rc aiohttp
	isort -rc tests
	isort -rc examples
	isort -rc demos

flake: .flake

.flake: .install-deps $(shell find aiohttp -type f) \
                      $(shell find tests -type f) \
                      $(shell find examples -type f) \
                      $(shell find demos -type f)
	@flake8 aiohttp --exclude=aiohttp/backport_cookies.py
	@if python -c "import sys; sys.exit(sys.version_info < (3,5))"; then \
	    flake8 examples tests demos && \
            python setup.py check -rms; \
	fi
	@if ! isort -c -rc aiohttp tests examples; then \
            echo "Import sort errors, run 'make isort' to fix them!!!"; \
            isort --diff -rc aiohttp tests examples; \
            false; \
	fi
	@touch .flake

check_changes:
	@./tools/check_changes.py

.develop: .install-deps $(shell find aiohttp -type f) .flake check_changes
	@pip install -e .
	@touch .develop

test: .develop
	@py.test -q ./tests

vtest: .develop
	@py.test -s -v ./tests

cov cover coverage:
	tox

cov-dev: .develop
	@echo "Run without extensions"
	@AIOHTTP_NO_EXTENSIONS=1 py.test --cov=aiohttp tests
	@py.test --cov=aiohttp --cov-report=term --cov-report=html --cov-append tests
	@echo "open file://`pwd`/coverage/index.html"

cov-ci-no-ext: .develop
	@echo "Run without extensions"
	@AIOHTTP_NO_EXTENSIONS=1 py.test --cov=aiohttp tests
cov-ci-aio-debug: .develop
	@echo "Run in debug mode"
	@PYTHONASYNCIODEBUG=1 py.test --cov=aiohttp --cov-append tests
cov-ci-run: .develop
	@echo "Regular run"
	@py.test --cov=aiohttp --cov-report=term --cov-report=html --cov-append tests

cov-dev-full: cov-ci-no-ext cov-ci-aio-debug cov-ci-run
	@echo "open file://`pwd`/coverage/index.html"

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
	@rm -rf coverage
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
