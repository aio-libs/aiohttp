# Some simple testing tasks (sorry, UNIX only).

pytest := python3 -m pytest

all: test

.install-deps: requirements/dev.txt
	@pip3 install -U -r requirements/dev.txt
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
	@if python3 -c "import sys; sys.exit(sys.version_info < (3,5))"; then \
	    flake8 examples tests demos && \
            python3 setup.py check -rms; \
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
	@pip3 install -e .
	@touch .develop

test: .develop
	$(pytest) -q ./tests

vtest: .develop
	$(pytest) -s -v ./tests

cov cover coverage:
	tox

cov-dev: .develop
	@echo "Run without extensions"
	@AIOHTTP_NO_EXTENSIONS=1 $(pytest) --cov=aiohttp tests
	$(pytest) --cov=aiohttp --cov-report=term --cov-report=html --cov-append tests
        @echo "open file://`pwd`/coverage/index.html"

cov-dev-full: .develop
	@echo "Run without extensions"
	@AIOHTTP_NO_EXTENSIONS=1 $(pytest) --cov=aiohttp tests
	@echo "Run in debug mode"
	@PYTHONASYNCIODEBUG=1 $(pytest) --cov=aiohttp --cov-append tests
	@echo "Regular run"
	$(pytest) --cov=aiohttp --cov-report=term --cov-report=html --cov-append tests
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
	@python3 setup.py clean
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

doc:
	@make -C docs html SPHINXOPTS="-W -E"
	@echo "open file://`pwd`/docs/_build/html/index.html"

doc-spelling:
	@make -C docs spelling SPHINXOPTS="-W -E"

install:
	@pip3 install -U pip
	@pip3 install -Ur requirements/dev.txt

.PHONY: all build flake test vtest cov clean doc
