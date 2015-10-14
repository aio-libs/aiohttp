# Some simple testing tasks (sorry, UNIX only).

.install-deps: requirements-dev.txt
	pip install -U -r requirements-dev.txt
	touch .install-deps

flake: .install-deps
#	python setup.py check -rms
	flake8 aiohttp
	if python -c "import sys; sys.exit(sys.version_info < (3,5))"; then \
            flake8 examples tests; \
        fi


.develop: .install-deps $(shell find aiohttp -type f)
	pip install -e .
	touch .develop

test: flake .develop
	py.test -q ./tests/

vtest: flake .develop
	py.test -s -v ./tests/

cov cover coverage:
	tox

cov-dev: flake develop
	@coverage erase
	@coverage run -m pytest -s tests
	@mv .coverage .coverage.accel
	@AIOHTTP_NO_EXTENSIONS=1 coverage run -m pytest -s tests
	@mv .coverage .coverage.pure
	@coverage combine
	@coverage report
	@coverage html
	@echo "open file://`pwd`/coverage/index.html"

clean:
	rm -rf `find . -name __pycache__`
	rm -f `find . -type f -name '*.py[co]' `
	rm -f `find . -type f -name '*~' `
	rm -f `find . -type f -name '.*~' `
	rm -f `find . -type f -name '@*' `
	rm -f `find . -type f -name '#*#' `
	rm -f `find . -type f -name '*.orig' `
	rm -f `find . -type f -name '*.rej' `
	rm -f .coverage
	rm -rf coverage
	rm -rf build
	rm -rf cover
	make -C docs clean
	python setup.py clean
	rm -f aiohttp/_multidict.html
	rm -f aiohttp/_multidict.c
	rm -f aiohttp/_multidict.*.so
	rm -f aiohttp/_multidict.*.pyd
	rm -rf .tox

doc:
	make -C docs html
	@echo "open file://`pwd`/docs/_build/html/index.html"

doc-spelling:
	make -C docs spelling

install:
	pip install -U pip
	pip install -Ur requirements-dev.txt

.PHONY: all build venv flake test vtest testloop cov clean doc
