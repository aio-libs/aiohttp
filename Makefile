# Some simple testing tasks (sorry, UNIX only).

FLAGS=


flake:
	flake8 aiohttp tests examples

test: flake
	nosetests -s $(FLAGS) ./tests/

vtest: flake
	nosetests -s -v $(FLAGS) ./tests/

testloop:
	while sleep 1; do python runtests.py $(FLAGS); done

cov cover coverage:
	nosetests -s --with-cover --cover-html --cover-branches --cover-html-dir ./coverage $(FLAGS) ./tests/
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

doc:
	make -C docs html
	@echo "open file://`pwd`/docs/_build/html/index.html"

.PHONY: all build venv flake test vtest testloop cov clean doc
