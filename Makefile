# Some simple testing tasks (sorry, UNIX only).

PYTHON=venv/bin/python3.3
PIP=venv/bin/pip
NOSE=venv/bin/nosetests
FLAKE=venv/bin/flake8
FLAGS=


build:
	$(PIP) install -e hg+https://fafhrd91@code.google.com/p/tulip/#egg=tulip
	$(PYTHON) ./setup.py develop

venv:
	curl -O https://raw.githubusercontent.com/pypa/virtualenv/1.10.X/virtualenv.py
	python3.3 virtualenv.py venv
	rm -f ./virtualenv.py
	curl -O https://bitbucket.org/pypa/setuptools/raw/bootstrap/ez_setup.py
	venv/bin/python ez_setup.py
	rm -f ./ez_setup.py
	venv/bin/easy_install pip

	$(PIP) install -e hg+https://fafhrd91@code.google.com/p/tulip/#egg=tulip
	$(PYTHON) ./setup.py develop

dev:
	$(PIP) install flake8 nose coverage
	$(PYTHON) ./setup.py develop

flake:
	$(FLAKE) --exclude=./venv ./

test:
	$(NOSE) -s $(FLAGS) ./tests/

vtest:
	$(NOSE) -s -v $(FLAGS) ./tests/

testloop:
	while sleep 1; do $(PYTHON) runtests.py $(FLAGS); done

cov cover coverage:
	$(NOSE) -s --with-cover --cover-html --cover-html-dir ./coverage $(FLAGS) ./tests/
	echo "open file://`pwd`/coverage/index.html"

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


.PHONY: all build venv flake test vtest testloop cov clean
