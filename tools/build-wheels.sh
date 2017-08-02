#!/bin/bash
PYTHON_VERSIONS="cp34-cp34m cp35-cp35m cp36-cp36m"

# Avoid creation of __pycache__/*.py[c|o]
export PYTHONDONTWRITEBYTECODE=1

package_name="$1"
if [ -z "$package_name" ]
then
    &>2 echo "Please pass package name as a first argument of this script ($0)"
    exit 1
fi

arch=`uname -m`

echo
echo
echo "Compile wheels"
for PYTHON in ${PYTHON_VERSIONS}; do
    /opt/python/${PYTHON}/bin/pip install -r /io/requirements/wheel.txt
    /opt/python/${PYTHON}/bin/pip wheel /io/ -w /io/dist/
done

echo
echo
echo "Bundle external shared libraries into the wheels"
for whl in /io/dist/${package_name}*${arch}.whl; do
    echo "Repairing $whl..."
    auditwheel repair "$whl" -w /io/dist/
done

echo "Cleanup OS specific wheels"
rm -fv /io/dist/*-linux_*.whl

echo
echo
echo "Install packages and test"
echo "dist directory:"
ls /io/dist

for PYTHON in ${PYTHON_VERSIONS}; do
    echo
    echo -n "Test $PYTHON: "
    /opt/python/${PYTHON}/bin/python -c "import platform;print(platform.platform())"
    /opt/python/${PYTHON}/bin/pip install "$package_name" --no-index -f file:///io/dist
    /opt/python/${PYTHON}/bin/py.test /io/tests
done
