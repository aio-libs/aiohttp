#!/bin/bash
if [ -n "$DEBUG" ]
then
  set -x
fi

package_name="$1"
if [ -z "$package_name" ]
then
    >&2 echo "Please pass package name as a first argument of this script ($0)"
    exit 1
fi

export WORKDIR_PATH="${GITHUB_WORKSPACE:-/io}"

BUILD_DIR=`mktemp -d "/tmp/${package_name}-manylinux1-build.XXXXXXXXXX"`
ORIG_WHEEL_DIR="${BUILD_DIR}/original-wheelhouse"
SRC_DIR="${BUILD_DIR}/src"
WHEELHOUSE_DIR="${WORKDIR_PATH}/dist"

set -euo pipefail
# ref: https://coderwall.com/p/fkfaqq/safer-bash-scripts-with-set-euxo-pipefail

PYTHON_VERSIONS="cp35-cp35m cp36-cp36m cp37-cp37m"

# Avoid creation of __pycache__/*.py[c|o]
export PYTHONDONTWRITEBYTECODE=1

arch=`uname -m`

echo
echo
echo "Copying source to ${SRC_DIR}..."
cp -a "${WORKDIR_PATH}" "${SRC_DIR}"

echo
echo
echo "Removing pre-existing ${SRC_DIR}/dist..."
rm -rfv "${SRC_DIR}/dist"

echo
echo
echo "Building ${package_name} dist has been requested"

echo
echo
echo "Compile wheels"
for PYTHON in ${PYTHON_VERSIONS}; do
    /opt/python/${PYTHON}/bin/python -m pip install -U pip
    /opt/python/${PYTHON}/bin/python -m pip install -r "${WORKDIR_PATH}/requirements/cython.txt"
    /opt/python/${PYTHON}/bin/python -m pip install -r "${WORKDIR_PATH}/requirements/wheel.txt"
    /opt/python/${PYTHON}/bin/python -m pip wheel "${SRC_DIR}/" --no-deps -w "${ORIG_WHEEL_DIR}/${PYTHON}" -v
done

echo
echo
echo "Bundle external shared libraries into the wheels"
for whl in ${ORIG_WHEEL_DIR}/*/${package_name}-*-linux_${arch}.whl; do
    echo "Repairing $whl..."
    auditwheel repair "$whl" -w "${WHEELHOUSE_DIR}"
done

echo
echo
echo "Cleanup OS specific wheels"
rm -fv ${WHEELHOUSE_DIR}/*-linux_*.whl

echo
echo
echo "Cleanup non-$package_name wheels"
find "${WHEELHOUSE_DIR}" -maxdepth 1 -type f ! -name "$package_name"'-*-manylinux1_*.whl' -print0 | xargs -0 rm -rf

echo
echo
echo "Install packages and test"
echo "dist directory:"
ls ${WHEELHOUSE_DIR}

for PYTHON in ${PYTHON_VERSIONS}; do
    # clear python cache
    find "${WORKDIR_PATH}" -type d -name __pycache__ -print0 | xargs -0 rm -rf

    echo
    echo -n "Test $PYTHON: "
    /opt/python/${PYTHON}/bin/python -c "import platform; print('Building wheel for {platform} platform.'.format(platform=platform.platform()))"
    /opt/python/${PYTHON}/bin/pip install -r ${WORKDIR_PATH}/requirements/cython.txt
    /opt/python/${PYTHON}/bin/pip install -r ${WORKDIR_PATH}/requirements/ci-wheel.txt
    /opt/python/${PYTHON}/bin/pip install "$package_name" --no-index -f "file://${WHEELHOUSE_DIR}"
    /opt/python/${PYTHON}/bin/py.test ${WORKDIR_PATH}/tests
done

chown -R --reference="${WORKDIR_PATH}/.travis.yml" "${WORKDIR_PATH}"
