#!/bin/bash
if [ -z $TRAVIS_TAG ] || [ -n $PYTHONASYNCIODEBUG ] || [ -n $AIOHTTP_NO_EXTENSIONS ]
then
    exit 1
fi

package_name="$1"
if [ -z "$package_name" ]
then
    &>2 echo "Please pass package name as a first argument of this script ($0)"
    exit 1
fi

dock_ext_args=""

for arch in x86_64 i686
do
    [ $arch == "i686" ] && dock_ext_args="linux32"

    echo "${arch}"
    docker pull "quay.io/pypa/manylinux1_${arch}"
    docker run --rm -v `pwd`:/io "quay.io/pypa/manylinux1_${arch}" $dock_ext_args /io/tools/build-wheels.sh "$package_name"

    echo "Dist folder content is:"
    for f in dist/aiohttp*manylinux1_${arch}.whl
    do
        echo "Upload $f"
        python -m twine upload "$f" --username andrew.svetlov --password "$PYPI_PASSWD"
    done

    echo "Cleanup"
    rm -rf ./dist
done
