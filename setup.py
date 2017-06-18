import codecs
import os
import re
import sys
from distutils.command.build_ext import build_ext
from distutils.errors import (CCompilerError, DistutilsExecError,
                              DistutilsPlatformError)

from setuptools import Extension, setup
from setuptools.command.test import test as TestCommand

try:
    from Cython.Build import cythonize
    USE_CYTHON = True
except ImportError:
    USE_CYTHON = False

ext = '.pyx' if USE_CYTHON else '.c'

extensions = [Extension('aiohttp._websocket', ['aiohttp/_websocket' + ext]),
              Extension('aiohttp._http_parser',
                        ['aiohttp/_http_parser' + ext,
                         'vendor/http-parser/http_parser.c'],),
              Extension('aiohttp._frozenlist',
                        ['aiohttp/_frozenlist' + ext])]


if USE_CYTHON:
    extensions = cythonize(extensions)


class BuildFailed(Exception):
    pass


class ve_build_ext(build_ext):
    # This class allows C extension building to fail.

    def run(self):
        try:
            build_ext.run(self)
        except (DistutilsPlatformError, FileNotFoundError):
            raise BuildFailed()

    def build_extension(self, ext):
        try:
            build_ext.build_extension(self, ext)
        except (CCompilerError, DistutilsExecError,
                DistutilsPlatformError, ValueError):
            raise BuildFailed()


with codecs.open(os.path.join(os.path.abspath(os.path.dirname(
        __file__)), 'aiohttp', '__init__.py'), 'r', 'latin1') as fp:
    try:
        version = re.findall(r"^__version__ = '([^']+)'\r?$",
                             fp.read(), re.M)[0]
    except IndexError:
        raise RuntimeError('Unable to determine version.')


install_requires = ['chardet', 'multidict>=2.1.4',
                    'async_timeout>=1.2.0', 'yarl>=0.10.0,<0.11']

if sys.version_info < (3, 4, 2):
    raise RuntimeError("aiohttp requires Python 3.4.2+")


def read(f):
    return open(os.path.join(os.path.dirname(__file__), f)).read().strip()


class PyTest(TestCommand):
    user_options = []

    def run(self):
        import subprocess
        import sys
        errno = subprocess.call([sys.executable, '-m', 'pytest', 'tests'])
        raise SystemExit(errno)


tests_require = install_requires + ['pytest', 'gunicorn', 'pytest-timeout']


args = dict(
    name='aiohttp',
    version=version,
    description='Async http client/server framework (asyncio)',
    long_description='\n\n'.join((read('README.rst'), read('CHANGES.rst'))),
    classifiers=[
        'License :: OSI Approved :: Apache Software License',
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Development Status :: 5 - Production/Stable',
        'Operating System :: POSIX',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Topic :: Internet :: WWW/HTTP',
        'Framework :: AsyncIO',
    ],
    author='Nikolay Kim',
    author_email='fafhrd91@gmail.com',
    maintainer=', '.join(('Nikolay Kim <fafhrd91@gmail.com>',
                          'Andrew Svetlov <andrew.svetlov@gmail.com>')),
    maintainer_email='aio-libs@googlegroups.com',
    url='https://github.com/aio-libs/aiohttp/',
    license='Apache 2',
    packages=['aiohttp'],
    install_requires=install_requires,
    tests_require=tests_require,
    include_package_data=True,
    ext_modules=extensions,
    cmdclass=dict(build_ext=ve_build_ext,
                  test=PyTest))

try:
    setup(**args)
except BuildFailed:
    print("************************************************************")
    print("Cannot compile C accelerator module, use pure python version")
    print("************************************************************")
    del args['ext_modules']
    del args['cmdclass']
    setup(**args)
