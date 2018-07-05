import codecs
import pathlib
import re
import sys
from distutils.command.build_ext import build_ext
from distutils.errors import (CCompilerError, DistutilsExecError,
                              DistutilsPlatformError)

from setuptools import Extension, setup


if sys.version_info < (3, 5, 3):
    raise RuntimeError("aiohttp 3.x requires Python 3.5.3+")


try:
    from Cython.Build import cythonize
    USE_CYTHON = True
except ImportError:
    USE_CYTHON = False

ext = '.pyx' if USE_CYTHON else '.c'


extensions = [Extension('aiohttp._websocket', ['aiohttp/_websocket' + ext]),
              Extension('aiohttp._http_parser',
                        ['aiohttp/_http_parser' + ext,
                         'vendor/http-parser/http_parser.c',
                         'aiohttp/_find_header.c'],
                        define_macros=[('HTTP_PARSER_STRICT', 0)],
                        ),
              Extension('aiohttp._frozenlist',
                        ['aiohttp/_frozenlist' + ext]),
              Extension('aiohttp._helpers',
                        ['aiohttp/_helpers' + ext]),
              Extension('aiohttp._http_writer',
                        ['aiohttp/_http_writer' + ext])]


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
        except (DistutilsExecError,
                DistutilsPlatformError, ValueError):
            raise BuildFailed()


here = pathlib.Path(__file__).parent

txt = (here / 'aiohttp' / '__init__.py').read_text('utf-8')
try:
    version = re.findall(r"^__version__ = '([^']+)'\r?$",
                         txt, re.M)[0]
except IndexError:
    raise RuntimeError('Unable to determine version.')


def get_environment_marker_support_level():
    """
    Copied from https://github.com/pytest-dev/pytest/blob/master/setup.py

    Tests how well setuptools supports PEP-426 environment marker.
    The first known release to support it is 0.7 (and the earliest on PyPI seems to be 0.7.2
    so we're using that), see: https://setuptools.readthedocs.io/en/latest/history.html#id350
    The support is later enhanced to allow direct conditional inclusions inside install_requires,
    which is now recommended by setuptools. It first appeared in 36.2.0, went broken with 36.2.1, and
    again worked since 36.2.2, so we're using that. See:
    https://setuptools.readthedocs.io/en/latest/history.html#v36-2-2
    https://github.com/pypa/setuptools/issues/1099
    References:
    * https://wheel.readthedocs.io/en/latest/index.html#defining-conditional-dependencies
    * https://www.python.org/dev/peps/pep-0426/#environment-markers
    * https://setuptools.readthedocs.io/en/latest/setuptools.html#declaring-platform-specific-dependencies
    """
    try:
        version = pkg_resources.parse_version(setuptools.__version__)
        if version >= pkg_resources.parse_version("36.2.2"):
            return 2
        if version >= pkg_resources.parse_version("0.7.2"):
            return 1
    except Exception as exc:
        sys.stderr.write("Could not test setuptool's version: %s\n" % exc)

    # as of testing on 2018-05-26 fedora was on version 37* and debian was on version 33+
    # we should consider erroring on those
    return 0


install_requires = [
    'attrs>=17.3.0',
    'chardet>=2.0,<4.0',
    'multidict>=4.0,<5.0',
    'async_timeout>=3.0,<4.0',
    'yarl>=1.0,<2.0',
]
extras_require = {}

environment_marker_support_level = get_environment_marker_support_level()
if environment_marker_support_level >= 2:
    install_requires.append('idna-ssl>=1.0;python_version<"3.7"')
elif environment_marker_support_level == 1:
    extras_require[':python_version<"3.7"'] = ["idna-ssl>=1.0"]
else:
    if sys.version_info < (3, 7):
        install_requires.append("idna-ssl>=1.0")


def read(f):
    return (here / f).read_text('utf-8').strip()


NEEDS_PYTEST = {'pytest', 'test'}.intersection(sys.argv)
pytest_runner = ['pytest-runner'] if NEEDS_PYTEST else []

tests_require = ['pytest', 'gunicorn',
                 'pytest-timeout', 'async-generator']


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
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
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
    url='https://github.com/aio-libs/aiohttp',
    project_urls={
        'Chat: Gitter': 'https://gitter.im/aio-libs/Lobby',
        'CI: AppVeyor': 'https://ci.appveyor.com/project/aio-libs/aiohttp',
        'CI: Circle': 'https://circleci.com/gh/aio-libs/aiohttp',
        'CI: Shippable': 'https://app.shippable.com/github/aio-libs/aiohttp',
        'CI: Travis': 'https://travis-ci.com/aio-libs/aiohttp',
        'Coverage: codecov': 'https://codecov.io/github/aio-libs/aiohttp',
        'Docs: RTD': 'https://docs.aiohttp.org',
        'GitHub: issues': 'https://github.com/aio-libs/aiohttp/issues',
        'GitHub: repo': 'https://github.com/aio-libs/aiohttp',
    },
    license='Apache 2',
    packages=['aiohttp'],
    python_requires='>=3.5.3',
    install_requires=install_requires,
    tests_require=tests_require,
    extras_require=extras_require,
    setup_requires=pytest_runner,
    include_package_data=True,
    ext_modules=extensions,
    cmdclass=dict(build_ext=ve_build_ext),
)

try:
    setup(**args)
except BuildFailed:
    print("************************************************************")
    print("Cannot compile C accelerator module, use pure python version")
    print("************************************************************")
    del args['ext_modules']
    del args['cmdclass']
    setup(**args)
