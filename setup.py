import os
import pathlib
import re
import sys

from setuptools import Extension, setup

if sys.version_info < (3, 7):
    raise RuntimeError("aiohttp 4.x requires Python 3.7+")


NO_EXTENSIONS = bool(os.environ.get("AIOHTTP_NO_EXTENSIONS"))  # type: bool
HERE = pathlib.Path(__file__).parent
IS_GIT_REPO = (HERE / ".git").exists()


if sys.implementation.name != "cpython":
    NO_EXTENSIONS = True


if IS_GIT_REPO and not (HERE / "vendor/http-parser/README.md").exists():
    print("Install submodules when building from git clone", file=sys.stderr)
    print("Hint:", file=sys.stderr)
    print("  git submodule update --init", file=sys.stderr)
    sys.exit(2)


# NOTE: makefile cythonizes all Cython modules

extensions = [
    Extension("aiohttp._websocket", ["aiohttp/_websocket.c"]),
    Extension(
        "aiohttp._http_parser",
        [
            "aiohttp/_http_parser.c",
            "vendor/http-parser/http_parser.c",
            "aiohttp/_find_header.c",
        ],
        define_macros=[("HTTP_PARSER_STRICT", 0)],
    ),
    Extension("aiohttp._helpers", ["aiohttp/_helpers.c"]),
    Extension("aiohttp._http_writer", ["aiohttp/_http_writer.c"]),
]


txt = (HERE / "aiohttp" / "__init__.py").read_text("utf-8")
try:
    version = re.findall(r'^__version__ = "([^"]+)"\r?$', txt, re.M)[0]
except IndexError:
    raise RuntimeError("Unable to determine version.")

install_requires = [
    "chardet>=2.0,<5.0",
    "multidict>=4.5,<7.0",
    "async_timeout>=4.0a2,<5.0",
    'asynctest==0.13.0; python_version<"3.8"',
    "yarl>=1.0,<2.0",
    "typing_extensions>=3.7.4",
    "frozenlist>=1.1.1",
    "aiosignal>=1.1.2",
]


def read(f):
    return (HERE / f).read_text("utf-8").strip()


args = dict(
    name="aiohttp",
    version=version,
    description="Async http client/server framework (asyncio)",
    long_description="\n\n".join((read("README.rst"), read("CHANGES.rst"))),
    long_description_content_type="text/x-rst",
    classifiers=[
        "License :: OSI Approved :: Apache Software License",
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Development Status :: 5 - Production/Stable",
        "Operating System :: POSIX",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
        "Topic :: Internet :: WWW/HTTP",
        "Framework :: AsyncIO",
    ],
    author="Nikolay Kim",
    author_email="fafhrd91@gmail.com",
    maintainer=", ".join(
        (
            "Nikolay Kim <fafhrd91@gmail.com>",
            "Andrew Svetlov <andrew.svetlov@gmail.com>",
        )
    ),
    maintainer_email="aio-libs@googlegroups.com",
    url="https://github.com/aio-libs/aiohttp",
    project_urls={
        "Chat: Gitter": "https://gitter.im/aio-libs/Lobby",
        "CI: GitHub Actions": "https://github.com/aio-libs/aiohttp/actions?query=workflow%3ACI",  # noqa
        "Coverage: codecov": "https://codecov.io/github/aio-libs/aiohttp",
        "Docs: Changelog": "https://docs.aiohttp.org/en/stable/changes.html",
        "Docs: RTD": "https://docs.aiohttp.org",
        "GitHub: issues": "https://github.com/aio-libs/aiohttp/issues",
        "GitHub: repo": "https://github.com/aio-libs/aiohttp",
    },
    license="Apache 2",
    packages=["aiohttp"],
    python_requires=">=3.7",
    install_requires=install_requires,
    extras_require={
        "speedups": [
            "aiodns>=1.1",
            "Brotli",
            "cchardet",
        ],
    },
    include_package_data=True,
)

if not NO_EXTENSIONS:
    print("*********************")
    print("* Accelerated build *")
    print("*********************")
    setup(ext_modules=extensions, **args)
else:
    print("*********************")
    print("* Pure Python build *")
    print("*********************")
    setup(**args)
