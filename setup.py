import os
import pathlib
import sys

from setuptools import Extension, setup

if sys.version_info < (3, 6):
    raise RuntimeError("aiohttp 3.x requires Python 3.6+")


NO_EXTENSIONS: bool = bool(os.environ.get("AIOHTTP_NO_EXTENSIONS"))
HERE = pathlib.Path(__file__).parent
IS_GIT_REPO = (HERE / ".git").exists()


if sys.implementation.name != "cpython":
    NO_EXTENSIONS = True


if IS_GIT_REPO and not (HERE / "vendor/llhttp/README.md").exists():
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
            "aiohttp/_find_header.c",
            "vendor/llhttp/build/c/llhttp.c",
            "vendor/llhttp/src/native/api.c",
            "vendor/llhttp/src/native/http.c",
        ],
        define_macros=[("LLHTTP_STRICT_MODE", 0)],
        include_dirs=["vendor/llhttp/build"],
    ),
    Extension("aiohttp._helpers", ["aiohttp/_helpers.c"]),
    Extension("aiohttp._http_writer", ["aiohttp/_http_writer.c"]),
]


build_type = "Pure" if NO_EXTENSIONS else "Accelerated"
setup_kwargs = {} if NO_EXTENSIONS else {"ext_modules": extensions}

print("*********************", file=sys.stderr)
print("* {build_type} build *".format_map(locals()), file=sys.stderr)
print("*********************", file=sys.stderr)
setup(**setup_kwargs)
