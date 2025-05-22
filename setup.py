import os
import pathlib
import sys

from setuptools import Extension, setup

if sys.version_info < (3, 9):
    raise RuntimeError("aiohttp 4.x requires Python 3.9+")


USE_SYSTEM_DEPS = bool(
    os.environ.get("AIOHTTP_USE_SYSTEM_DEPS", os.environ.get("USE_SYSTEM_DEPS"))
)
NO_EXTENSIONS: bool = bool(os.environ.get("AIOHTTP_NO_EXTENSIONS"))
HERE = pathlib.Path(__file__).parent
IS_GIT_REPO = (HERE / ".git").exists()


if sys.implementation.name != "cpython":
    NO_EXTENSIONS = True


if (
    not USE_SYSTEM_DEPS
    and IS_GIT_REPO
    and not (HERE / "vendor/llhttp/README.md").exists()
):
    print("Install submodules when building from git clone", file=sys.stderr)
    print("Hint:", file=sys.stderr)
    print("  git submodule update --init", file=sys.stderr)
    sys.exit(2)


# NOTE: makefile cythonizes all Cython modules

if USE_SYSTEM_DEPS:
    import shlex

    import pkgconfig

    llhttp_sources = []
    llhttp_kwargs = {
        "extra_compile_args": shlex.split(pkgconfig.cflags("libllhttp")),
        "extra_link_args": shlex.split(pkgconfig.libs("libllhttp")),
    }
else:
    llhttp_sources = [
        "vendor/llhttp/build/c/llhttp.c",
        "vendor/llhttp/src/native/api.c",
        "vendor/llhttp/src/native/http.c",
    ]
    llhttp_kwargs = {
        "define_macros": [("LLHTTP_STRICT_MODE", 0)],
        "include_dirs": ["vendor/llhttp/build"],
    }

extensions = [
    Extension("aiohttp._websocket.mask", ["aiohttp/_websocket/mask.c"]),
    Extension(
        "aiohttp._http_parser",
        [
            "aiohttp/_http_parser.c",
            "aiohttp/_find_header.c",
            *llhttp_sources,
        ],
        **llhttp_kwargs,
    ),
    Extension("aiohttp._http_writer", ["aiohttp/_http_writer.c"]),
    Extension("aiohttp._websocket.reader_c", ["aiohttp/_websocket/reader_c.c"]),
]


build_type = "Pure" if NO_EXTENSIONS else "Accelerated"
setup_kwargs = {} if NO_EXTENSIONS else {"ext_modules": extensions}

print("*********************", file=sys.stderr)
print("* {build_type} build *".format_map(locals()), file=sys.stderr)
print("*********************", file=sys.stderr)
setup(**setup_kwargs)
