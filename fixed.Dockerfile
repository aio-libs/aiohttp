# syntax=docker/dockerfile:1
# =============================================================================
# fixed.Dockerfile
#
# Corrected build for aio-libs/aiohttp @ PR #11290 (4.0.0a2.dev0).
#
# Three changes relative to original-reconstructed.Dockerfile:
#
#   FIX 1 - Ordering. `git submodule update --init --recursive` now runs BEFORE
#           `pip install -e .`. This is the actual reported bug: setup.py exits
#           with code 2 ("Install submodules when building from git clone")
#           when vendor/llhttp/README.md is missing.
#
#   FIX 2 - Generated sources. setup.py lists aiohttp/_websocket/mask.c,
#           aiohttp/_http_parser.c, aiohttp/_http_writer.c and
#           aiohttp/_websocket/reader_c.c as Extension sources, but the repo
#           only ships the .pyx originals ("NOTE: makefile cythonizes all
#           Cython modules"). They must be generated with Cython, and
#           vendor/llhttp/build/c/llhttp.c must be generated with the llhttp
#           Node toolchain, before the compiler runs. Skipping this is what
#           produced the second failure in the log:
#             cc1: fatal error: aiohttp/_websocket/mask.c: No such file or directory
#
#   FIX 3 - Dependencies. Install the project's own pinned lockfile
#           requirements/test.txt instead of hand-listing packages. The
#           original spec guessed at them and still missed isal, zlib_ng,
#           blockbuster, freezegun and pytest-mock, which the log rediscovered
#           one failure at a time across attempts 3, 4 and 5.
#
#   FIX 4 - Working-tree hygiene. The supplied repository.zip came from a
#           Windows checkout: CRLF line endings, stripped exec bits, and
#           symlinks flattened into text files. `git reset --hard HEAD` with
#           the core.* overrides rebuilds the tree from the objects in .git.
#           Not needed for a real git clone.
#
# The Node.js/npm toolchain is confined to a builder stage so it never reaches
# the final image.
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1 - generate the vendored llhttp C sources.
# `make -C vendor/llhttp generate` needs Node; the final image must not.
# -----------------------------------------------------------------------------
FROM node:20-bookworm-slim AS llhttp-builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends git make ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src

# FIX 1 applied here: the submodule is materialised before anything consumes it.
RUN git submodule update --init --recursive vendor/llhttp

# FIX 2 (part a): produces vendor/llhttp/build/c/llhttp.c and build/llhttp.h,
# which setup.py references via llhttp_sources / include_dirs.
WORKDIR /src/vendor/llhttp
RUN npm ci && make generate


# -----------------------------------------------------------------------------
# Stage 2 - the testbed image.
# Base layout kept identical to the reconstruction (/testbed + the miniconda
# "testbed" env on Python 3.11) so the SWE-bench harness keeps working.
# -----------------------------------------------------------------------------
FROM ubuntu:22.04 AS testbed

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential gcc git libffi-dev libssl-dev pkg-config python3-dev \
        wget bzip2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Miniforge rather than Miniconda: repo.anaconda.com now refuses
# non-interactive installs until its Terms of Service are accepted. Same conda,
# conda-forge defaults, identical /opt/miniconda3 + "testbed" layout.
RUN wget -qO /tmp/miniforge.sh \
        "https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-Linux-$(uname -m).sh" \
    && bash /tmp/miniforge.sh -b -p /opt/miniconda3 \
    && rm -f /tmp/miniforge.sh

ENV PATH=/opt/miniconda3/bin:$PATH
RUN conda create -y -n testbed python=3.11 && conda clean -afy
ENV PATH=/opt/miniconda3/envs/testbed/bin:/opt/miniconda3/condabin:$PATH \
    CONDA_DEFAULT_ENV=testbed \
    CONDA_PREFIX=/opt/miniconda3/envs/testbed

WORKDIR /testbed
COPY . /testbed

# FIX 4 - normalise the working tree against the commit it claims to be.
# The supplied repository.zip was produced from a Windows checkout: its
# .git/config carries `filemode = false`, `symlinks = false`, `ignorecase =
# true`. Three separate kinds of damage follow, and all three break the build:
#
#   a) CRLF everywhere - 395 of 400 tracked files differ from HEAD (117942
#      insertions / 117942 deletions of pure line-ending churn). tools/gen.py's
#      shebang becomes `#!/usr/bin/env python\r`:
#        /usr/bin/env: 'python\r': No such file or directory
#   b) exec bits stripped - tools/gen.py arrives 644:
#        ./tools/gen.py: Permission denied
#        make: *** [Makefile:57: aiohttp/_find_header.c] Error 127
#   c) symlinks flattened - aiohttp/_websocket/reader_c.py is recorded in git
#      as mode 120000 -> reader_py.py, but arrives as a 12-byte text file
#      containing the string "reader_py.py". Cython then compiles an empty
#      module against reader_c.pxd and fails:
#        reader_c.pxd:57:29: C method '_release_waiter' is declared but not
#        defined
#
# Overriding the three core.* settings and resetting to HEAD rebuilds the tree
# correctly from the objects already present in .git. No-op for a real clone.
RUN git -c core.autocrlf=false -c core.eol=lf \
        -c core.fileMode=true -c core.symlinks=true \
        reset --hard HEAD

# FIX 1 - submodule first. Kept even though stage 1 also ran it: this populates
# the rest of the tree and makes vendor/llhttp/README.md exist, which is the
# exact file setup.py's guard checks.
RUN git submodule update --init --recursive

# FIX 2 (part a, continued) - take the generated llhttp artefacts from stage 1
# rather than dragging Node into this image.
COPY --from=llhttp-builder /src/vendor/llhttp/build /testbed/vendor/llhttp/build

RUN pip install --upgrade pip setuptools wheel

# FIX 3 - the project's own pinned lockfile, which already covers isal,
# zlib_ng, blockbuster, freezegun, pytest-mock, pytest-xdist, trustme, etc.
RUN pip install --no-cache-dir -r requirements/cython.txt \
    && pip install --no-cache-dir -r requirements/test.txt

# FIX 2 (part b) - .pyx -> .c, plus tools/gen.py for aiohttp/_find_header.c.
# `cythonize-nodeps` is the project's own target; it skips the pip bootstrap
# that `cythonize` would redo.
RUN make cythonize-nodeps

# Now the editable install has everything it needs and builds the accelerated
# (C extension) variant, exactly as upstream CI does.
RUN pip install --no-cache-dir -e . -c requirements/runtime-deps.txt

# Basic functionality check for `docker run --rm assessment-fix`: proves the
# package imports, that the C extensions really were built (not the pure-Python
# fallback), and that a real request/response round-trip works.
COPY <<-'PY' /usr/local/bin/smoke-test.py
	import asyncio
	import aiohttp
	from aiohttp import web


	def extension_state() -> str:
	    from aiohttp._websocket import mask
	    from aiohttp import http_parser
	    # A compiled module reports a .so path; the pure-Python fallback a .py one.
	    accel = mask.__file__.endswith(".so")
	    # Resolves to aiohttp._http_parser when the C parser was built,
	    # aiohttp.http_parser when it fell back to pure Python.
	    parser = http_parser.HttpRequestParser.__module__
	    assert accel, "C extensions did not build - this is the pure-Python fallback"
	    return f"c_extensions=yes mask={mask.__file__.rsplit('/', 1)[-1]} parser={parser}"


	async def round_trip() -> None:
	    async def handler(request: web.Request) -> web.Response:
	        return web.json_response({"pong": request.query.get("ping")})

	    app = web.Application()
	    app.router.add_get("/", handler)
	    runner = web.AppRunner(app)
	    await runner.setup()
	    site = web.TCPSite(runner, "127.0.0.1", 8080)
	    await site.start()
	    try:
	        async with aiohttp.ClientSession() as session:
	            async with session.get("http://127.0.0.1:8080/?ping=hello") as resp:
	                body = await resp.json()
	                print(f"round-trip     : HTTP {resp.status} {body}")
	                assert resp.status == 200 and body == {"pong": "hello"}
	    finally:
	        await runner.cleanup()


	print(f"aiohttp version: {aiohttp.__version__}")
	print(f"build          : {extension_state()}")
	asyncio.run(round_trip())
	print("SMOKE TEST PASSED")
PY

# Drop privileges for the default run. The harness overrides the entrypoint
# when it needs root, so this does not interfere with evaluation.
RUN useradd --create-home --uid 1000 testrunner \
    && chown -R testrunner:testrunner /testbed
USER testrunner

CMD ["python", "/usr/local/bin/smoke-test.py"]
