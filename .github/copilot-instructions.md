Guidance for coding agents working on aiohttp
============================================

This file contains focused, actionable guidance for an AI coding assistant to be immediately productive in the aiohttp repository.

- Big picture
  - aiohttp is a dual client/server HTTP framework. Major areas:
    - client: `aiohttp/client.py`, `aiohttp/client_reqrep.py`, `aiohttp/client_ws.py`
    - server/web: `aiohttp/web.py`, `aiohttp/web_request.py`, `aiohttp/web_response.py`,
      `aiohttp/web_app.py`, `aiohttp/web_runner.py`, `aiohttp/web_server.py`, `aiohttp/web_urldispatcher.py`
    - protocol/parsing: Cython/C extensions in `aiohttp/*.pyx` and `aiohttp/_websocket/*.pyx` (see `aiohttp/_http_parser.pyx`, `aiohttp/_http_writer.pyx`)
    - websocket internals: `aiohttp/_websocket/` (e.g. `reader_c`, `mask`)

- Build / dev workflow (what actually matters)
  - Python >= 3.10 is required (see `setup.py`).
  - C extensions are optional: environment vars control the build
    - `AIOHTTP_NO_EXTENSIONS=1` forces a pure-Python build
    - `AIOHTTP_USE_SYSTEM_DEPS=1` uses system libllhttp if available (see `setup.py`)
  - The repo includes generated C files and a vendored `llhttp`. When building from a git clone you must run:
    - `git submodule update --init` to populate `vendor/llhttp` (setup.py will refuse if missing)
  - Makefile targets (UNIX Makefile; Windows users must translate to PowerShell):
    - `make .develop` — installs dev deps and prepares C sources (equivalent: `python -m pip install -r requirements/dev.in -c requirements/dev.txt` then run the generator targets)
    - `make cythonize` — generate `.c` files from `.pyx`
    - `make generate-llhttp` — builds the vendored llhttp (requires npm in `vendor/llhttp`)

- Running tests and lint (how CI runs them)
  - `pytest` is used; default flags live in `setup.cfg` under `[tool:pytest]`.
    - CI uses `pytest -q` (see Makefile `test` target). Tests are configured to run with xdist (`--numprocesses=auto`) and collect coverage (`pytest-cov`).
  - On Windows PowerShell, a minimal reproducible invocation is:
    - `python -m pip install -r requirements/dev.in -c requirements/dev.txt; python -m pytest -q`
  - Lint & format: pre-commit is used. Run `python -m pre_commit run --all-files` (Makefile `fmt` target).

- Project-specific patterns & conventions
  - Intermix of pure-Python + C-accelerated code: many modules have both `.pyx` and generated `.c`/`.so` artifacts. Prefer changing the `.pyx`/`.py` source and regenerate artifacts via the Makefile/tooling.
  - Generated helpers: `tools/gen.py` produces `aiohttp/_find_header.c` and related `.pyi` stubs. When modifying headers/`hdrs.py` run the generator.
  - Towncrier changelog workflow: CHANGES are stored in `CHANGES/` and towncrier is configured in `pyproject.toml`.
  - Test markers: tests use markers like `dev_mode` and `internal`. Default CI runs tests excluding `dev_mode` (see `setup.cfg` pytest addopts `-m "not dev_mode"`).

- Integration points & external dependencies
  - Vendor: `vendor/llhttp` (native HTTP parser). Building accelerated extensions may require C toolchain and `npm` for llhttp generation.
  - Runtime deps: `multidict`, `yarl`, `frozenlist`, `aiodns` (optional speedups). See `setup.cfg` and `pyproject.toml` for precise pins.

- Where to look for common fixes or changes
  - HTTP parsing/headers: `aiohttp/hdrs.py`, `aiohttp/_find_header.*`, `aiohttp/_http_parser.pyx`
  - Web API/route handling: `aiohttp/web_app.py`, `aiohttp/web_routedef.py`, `aiohttp/web_urldispatcher.py`
  - Client session internals: `aiohttp/client.py`, `aiohttp/client_reqrep.py`

- Short contract for code edits
  - Inputs: change description + target files.
  - Outputs: minimal, well-tested edits; update generated artifacts when relevant.
  - Error modes to watch: failing type checks (mypy), flake8/mismatched formatting, failing pytest markers, failure to build C extensions when expected.

If anything above is unclear or you'd like me to expand sections (Windows-specific build steps, exact Makefile -> PowerShell equivalents, or example PR checklist), tell me which area to expand.
