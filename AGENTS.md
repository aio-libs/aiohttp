# AGENTS.md

This file provides guidance to AI coding agents working with this repository.

## Branching

- All new features and bug fixes target `master`. A bot creates backports to the `x.y` release branches automatically.

## Build

- Full dev setup: `make install-dev` (installs deps, cythonizes, builds extensions)
- Vendored llhttp: `git submodule update --init` + `make generate-llhttp` (requires Node.js)
- Cython extensions: `make cythonize` (.pyx → .c), then `pip install -e .` to compile
- Pure Python mode: `AIOHTTP_NO_EXTENSIONS=1 pip install -e .`
- `AIOHTTP_CYTHON_TRACE=1` enables Cython trace macros (only useful with linetrace-enabled .c files)

## Test

- Run all: `PYTHONPATH='.' pytest --numprocesses=auto`
- Single test: `PYTHONPATH='.' pytest tests/test_foo.py::test_name`
- Pure Python only: `PYTHONPATH='.' AIOHTTP_NO_EXTENSIONS=1 pytest`

## Lint & Format

- `pre-commit run --all-files` runs all checks (black, isort, flake8, pyupgrade, codespell)
- `black` for formatting only, `mypy` for type checking
- black with 88-col line length, isort with trailing commas

## Changelog

Fragments in `CHANGES/{pr_or_issue}.{type}.rst` (valid types are defined in `pyproject.toml` under `[tool.towncrier]`). Use `:user:\`name\`` role to credit contributors by Github ID.

## Threat model

`THREAT_MODEL.md` is a living document and should be revised when:

- A CVE / GHSA is filed against aiohttp.
- The parser configuration changes (llhttp lenient flags, size limits, version regex).
- Any default referenced in the document changes (`client_max_size`, `keepalive_timeout`, `max_redirects`, `limit`, `limit_per_host`, etc.).
- The vendored llhttp version is bumped.
- A public API surface is added or removed in `client.py` / `web_*.py` / `multipart.py`.

When a chunk's content is materially affected, update both the chunk and the relevant entries in §6.1–§6.4. The "Past advisories / hardening (recap)" subsection of each chunk is the audit trail for what has been verified-in-place.
