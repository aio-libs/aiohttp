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

## Documentation & code style

- User-visible API changes need a docs update under `docs/` (`docs/client_reference.rst` / `docs/web_reference.rst` plus any narrative pages).
- Docstrings in code, prose in Sphinx; `make doc` builds locally.
- No docstrings or comments that just restate the code.

## Changelog

- Fragments in `CHANGES/{pr_or_issue}.{type}.rst` (valid types are defined in `pyproject.toml` under `[tool.towncrier]`).
- Sign with `` -- by :user:`github-handle` ``.
- Both issue and PR number wanted: keep the issue-numbered file and symlink: `ln -s 1234.bugfix.rst CHANGES/1240.bugfix.rst`.
- Multiple fragments same category: `1234.feature.rst`, `1234.feature.1.rst`.

## PRs

- **Prove it works before opening the PR**. This means:
  - Relevant tests pass locally.
  - New behaviour is covered by a test.
  - Any parser/websocket related changes have been tested with Cython extensions installed.
- Use the shipped template at [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md).
  - A couple of sentences per section is plenty.
  - Tick checklist boxes that apply; write `N/A` next to ones that do not.
  - First-time contributors add themselves to `CONTRIBUTORS.txt` (alphabetical by first name).
- **Draft.** Use `gh pr create --draft`.
  - Every submission must be reviewed by a human before going out of draft; that review is the operator's job, not the maintainers'.
  - Do not mark ready or request reviewers yourself.
- **Disclosure.** One plain line at the bottom: `Drafted with <agent name and version>; reviewed by <human handle>.`
- **No `Co-Authored-By:`** LLM trailers in commits or PR body.
- Agent run output (test logs) goes in a collapsed `<details>` block **below** the template summary.

## Threat model

`THREAT_MODEL.md` is a living document and should be revised when:

- A CVE / GHSA is filed against aiohttp.
- The parser configuration changes (llhttp lenient flags, size limits, version regex).
- Any default referenced in the document changes (`client_max_size`, `keepalive_timeout`, `max_redirects`, `limit`, `limit_per_host`, etc.).
- The vendored llhttp version is bumped.
- A public API surface is added or removed in `client.py` / `web_*.py` / `multipart.py`.

When a chunk's content is materially affected, update both the chunk and the relevant entries in §6.1–§6.4. The "Past advisories / hardening (recap)" subsection of each chunk is the audit trail for what has been verified-in-place.
