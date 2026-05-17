# Notes for LLM contributors

Agent orientation for `aio-libs/aiohttp`. Human-facing docs:
[CONTRIBUTING.rst](CONTRIBUTING.rst), [docs/contributing.rst](docs/contributing.rst),
[CHANGES/README.rst](CHANGES/README.rst).

## Rule zero: prove it works before opening the PR

Tests must pass locally, new behaviour must be covered by a test,
and the user-visible path must run end-to-end on **both** the default
C-extension build **and** `AIOHTTP_NO_EXTENSIONS=1`. If you cannot
run the suite locally, say so in the PR body.

## Branching

- Open PRs against `master` (default branch is `master`, not `main`).
- `Patchback` auto-backports merged PRs labelled `backport-3.X` to
  release branches (`3.13`, `3.14`, ...). Use `backport:skip` to opt
  out.
- Do not open PRs against release branches, except to recover from a
  failed auto-backport (cherry-pick the merge commit, push a
  replacement backport PR).

## Build

- Full setup: `make install-dev` (deps + cythonize + build).
- Vendored llhttp: `git submodule update --init` + `make generate-llhttp`
  (requires Node.js; regenerates parser tables, does not change pin).
- Cython only: `make cythonize` (`.pyx` → `.c`), then `pip install -e .`.
- Pure Python: `AIOHTTP_NO_EXTENSIONS=1 pip install -e .`.
- `AIOHTTP_CYTHON_TRACE=1` enables Cython trace macros.

## Test

- Run all: `PYTHONPATH='.' pytest --numprocesses=auto`
- Single test: `PYTHONPATH='.' pytest tests/test_foo.py::test_name`
- Pure Python leg: `PYTHONPATH='.' AIOHTTP_NO_EXTENSIONS=1 pytest`
- Or `make test` / `make vtest` / `make cov-dev`.

Run **both** legs before opening a PR. Coverage tracks `aiohttp/`
and `tests/`; uncovered test lines show up on the codecov patch
report. No unreachable `raise` guards in stubs, no cleanup branches
behind `if had_own_attr:` without a second test exercising the other
shape. Prefer `monkeypatch` over hand-rolled save/restore. See
[aio-libs/yarl#1687](https://github.com/aio-libs/yarl/pull/1687).

## Dual-backend discipline

Biggest source of broken aiohttp PRs from agents. The pure-Python and
Cython/C implementations of the hot paths must stay behaviourally
identical; fix the matching one in the same PR. The pairs are:
`http_parser.py` ↔ `_http_parser.pyx` (parser bugs may live upstream
in `vendor/llhttp`); `http_writer.py` ↔ `_http_writer.pyx`;
`_websocket/reader_py.py` ↔ `_websocket/reader_c.py` (byte-for-byte
equivalent); `_websocket/helpers.py::_websocket_mask_python` ↔
`_websocket/mask.pyx::_websocket_mask_cython`. New public API lands
in both with identical signatures, type hints, and docstrings. If
only one backend can be fixed in scope, file a follow-up and call it
out in the PR.

## Lint & Format

- `pre-commit run --all-files` runs all hooks in
  [`.pre-commit-config.yaml`](.pre-commit-config.yaml). Hooks rewrite
  in place; re-stage and commit. Do **not** use `--no-verify`.
- `make lint` adds `mypy` (also runnable as `make mypy`).
- Style: black 88-col, isort with trailing commas.
- `make doc-spelling` before pushing if you edited any `.rst`; it
  reads every `CHANGES/*.rst` fragment. Add real technical terms to
  [`docs/spelling_wordlist.txt`](docs/spelling_wordlist.txt); fix
  typos rather than papering over.

## Changelog

Every user- or contributor-visible PR needs a towncrier fragment in
`CHANGES/`, named `<issue_or_pr_number>.<category>.rst`. Valid
categories are in `[tool.towncrier]` in
[pyproject.toml](pyproject.toml).

- reStructuredText, past tense; no PR/issue number in the body
  (towncrier reads it from the filename). Sign with
  `` -- by :user:`github-handle` ``.
- Prefer the issue number when the PR closes one. No linked issue:
  use the PR number (open PR first, or guess from `gh pr list --repo
  aio-libs/aiohttp --state all --limit 5`).
- Both issue and PR number wanted: symlink the PR-named fragment at
  the issue-named fragment.
- Multiple fragments same category: append `.1`, `.2`, ...

## Pull request rules

**Template.** Use the shipped template at
[`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md)
verbatim. Do **not** invent a `## What / ## Why / ## How / ## Testing`
layout. Two sentences per section is plenty. Tick checklist boxes that
apply; write `N/A` next to ones that do not. First-time contributors
add themselves to `CONTRIBUTORS.txt` (alphabetical by first name).

**Draft + human review.** Use `gh pr create --draft`. Every
LLM-authored submission must be reviewed by a human before going out
of draft; that review is the operator's job, not the maintainers'.
Do not mark ready or request reviewers yourself.

**Disclosure.** One plain line at the bottom: `Drafted with <agent
name and version>; reviewed by <human handle>.` In addition:

- **No `Co-Authored-By:`** LLM trailers in commits or PR body.
- **No emoji** (`🤖`, `✨`, `🚀`) anywhere; plain prose.
- **No em-dashes (`—`)** or sentence-separating dashes (`foo - bar`);
  use a semicolon or comma. Strongest AI tell here.
- No "Let me" / "I'll" narration. No filler sections (Overview,
  Summary) above the template.
- Agent run output (test logs) goes in a collapsed `<details>` block
  **below** the template summary.

**Commits.** One logical change per PR. The repo does **not** use
Conventional Commits; match recent imperative subjects.

## Generated files, Cython, llhttp

`make cythonize` regenerates `aiohttp/_http_parser.c`,
`aiohttp/_http_writer.c`, `aiohttp/_websocket/mask.c`,
`aiohttp/_websocket/reader_c.c`, `aiohttp/_headers.pxi`, and
`aiohttp/_find_header.c`. `vendor/llhttp/` is a git submodule
pointing at [`nodejs/llhttp`](https://github.com/nodejs/llhttp); the
aiohttp tree only tracks the sha. **Do not edit `vendor/llhttp/` by
hand**; fixes belong upstream, and bumping is a submodule pointer
move in its own PR.

Never commit: `aiohttp/**/*.c`, `aiohttp/**/*.html`,
`aiohttp/**/*.so`, `*.py,cover`, `__pycache__/`, `.hash/`, `build/`,
`dist/`.

## Threat model

[`THREAT_MODEL.md`](THREAT_MODEL.md) is a living document. Revise
when: a CVE/GHSA is filed; the parser configuration changes (llhttp
lenient flags, size limits, version regex); any documented default
changes (`client_max_size`, `keepalive_timeout`, `max_redirects`,
`limit`, `limit_per_host`, ...); the vendored llhttp version is
bumped; or a public API surface is added/removed in `client.py` /
`web_*.py` / `multipart.py`. The "Past advisories / hardening
(recap)" subsection of each chunk is the audit trail for what has
been verified-in-place.

## Documentation & code style

User-visible API changes need a docs update under `docs/`
(`docs/client_reference.rst` / `docs/web_reference.rst` plus any
narrative pages). Docstrings in code, prose in Sphinx; `make doc`
builds locally. `requires-python = ">= 3.10"`; match surrounding
import and typing conventions. No docstrings or comments that just
restate the code.
