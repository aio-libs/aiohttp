# Notes for LLM contributors

Agent orientation for `aio-libs/aiohttp`. Human-facing docs:
[CONTRIBUTING.rst](CONTRIBUTING.rst),
[docs/contributing.rst](docs/contributing.rst),
[CHANGES/README.rst](CHANGES/README.rst).

## Rule zero: prove it works before opening the PR

"It compiles" and "the diff looks right" are not proof. Proof is:
relevant tests pass locally, new behaviour is covered by a test, and
the user-visible path runs end-to-end on **both** the default
C-extension build **and** the pure-Python build
(`AIOHTTP_NO_EXTENSIONS=1`). If you cannot run the suite locally, say
so in the PR body.

## Branching

- Open PRs against `master` (default branch is `master`, not `main`).
- `Patchback` auto-backports merged PRs labelled `backport-3.X` to
  release branches (`3.13`, `3.14`, ...). Use `backport:skip` to opt
  out.
- Do not open PRs against release branches, except to recover from a
  failed auto-backport (cherry-pick the merge commit, push a
  replacement backport PR).

## Build

- Full dev setup: `make install-dev` (alias for `.develop`; installs
  deps, cythonizes, builds extensions).
- Vendored llhttp: `git submodule update --init` + `make generate-llhttp`
  (requires Node.js). Regenerates parser tables for the pinned commit;
  does **not** change the pin.
- Cython extensions: `make cythonize` (`.pyx` → `.c`; also runs
  `tools/gen.py`), then `pip install -e .` to compile.
- Pure Python mode: `AIOHTTP_NO_EXTENSIONS=1 pip install -e .`.
- `AIOHTTP_CYTHON_TRACE=1` enables Cython trace macros (only useful
  with linetrace-enabled `.c` files).

## Test

- Run all: `PYTHONPATH='.' pytest --numprocesses=auto`
- Single test: `PYTHONPATH='.' pytest tests/test_foo.py::test_name`
- Pure Python leg: `PYTHONPATH='.' AIOHTTP_NO_EXTENSIONS=1 pytest`
- Convenience: `make test`, `make vtest`, `make cov-dev`.

Run **both** the default and `AIOHTTP_NO_EXTENSIONS=1` legs before
opening a PR. Coverage tracks `aiohttp/` and `tests/`; uncovered
lines in `tests/` show up on the codecov patch report. No
unreachable `raise` guards in stubs, no cleanup branches behind
`if had_own_attr:` without a second test exercising the other
shape. Prefer `monkeypatch` (auto-reverts) over hand-rolled
save/restore. See
[aio-libs/yarl#1687](https://github.com/aio-libs/yarl/pull/1687).

## Dual-backend discipline

The single biggest source of broken aiohttp PRs from agents. Hot
paths exist in both backends and must stay behaviourally identical;
fix the matching one in the same PR:

| Pure Python                                             | Cython / C                                                                    |
| ------------------------------------------------------- | ----------------------------------------------------------------------------- |
| `aiohttp/http_parser.py`                                | `aiohttp/_http_parser.pyx` (parser bugs may live upstream in `vendor/llhttp`) |
| `aiohttp/http_writer.py`                                | `aiohttp/_http_writer.pyx`                                                    |
| `aiohttp/_websocket/reader_py.py`                       | `aiohttp/_websocket/reader_c.py` (must stay byte-for-byte equivalent)         |
| `aiohttp/_websocket/helpers.py::_websocket_mask_python` | `aiohttp/_websocket/mask.pyx::_websocket_mask_cython`                         |

A new public API lands in both backends with identical signatures,
type hints, and docstrings. If a fix really only applies to one
backend, say so in the PR body. If you can only fix one in scope,
file a follow-up issue; do not silently leave them divergent.

## Lint & Format

- `pre-commit run --all-files` runs all hooks defined in
  [`.pre-commit-config.yaml`](.pre-commit-config.yaml). `make lint`
  runs the same plus `mypy`.
- `black` for formatting only, `mypy` for type checking (not in
  pre-commit; `make mypy`).
- Style: black with 88-col line length, isort with trailing commas.
- Hooks rewrite files in place. Re-stage and commit again. Do
  **not** use `--no-verify`.
- `make doc-spelling` (run before pushing if you edited any `.rst`)
  reads every `CHANGES/*.rst` fragment with `-W --keep-going`. Add
  real technical terms to
  [`docs/spelling_wordlist.txt`](docs/spelling_wordlist.txt); fix
  typos.

## Changelog

Every user- or contributor-visible PR needs a towncrier fragment in
`CHANGES/`, named `<pr_or_issue_number>.<category>.rst`. Valid
categories are defined in `[tool.towncrier]` in
[pyproject.toml](pyproject.toml).

- reStructuredText, past tense (`Fixed`, `Added`, `Bumped`).
- No PR/issue number in the body; towncrier reads it from the
  filename. Sign with `` -- by :user:`github-handle` ``.
- Prefer the **issue** number for the filename (stable, known up
  front). No linked issue: open the PR first then add the fragment
  by assigned number, or guess from
  `gh pr list --repo aio-libs/aiohttp --state all --limit 5`.
- Both issue and PR number wanted: keep the issue-numbered file and
  symlink: `ln -s 1234.bugfix.rst CHANGES/1240.bugfix.rst`.
- Multiple fragments same category: `1234.feature.rst`,
  `1234.feature.1.rst`.

## Pull request rules

**Template.** Use the shipped template at
[`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md)
verbatim. Do **not** invent a `## What / ## Why / ## How / ## Testing`
layout; that is the giveaway of an LLM-authored PR that ignored
conventions. A couple of sentences per section is plenty. Tick
checklist boxes that apply; write `N/A` next to ones that do not.
First-time contributors add themselves to `CONTRIBUTORS.txt`
(alphabetical by first name).

**Draft.** Use `gh pr create --draft`. Every LLM-authored submission
must be reviewed by a human before going out of draft; that review
is the operator's job, not the maintainers'. Do not mark ready or
request reviewers yourself.

**Disclosure, not advertising.** One plain line at the bottom of the
PR body:

```
Drafted with <agent name and version>; reviewed by <human handle>.
```

In addition:

- **No `Co-Authored-By:` trailers** for an LLM, in commits or PR body.
- **No emoji** (`🤖`, `✨`, `🚀`) anywhere; plain prose.
- **No em-dashes (`—`)** and no dashes used as sentence separators
  (`foo - bar`); use a semicolon or comma. Strongest AI tell here.
- No "Let me" / "I'll" / first-person narration. Describe the change.
- No filler sections (Overview, Summary, Key takeaways) above the
  template.
- Agent run output (test logs, scans) goes in a collapsed
  `<details>` block **below** the template summary, not inside it.

**Commits.** One logical change per PR; split refactors from
bugfixes. The repo does **not** use Conventional Commits; match
recent imperative or descriptive subjects (e.g. `Fix digest
authentication for URLs with reserved characters`, `ci: report
slowest benchmarks via --durations=30`).

## Generated files, Cython, llhttp

`aiohttp/_http_parser.pyx`, `aiohttp/_http_writer.pyx`, and
`aiohttp/_websocket/mask.pyx` compile to `.c`/`.so` via `make
cythonize`. `aiohttp/_headers.pxi` and `aiohttp/_find_header.c` are
generated from `aiohttp/hdrs.py` by `tools/gen.py` (also via `make
cythonize`).

`vendor/llhttp/` is a git submodule pointing at
[`nodejs/llhttp`](https://github.com/nodejs/llhttp); the aiohttp tree
only tracks the sha. **Do not edit anything under `vendor/llhttp/` by
hand**; fixes belong upstream. Bumping is a pointer move
(`git checkout <sha>` inside the submodule, `git add vendor/llhttp`
from the root) and goes in its own PR.

Never commit: `aiohttp/**/*.c`, `aiohttp/**/*.html`,
`aiohttp/**/*.so`, `*.py,cover`, `__pycache__/`, `.hash/`, `build/`,
`dist/`.

## Threat model

[`THREAT_MODEL.md`](THREAT_MODEL.md) is a living document. Revise
when:

- A CVE / GHSA is filed against aiohttp.
- The parser configuration changes (llhttp lenient flags, size
  limits, version regex).
- Any default referenced in the document changes (`client_max_size`,
  `keepalive_timeout`, `max_redirects`, `limit`, `limit_per_host`,
  etc.).
- The vendored llhttp version is bumped.
- A public API surface is added or removed in `client.py` /
  `web_*.py` / `multipart.py`.

When a chunk's content is materially affected, update both the
chunk and any cross-referenced summary entries. The "Past advisories
/ hardening (recap)" subsection of each chunk is the audit trail for
what has been verified-in-place.

## Documentation & code style

User-visible API changes need a docs update under `docs/` (the
relevant `docs/client_reference.rst` / `docs/web_reference.rst`
section plus any narrative pages). Docstrings in code, prose in
Sphinx. `make doc` builds locally; `make doc-spelling` is the CI
spell-check leg.

`pyproject.toml` pins `requires-python = ">= 3.10"`. Match the
surrounding file's import and typing conventions; do not introduce
`from __future__ import annotations` where the file does not already
use it. No docstrings or comments that just restate the code.
