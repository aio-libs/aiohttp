---
name: backport-failed
description: Recover from a patchback auto-backport failure. Given a merged PR number, parse the patchback comments to find which target branches failed, cherry-pick the merge commit onto each failed branch, resolve conflicts, push to the user's fork, and open backport PRs that exactly match patchback's title and body shape so they look indistinguishable from successful auto-backports.
user-invocable: true
allowed-tools:
  - Bash
  - Read
  - Edit
  - Write
  - AskUserQuestion
---

# /backport-failed — Manual recovery for failed patchback backports

When patchback (the auto-backport bot used by aio-libs and similar orgs) fails to cherry-pick a merged PR onto a stable branch, it leaves a comment like:

> ### Backport to 3.13: 💔 cherry-picking failed — conflicts found
> ❌ Failed to cleanly apply `<sha>` on top of `patchback/backports/3.13/<sha>/pr-<num>`

This skill produces the manual backport PRs that should have been created, matching patchback's exact shape so the PR list stays uniform.

Arguments passed: `$ARGUMENTS` — usually a PR number (e.g. `12581`). If empty, ask the user for it via `AskUserQuestion`.

## The exact patchback PR shape

Every backport PR this skill opens **must** match this shape (study PRs authored by `patchback[bot]` — e.g. aio-libs/aiohttp#12574 — for the canonical form):

- **Title:** `[PR #<orig_num>/<short_sha> backport][<branch>] <original PR title>`
  - `<short_sha>` is the first 8 chars of the merge commit on master
  - `<branch>` is the target branch, e.g. `3.13`, `3.14`
- **Body first line:** `**This is a backport of PR #<orig_num> as merged into master (<full_sha>).**`
- **Body remainder:** the *original* PR body verbatim (including the HTML template comments and the unchecked checklist items as patchback preserves them — copy what's on the original PR)
- **Base branch:** the stable branch (`3.13`, `3.14`, etc.)
- **Head branch on fork:** `patchback/backports/<branch>/<full_sha>/pr-<orig_num>`

Do **not** add a "Drafted with Claude Code" footer, do **not** add Co-Authored-By, do **not** edit or summarize the original body. The goal is byte-for-byte indistinguishability from a successful patchback PR.

## Procedure

### 1. Resolve the PR number and gather metadata

If `$ARGUMENTS` is empty, ask the user for the PR number with `AskUserQuestion`. Then in parallel:

```bash
gh pr view <num> --repo <owner/repo> --json number,title,body,mergeCommit,headRepositoryOwner,baseRefName,labels,url
gh pr view <num> --repo <owner/repo> --comments
```

Detect the repo from the working directory's `upstream` remote (`git remote get-url upstream`). If there is no `upstream` remote, ask the user which remote points at the canonical repo.

Extract:
- `orig_num` — the PR number
- `orig_title` — the PR title (use as-is, do not modify)
- `orig_body` — the PR body (use as-is, do not modify, do not strip HTML comments)
- `full_sha` — the merge commit SHA on master (from `mergeCommit.oid`)
- `short_sha` — first 8 chars of `full_sha`

### 2. Find the failed target branches

From the comments output, find each patchback comment that says **"💔 cherry-picking failed — conflicts found"** and extract the target branch from the heading (`Backport to <branch>:`).

Sanity check against PR labels: patchback is driven by labels like `backport-3.13`, `backport-3.14`. The set of failed branches should be a subset of those labels. If a backport label has no patchback failure comment and no existing backport PR, that target probably succeeded automatically — skip it.

To confirm a branch genuinely needs a manual backport, check whether a successful backport PR already exists:

```bash
gh pr list --repo <owner/repo> --search "[PR #<orig_num>/<short_sha> backport]" --state all
```

If a PR with the expected title already exists for that branch, skip it.

### 3. Verify the working tree is clean enough to checkout branches

```bash
git status --porcelain
```

If there are staged/unstaged changes to tracked files, stop and tell the user. Untracked files are fine — patchback's workflow doesn't touch them.

Remember the current branch so you can return to it at the end:

```bash
git rev-parse --abbrev-ref HEAD
```

### 4. For each failed branch, create the backport

Run these steps **sequentially per branch** — never parallelize across target branches (they share the working tree).

```bash
git fetch upstream
git checkout -b patchback/backports/<branch>/<full_sha>/pr-<orig_num> upstream/<branch>
git cherry-pick -x <full_sha>
```

If the commit is a merge commit (`git cat-file -p <full_sha> | grep -c '^parent '` returns > 1), use `git cherry-pick -m1 -x <full_sha>` instead. For squash-merged PRs (the common case on aio-libs) it's a single-parent commit, so plain `-x` works.

#### Resolving conflicts

If cherry-pick reports conflicts:

1. Run `git status` to list conflicted files.
2. For each file, Read it, locate the `<<<<<<<`/`=======`/`>>>>>>>` markers, and resolve.
3. **Conflict-resolution principles** (in order):
   - Preserve the *intent* of the original PR — the change being backported is the source of truth for what should land.
   - Adapt to the stable branch's existing context. The conflict usually means surrounding code differs (e.g. a function got renamed on master but not on 3.13). Apply the PR's logical change to the stable branch's version of the code.
   - For news fragments (`CHANGES/*.rst`) the file usually doesn't exist on the stable branch yet — just take the master version.
   - If you cannot confidently resolve a conflict, **stop and ask the user**. Do not guess. Show the conflict markers and your proposed resolution, and let them confirm.
4. `git add <file>` for each resolved file.
5. `git cherry-pick --continue` (use a non-interactive editor: `GIT_EDITOR=true git cherry-pick --continue` to keep the cherry-pick's default message which already contains the `(cherry picked from commit ...)` trailer from `-x`).

#### Push to the user's fork

The user's fork remote is conventionally `origin` for aio-libs contributors (or named after their GitHub handle). Detect it:

```bash
git remote -v | grep -E "(fetch)" | grep -v upstream
```

If multiple non-upstream remotes exist, prefer one matching the GitHub user from `gh api user --jq .login`. Ask the user if ambiguous.

```bash
git push <fork_remote> patchback/backports/<branch>/<full_sha>/pr-<orig_num>
```

#### Open the backport PR

Use a HEREDOC so the body is preserved exactly. The body of the new PR is the **original PR's body**, prepended with the `**This is a backport...**` line and a blank line:

```bash
gh pr create \
  --repo <owner/repo> \
  --base <branch> \
  --head <fork_owner>:patchback/backports/<branch>/<full_sha>/pr-<orig_num> \
  --title "[PR #<orig_num>/<short_sha> backport][<branch>] <orig_title>" \
  --body "$(cat <<'EOF'
**This is a backport of PR #<orig_num> as merged into master (<full_sha>).**

<orig_body verbatim>
EOF
)"
```

If `<orig_body>` contains an `EOF` marker itself (rare), pick a different HEREDOC delimiter (e.g. `PATCHBACK_BODY`).

Report the new PR URL.

### 5. Return to the original branch

After all backports are done (or after stopping for user input):

```bash
git checkout <original_branch>
```

Leave the patchback branches in place locally — the user may want to amend them.

## Output to the user

At the end, print a short summary:

- Which branches had failed backports
- For each: the new PR URL, or `skipped (already exists)`, or `paused for user (conflict in <file>)`

Keep it terse — one line per branch.

## Edge cases

- **No patchback failure comments found.** Tell the user the PR's auto-backports look healthy and ask if they want to force a manual backport anyway.
- **Cherry-pick is clean (no conflicts).** Still legitimate — patchback may have failed for a transient reason. Proceed to push and PR creation as normal.
- **PR was a merge commit, not a squash.** Use `-m1` as noted above.
- **The fork already has the branch.** `git push --force-with-lease` only if the user confirms (`AskUserQuestion`). Never `--force` blindly.
- **News fragment filename differs.** Patchback preserves whatever filename the original PR used; do not rename.
- **Stable branch is end-of-life.** If `gh api repos/<owner>/<repo>/branches/<branch>` 404s, tell the user — the backport label may be stale.
