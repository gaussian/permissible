---
name: create-merge-pr
description: Create a pull request, bump the version, and merge. Use whenever you have committed work on a branch and want it landed — the standard way to open and merge PRs in this repo.
---

# create-merge-pr

The standard way to land a change in this repo.

## 1. Open the PR

Push your branch and open a PR. **Target `develop` by default.** Only target
`main` if the task explicitly says to release — a `develop` → `main` PR is a
release and triggers publishing to PyPI.

```
gh pr create --base develop --title "<title>" --body "<body>"
```

## 2. Bump the version — easy to forget, so don't

The version is **not** bumped automatically. If you skip this, your change lands
but no release is ever cut. When your change should ship, bump it — run the
**Bump Version** workflow, which commits the bump to `develop`:

```
gh workflow run "Bump Version" --ref develop -f bump_type=patch
```

`patch` by default; `minor` for new features, `major` for breaking changes.

(The bump commits directly to `develop`, independent of your PR — you don't need
it in your branch.)

## 3. Merge

Use a merge commit — **do not squash**:

```
gh pr merge --merge --delete-branch
```

Checks (`lint`, `test`) run automatically and must pass — `main` is protected,
so a red PR cannot be merged. If something's red, fix it and push; you can
reproduce the checks locally:

```
uv run --all-extras ruff check permissible/ tests/ && uv run --all-extras ruff format --check permissible/ tests/
uv run --all-extras pytest
```
