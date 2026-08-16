---
name: create-merge-pr
description: Create a pull request, bump the version, and merge. Use whenever you have committed work on a branch and want it landed — the standard way to open and merge PRs in this repo.
---

# create-merge-pr

The standard way to land a change in this repo. There are two pathways — pick
by where you are:

- **On a feature branch** → Pathway A (feature pathway): land it into `develop`.
- **Already on `develop`** → Pathway B (release pathway): release `develop` into `main`.

## Pathway A (feature pathway) — feature branch → `develop`

1. Push your branch and open a PR targeting `develop`:

   ```
   gh pr create --base develop --title "<title>" --body "<body>"
   ```

2. **Do not bump the version** — bumps happen only on releases (Pathway B).

3. Merge with a merge commit — **do not squash** (it loses the individual
   commits), and **do NOT pass `--delete-branch`** (the branch is deleted
   separately, in step 4):

   ```
   gh pr merge --merge
   ```

4. Delete the branch, directly after the merge:

   ```
   git push origin --delete <branch>
   ```

## Pathway B (release pathway) — `develop` → `main`

A `develop` → `main` PR is a release — merging it triggers publishing to PyPI.

1. Open the PR from `develop` into `main`:

   ```
   gh pr create --base main --head develop --title "<title>" --body "<body>"
   ```

2. **Bump the version — easy to forget, so don't.** The version is **not**
   bumped automatically; if you skip this, no release is cut. Run the
   **Bump Version** workflow, which commits the bump to `develop`:

   ```
   gh workflow run "Bump Version" --ref develop -f bump_type=patch
   ```

   `patch` by default; `minor` for new features, `major` for breaking changes.

   The workflow commits directly to the **remote** `develop`, so your local
   `develop` is now stale. Wait for the workflow to finish, then re-pull:

   ```
   git pull origin develop
   ```

3. Merge with a merge commit — **do not squash**, and **do NOT pass
   `--delete-branch`** (it would delete `develop`):

   ```
   gh pr merge --merge
   ```

4. **Do not delete the branch.**

## Checks (both pathways)

Checks (`lint`, `test`) run automatically and must pass — `main` is protected,
so a red PR cannot be merged. If something's red, fix it and push; you can
reproduce the checks locally:

```
uv run --all-extras ruff check permissible/ tests/ && uv run --all-extras ruff format --check permissible/ tests/
uv run --all-extras pytest
```
