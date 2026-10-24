---
name: merge-feature-and-release
description: Merge the current feature branch into develop, then release develop to main. Slash command only.
argument-hint: "[patch|minor|major] [target-branch]"
disable-model-invocation: true
---

# merge-feature-and-release

Lands a feature branch and releases it in one go. Arguments: `$ARGUMENTS`. The bump type is `patch` unless the user gave `minor` or `major`. The target branch is `develop` unless the user named another. Stop and report if any step fails.

1. **Merge the feature.** From the feature branch, run `/create-merge-pr` (Pathway A) to open and merge a PR into the target branch. Note the feature branch name first.

2. **Switch to the target branch** and bring it up to date:

   ```
   git fetch origin && git switch <target> && git pull origin <target>
   ```

   If `git switch` refuses because the target is checked out in another worktree, run `git switch --detach origin/<target>` instead.

3. **Delete the remote feature branch** if it still exists (Pathway A normally does this already):

   ```
   git push origin --delete <feature-branch>
   ```

4. **Run all checks. They must pass.** If any fail, stop and report; do not release.

   ```
   uv run --all-extras ruff check permissible/ tests/ && uv run --all-extras ruff format --check permissible/ tests/
   uv run --all-extras pytest
   ```

5. **Release.** Run `/create-merge-pr` again (Pathway B) to open the target → `main` PR, bump the version with the bump type above, and merge it. If you are on a detached HEAD from step 2, skip its local `git pull`.
