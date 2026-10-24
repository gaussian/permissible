---
name: merge-feature-and-release
description: Merge the current feature branch into develop, then release develop to main. Slash command only.
argument-hint: "[patch|minor|major] [target-branch]"
disable-model-invocation: true
---

# merge-feature-and-release

Arguments: `$ARGUMENTS`. The bump type is `patch` unless the user gave `minor` or `major`. The target branch is `develop` unless the user named another. Stop and report if any step fails.

1. Run `/create-merge-pr` (Pathway A) to merge the feature branch into the target.
2. Switch to the target: `git fetch origin && git switch <target> && git pull origin <target>`. If another worktree has it checked out, use `git switch --detach origin/<target>`.
3. Run every lint and test `run:` command from `.github/workflows/checks.yml`; all must pass. Skip jobs that need service containers (e.g. a database) and say which.
4. Run `/create-merge-pr` (Pathway B) with the bump type.
