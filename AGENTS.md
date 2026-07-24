# permissible — agent guide

Object-level, rule-driven permissions for Django & Django REST Framework.
Published to PyPI.

## Repo shape

- Source: `permissible/`
- Tests: `tests/` (pytest-django, settings at `tests.settings`) — `uv run --all-extras pytest`
- Lint + format: `uv run --all-extras ruff check permissible/ tests/` and `ruff format --check permissible/ tests/`
- Default working branch: `develop`. Releases flow `develop` → `main`.

## Opening PRs & versioning

`main` is protected: PRs only, and checks (`lint`, `test`) must pass to merge.
The version is a static string in `pyproject.toml`, `permissible/__init__.py`, and
`uv.lock` and is **not** bumped automatically on merge — it must be bumped
deliberately, or no release is cut. Publishing to PyPI is automatic once a
`develop` → `main` PR merges.

**Follow the `create-merge-pr` skill** (`.agents/skills/create-merge-pr/`) for the
full PR workflow, including when and how to bump the version.
