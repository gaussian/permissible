# Changelog

## Unreleased

`HierarchicalPermDomain` ancestor traversal is now ordered, cycle-safe and
depth-capped.

### Breaking

- `HierarchicalPermDomain.get_ancestor_ids_from_id()` returns an **ordered list**
  (nearest ancestor first) instead of an unordered `set`. It also takes a new
  optional `max_levels` argument.
- `save()` raises `django.core.exceptions.ValidationError` (keyed on `"parent"`)
  where it used to raise `ValueError` for self-parenting.
- `save()` now also raises `ValidationError` for a parent that would create a
  cycle, or that would push the tree past `MAX_HIERARCHY_DEPTH`. Writes that
  were previously accepted can now be rejected.

### Fixed

- `get_ancestor_ids_from_id()` looped forever on a cycle in the `parent` chain,
  issuing one query per iteration. Nothing in the database prevents such a
  cycle: it is reachable through `.update(parent_id=...)`, a data migration, a
  fixture or raw SQL, none of which pass through `save()`. The walk now stops on
  any repeated id and logs it with `logger.error`.
- `save()` inherited that hang through its two calls to
  `get_ancestor_ids_from_id()`. It now terminates.
- `get_permission_targets()` recursed until `RecursionError` on a cycle. It is
  now iterative with a visited set, and yields each node exactly once. It also
  fetches one level per query instead of one node per query (it was N+1).

### Added

- `MAX_HIERARCHY_DEPTH = 10`, a class attribute subclasses may override. It is a
  Python-level cap; it needs no migration.
- `get_ancestor_ids(max_levels=None)` and `aget_ancestor_ids(max_levels=None)`
  return ancestor ids **nearest first**, excluding the object itself. One
  `values_list("parent_id", flat=True)` query per level, instantiating no model
  rows. Both stop on a repeated id (`logger.error`) and at `max_levels`
  (`logger.warning`), and neither raises.
- `get_descendant_depth()` returns the number of levels below the object, 0 for
  a leaf. Breadth-first, one query per level, bounded by `MAX_HIERARCHY_DEPTH`
  and by a seen set.
- `validate_hierarchy()` checks the pending `parent_id` against the
  self-parent, cycle and depth rules. It is wired into `clean()` and `save()`,
  because most writes to `parent` never pass through a ModelForm. The depth
  check counts ancestors above the new parent, plus the object, plus
  `get_descendant_depth()`, so a subtree cannot be re-parented under a deep node
  to slip past the cap.
- Module-level `walk_ancestor_ids()` / `awalk_ancestor_ids()` helpers, for
  callers that have an id rather than an instance.

### Changed

- A save that cannot change `parent` — `save(update_fields=[...])` without
  `"parent"` — now runs no hierarchy queries at all, neither the validation
  walks nor the previous-parent lookup.
- The walks read through `_default_manager` rather than `objects`. For a model
  whose default manager hides rows (a soft-delete manager, for example), a
  hidden ancestor is invisible and therefore **ends the chain**: its id is still
  returned, because the child names it, but nothing above it is.
