# Changelog

## Unreleased

`HierarchicalPermDomain` tree traversal is now ordered, cycle-safe and
depth-capped, and both it and `reset_permissions()` do markedly less work.

### Breaking

Only one item here can break a working system. The rest are listed for
completeness, and their blast radius is stated.

- **`save()` now rejects writes it used to accept**: a parent that would create
  a cycle, or that would push the tree past `MAX_HIERARCHY_DEPTH`. **This is the
  one to check before upgrading.** Any existing tree deeper than the cap - and
  any fixture or test that builds one - starts raising `ValidationError`. Find
  them first, or raise `MAX_HIERARCHY_DEPTH` on your subclass:

  ```python
  # any object whose ancestor chain is already at or past the cap
  [obj for obj in Model.objects.all() if len(obj.get_ancestor_ids()) >= Model.MAX_HIERARCHY_DEPTH - 1]
  ```

- `get_ancestor_ids_from_id()` returns an **ordered list** (nearest first)
  instead of an unordered `set`, and takes a new optional `max_levels`. *No
  known callers:* inside this package it is only used by `save()`, and a survey
  of the consuming repositories found none outside it.
- `save()` raises `django.core.exceptions.ValidationError` keyed on `"parent"`
  where it used to raise `ValueError` for self-parenting. *No known catchers,
  and no test asserts the old type or message.*

Not breaking, listed here because it is a visible change in behaviour: an object
**already self-parented in the database** used to raise `ValueError` on every
save, including saves that had nothing to do with `parent`. It now saves. This
only removes an exception, so nothing that worked before stops working.

### Fixed

- `get_ancestor_ids_from_id()` looped forever on a cycle in the `parent` chain,
  issuing one query per iteration — it pinned a worker and hammered the
  database until the request was killed. Nothing in the database prevents such a
  cycle: it is reachable through `.update(parent_id=...)`, a data migration, a
  fixture or raw SQL, none of which pass through `save()`. The walk now stops on
  any repeated id and logs it with `logger.error`.
- `save()` inherited that hang through its two calls to
  `get_ancestor_ids_from_id()`. It now terminates.
- `get_permission_targets()` recursed until `RecursionError` on a cycle, and
  could revisit a node reachable by more than one path. It is now iterative with
  a visited set and yields each node exactly once.
- `save(update_fields=[...])` that excluded `"parent"` but left `.parent` dirty
  in memory reset the ancestors of a re-parenting **that was never written**
  (Django does not write a column absent from `update_fields`) — the wrong
  chain, for a change that did not happen. It now resets nothing. This is the
  only case in which `reset_domain_roles()` runs a different number of times
  than before.
- `save()` accepted any iterable for `update_fields`, as Django does, but tested
  it for membership before passing it on; a generator reached `super().save()`
  already consumed.

### Added

- `MAX_HIERARCHY_DEPTH = 10`, a class attribute subclasses may override. It is a
  Python-level cap and needs no migration.
- `get_ancestor_ids(max_levels=None)` and `aget_ancestor_ids(max_levels=None)`
  return ancestor ids **nearest first**, excluding the object itself. One
  `values_list("parent_id", flat=True)` query per level, instantiating no model
  rows. Both stop on a repeated id (`logger.error`) and at `max_levels`
  (`logger.warning`), and neither raises. The async variant exists because
  config resolution happens on ASGI paths too.
- `get_descendant_depth()` returns the number of levels below the object, 0 for
  a leaf. Breadth-first, one query per level, bounded by `MAX_HIERARCHY_DEPTH`
  and by a seen set.
- `validate_hierarchy()` checks the pending `parent_id` against the self-parent,
  cycle and depth rules. It is wired into both `clean()` and `save()`, because
  most writes to `parent` never pass through a ModelForm. The depth check counts
  the ancestors above the new parent, plus the object, plus
  `get_descendant_depth()`, so an existing subtree cannot be re-parented under a
  deep node to slip past the cap.
- Module-level `walk_ancestor_ids()` / `awalk_ancestor_ids()` helpers for
  callers holding an id rather than an instance. Both are exported from
  `permissible.models`.

### Performance

- `reset_permissions()` walks each domain object's `get_permission_targets()`
  **once per domain object** rather than once per role. Every role of one domain
  object sees the same subtree, and nothing in the call mutates the tree.
- `get_permission_targets()` fetches **one level per query** rather than one
  node per query (it was N+1). Its visited set is applied in Python rather than
  as `exclude(pk__in=seen)`, so the query carries only the current level: the
  bind parameter list does not grow with the subtree and cannot outgrow the
  backend's limit.
- The hierarchy checks run only when `parent` actually changed, so a plain
  `.save()` on a nested object costs the same 2 queries it always did, and
  `save(update_fields=[...])` without `"parent"` now costs 1 — it skips the
  previous-parent lookup it used to pay for.

Measured on SQLite against the previous release:

| Operation | Before | After |
|---|---|---|
| `reset_domain_roles()` on the root of a 6-node tree | 29 | **17** |
| create a child at depth 6 | 140 | **103** |
| create a child at depth 4 | 81 | **64** |
| re-parent a leaf under a 5-chain | 143 | **134** |
| plain `.save()`, parent unchanged | 2 | **2** |
| `save(update_fields=["name"])` | 2 | **1** |
| create a flat `PermDomain` (no hierarchy) | 16 | **16** |

### Changed

- `get_permission_targets()` yields **breadth-first** (the object, then every
  child, then every grandchild) where it used to yield depth-first. Nothing in
  this package depends on the order.
- Every read of the tree goes through `_default_manager` rather than `objects`,
  including `save()`'s lookup of the stored `parent_id` and its fetch of the
  ancestors to reset. For a model that has not overridden its manager these are
  the same thing.

### Default-manager semantics, now stated

These follow from reading through `_default_manager`. Neither is new — the
previous code behaved the same way — but neither was written down.

- A **hidden ancestor ends the chain**: its id is still returned, because its
  child names it, but nothing above it is.
- A **hidden node hides its whole subtree** from `get_permission_targets()` and
  `get_descendant_depth()`, not just itself, so those objects get no permissions
  from this domain's roles.

### Known limits

- The rules are enforced at write time, not by a database constraint, so two
  concurrent re-parents can still race into a cycle. That is why every read of
  the tree is cycle-safe rather than trusting the data.
