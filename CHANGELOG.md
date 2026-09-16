# Changelog

## 0.12.2

Refusable grants, from `neutron`'s invite-apply and SSO-provisioning paths.

- `permissible.exceptions.RoleGrantRefused` (`code = "grant_refused"`): an
  `m2m_changed` receiver on `Group.user_set` raises a subclass to veto a grant.
  `PermDomainMemberViewSetMixin` maps it to 409 `{"code", "detail"}`.
- `set_roles_for_user(..., member_if_refused=False)`: with `True`, a refusal
  is logged at error and the user keeps the roles they held, plus
  `MEMBER_ROLE`. For unattended grants, where nobody reads a refusal.

## 0.12.1

- Fix: import cycle that broke every consumer at import in 0.12.0.
  `CheckViewConfigMixin` moved to `permissible.utils.views`.

## 0.12.0

The member-roles endpoint and its helpers, from `neutron`.

- `MEMBER_ROLE = "mem"` (`permissible.models`).
- `PermDomain.get_roles_for_user(user)`: the codes `user` holds; one query.
- `PermDomain.set_roles_for_user(user, roles, by=None)`: replace semantics.
  Adds before it removes, so the member row keeps its id; `MEMBER_ROLE` is
  always kept; an unknown code raises `ValueError`. One transaction; with
  `by=`, the role rows are locked as its first read. One query plus the
  guards and the group writes.
- `PermDomainRole.role_labels()`: `{code: label}`.
- `PermDomainFieldMixin.get_domain()`: the row's `PermDomain`.
- `PermDomainMemberViewSetMixin` (`permissible.views`): `PUT {id}/roles/`
  `{"roles": [code]}` (400 on an unknown code; returns the row) and
  `DELETE {id}/` (removes the held roles, then the row), both
  `by=request.user`. `RoleLockoutDenied` → 409; escalation stays 403. The
  member model's global policy needs `roles`; `make_domain_member_policy`
  is the object side.
- The member signal handles each domain once per change, not once per group.
- Known: with `ATOMIC_REQUESTS`, the no-lockout lock is not the request's
  first read (MySQL only; Postgres is unaffected).

## 0.11.0

Guards for changing a member's roles on a `PermDomain`; `make_domain_member_policy`
fixed and reshaped.

### Added

- `assign_roles_to_user()` / `remove_roles_from_user()` take `by=user`. Without
  it, nothing changes. With it:
  - **No escalation** (`check_role_change()`, public): `by` must hold, on the
    domain, every permission each role carries (`ROLE_DEFINITIONS`); role codes
    are never compared. A role carrying nothing (`mem` by default) is open to
    all; superusers pass via `has_perms`. Raises `RoleEscalationDenied`, or
    `ValueError` for an unknown role code. This bounds *which* roles `by` may
    touch; whether `by` may change roles at all is `change_permission` on the
    domain, gated by the caller.
  - **No lockout** (remove only): the change may not take the domain from one
    active `change_permission` holder to none. Fires on 1 → 0 only; only
    `is_active` users count; a domain with no manager stays as it is. The
    domain's role rows are locked (`select_for_update`) as the first read of
    the transaction, so two concurrent demotions cannot both pass. Raises
    `RoleLockoutDenied`.
  - Both subclass `RoleChangeDenied(PermissionDenied)`: DRF answers 403 unless
    the consumer handles them. All three live in `permissible.exceptions`.
- `remove_roles_from_user()` runs in `transaction.atomic()` for every caller;
  `groups.remove()` already was, so nothing visible changes.
- With `by=`, no escalation costs 2 queries and no lockout 3-4, on top of the
  unguarded call.

### Fixed

- `make_domain_member_policy()` never granted an admin: its `change_permission`
  check followed `"user"`, so it tested `change_permission_user` on the joined
  User (`AttributeError` without `PermissibleMixin` on User, else a denial), and
  `domain_name` was unused. Now `destroy` and a new `roles` action check
  `change_permission` on the domain; `retrieve`, `update` and `partial_update`
  are self-only (the admin branch never worked, so nothing that worked stops).

## 0.10.0

`HierarchicalPermDomain` tree traversal is now ordered, cycle-safe and
depth-capped, and both it and `reset_permissions()` do markedly less work.

### Breaking

**No known consumer is affected.** Every item below was checked against the
consuming repositories; the findings are stated per item.

- **`save()` now rejects writes it used to accept**: a parent that would create
  a cycle, or that would push the tree past `MAX_HIERARCHY_DEPTH`. *Nothing sets
  `parent` in `neutron` or `sapeum` - no tree is ever built, so no write can hit
  the cap.* If you do use the hierarchy, find over-deep rows before upgrading,
  or raise `MAX_HIERARCHY_DEPTH` on your subclass:

  ```python
  [obj for obj in Model.objects.all() if len(obj.get_ancestor_ids()) >= Model.MAX_HIERARCHY_DEPTH - 1]
  ```

- `get_ancestor_ids_from_id()` returns an **ordered list** (nearest first)
  instead of an unordered `set`, and takes a new optional `max_levels`. *No
  callers found outside this package, where only `save()` uses it.*
- `save()` raises `django.core.exceptions.ValidationError` keyed on `"parent"`
  where it used to raise `ValueError` for self-parenting. *No `except ValueError`
  found anywhere near a domain save, and no test asserts the old type or
  message.*

Not breaking, listed because it is a visible change in behaviour: an object
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
