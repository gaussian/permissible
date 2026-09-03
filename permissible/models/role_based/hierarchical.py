"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from __future__ import annotations

import logging

from django.core.exceptions import ValidationError
from django.db import models

from .core import PermDomain

logger = logging.getLogger(__name__)


def _parent_id_queryset(model, current_id):
    """The one-column queryset both ancestor walks step through."""
    return model._default_manager.filter(pk=current_id).values_list(
        "parent_id", flat=True
    )


def _accept_ancestor(model, current_id, ancestor_ids, seen, start_id, max_levels):
    """
    Decide whether the walk takes `current_id`, and record it if so.

    Shared by the sync and async walks, so the stop conditions and their log
    lines exist once.

    Returns:
        True when the id was accepted, False when the walk must stop.
    """
    if current_id in seen:
        logger.error(
            "Cycle in %s parent chain at id %s; stopping the walk",
            model.__name__,
            current_id,
        )
        return False

    if len(ancestor_ids) >= max_levels:
        logger.warning(
            "%s parent chain from id %s is deeper than %s levels; stopping there",
            model.__name__,
            start_id,
            max_levels,
        )
        return False

    seen.add(current_id)
    ancestor_ids.append(current_id)
    return True


def walk_ancestor_ids(model, start_id, exclude_id=None, max_levels=None) -> list:
    """
    Walk the parent chain up from `start_id`, returning ids NEAREST FIRST.

    One small query per level; no model rows are built. The walk stops at a
    `None` parent, at any repeated id (a cycle - `logger.error`), and at
    `max_levels` ids (default `MAX_HIERARCHY_DEPTH - 1` - `logger.warning`).
    Neither stop condition raises, so a malformed chain neither hangs nor
    recurses.

    Pass `exclude_id` (normally the walking object's own pk) to seed the seen
    set, so a chain that loops back to that object stops on the first repeat
    rather than after a full lap.

    IMPORTANT: the walk reads through `model._default_manager`. A default
    manager that hides rows (soft delete, for example) therefore ENDS the chain
    at a hidden ancestor: that ancestor's id is still returned, because its
    child names it, but nothing above it is.
    """
    if max_levels is None:
        max_levels = model.MAX_HIERARCHY_DEPTH - 1

    ancestor_ids = []
    seen = set() if exclude_id is None else {exclude_id}
    current_id = start_id

    while current_id is not None:
        if not _accept_ancestor(
            model, current_id, ancestor_ids, seen, start_id, max_levels
        ):
            break
        current_id = _parent_id_queryset(model, current_id).first()

    return ancestor_ids


async def awalk_ancestor_ids(model, start_id, exclude_id=None, max_levels=None) -> list:
    """Async `walk_ancestor_ids`: same order, stop conditions and log lines."""
    if max_levels is None:
        max_levels = model.MAX_HIERARCHY_DEPTH - 1

    ancestor_ids = []
    seen = set() if exclude_id is None else {exclude_id}
    current_id = start_id

    while current_id is not None:
        if not _accept_ancestor(
            model, current_id, ancestor_ids, seen, start_id, max_levels
        ):
            break
        current_id = await _parent_id_queryset(model, current_id).afirst()

    return ancestor_ids


def _iter_descendant_levels(model, root_id, max_levels=None, ids_only=False):
    """
    Yield the descendants of `root_id` one level at a time, nearest level first.

    One query per level rather than one per node. Every node already seen is
    excluded from the next query, so each node is yielded at most once and a
    cycle cannot spin - `max_levels` is a cost bound, not the reason the walk
    terminates. Pass `ids_only` to read the pk column instead of whole rows.
    """
    manager = model._default_manager
    seen = {root_id}
    frontier = [root_id]
    levels_done = 0

    while max_levels is None or levels_done < max_levels:
        queryset = manager.filter(parent_id__in=frontier).exclude(pk__in=seen)
        level = list(queryset.values_list("pk", flat=True) if ids_only else queryset)
        if not level:
            return
        frontier = level if ids_only else [obj.pk for obj in level]
        seen.update(frontier)
        yield level
        levels_done += 1


class HierarchicalPermDomain(PermDomain):
    """
    HierarchicalPermDomain extends PermDomain by adding a parent/children relationship,
    and propagating permissions to all parents/ancestors.
    """

    # Maximum number of levels in a parent chain, counting the root as level 1.
    # Salesforce reports write-time degradation in most orgs beyond seven levels of role
    # hierarchy; Google Workspace caps organizational units at 35 and advises staying flatter
    # above 50,000 users. Ten sits above the level at which the shape stops being useful to
    # model and well below the level at which it becomes a data-volume problem.
    # Subclasses may override.
    MAX_HIERARCHY_DEPTH = 10

    parent = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="children",
    )

    class Meta:
        abstract = True

    def get_permission_targets(self):
        """
        Return an iterable (or generator) of PermDomain objects for which
        permissions should be set based on this instance.
        In this case, as opposed to the base class, we need to include
        all DESCENDANTS in the set of permission targets.

        Deliberately uncapped: dropping a descendant here would silently
        withhold its permissions. The seen set in `_iter_descendant_levels` is
        what makes this terminate, cycle or no cycle.
        """
        yield self

        if not self.pk:
            return

        for level in _iter_descendant_levels(type(self), self.pk):
            yield from level

    def get_ancestor_ids(self, max_levels=None) -> list:
        """
        Return this object's ancestor ids NEAREST FIRST (parent, grandparent,
        ...), excluding this object itself.

        See `walk_ancestor_ids` for the stop conditions and for what a
        filtering default manager does to the result.
        """
        return walk_ancestor_ids(
            type(self), self.parent_id, exclude_id=self.pk, max_levels=max_levels
        )

    async def aget_ancestor_ids(self, max_levels=None) -> list:
        """Async `get_ancestor_ids`."""
        return await awalk_ancestor_ids(
            type(self), self.parent_id, exclude_id=self.pk, max_levels=max_levels
        )

    def get_descendant_depth(self) -> int:
        """
        Return the number of levels below this object; 0 for a leaf.
        One query per level, bounded by `MAX_HIERARCHY_DEPTH`.
        """
        if not self.pk:
            return 0

        return sum(
            1
            for _ in _iter_descendant_levels(
                type(self),
                self.pk,
                max_levels=self.MAX_HIERARCHY_DEPTH,
                ids_only=True,
            )
        )

    def validate_hierarchy(self) -> None:
        """
        Check the PENDING `parent_id` against the hierarchy rules, and raise
        `ValidationError` keyed on "parent" when it would make this object its
        own parent, put it inside its own ancestor chain, or push the tree past
        `MAX_HIERARCHY_DEPTH`.

        The depth check counts the ancestors above the new parent, plus this
        object, plus `get_descendant_depth()`, so an existing subtree cannot be
        re-parented under a deep node to slip past the cap.

        Callers should only run this when `parent` actually changed - see
        `save()`. It costs up to `2 * MAX_HIERARCHY_DEPTH` queries.
        """
        if self.parent_id is None:
            return

        if self.pk and self.parent_id == self.pk:
            raise ValidationError({"parent": "An object cannot be its own parent."})

        # Walk with one level of headroom over the cap, so an over-deep chain is
        # MEASURED rather than truncated to the cap and found compliant.
        ancestor_ids = walk_ancestor_ids(
            type(self), self.parent_id, max_levels=self.MAX_HIERARCHY_DEPTH
        )
        if self.pk and self.pk in ancestor_ids:
            raise ValidationError(
                {"parent": "That parent would create a cycle in the hierarchy."}
            )

        levels = len(ancestor_ids) + 1 + self.get_descendant_depth()
        if levels > self.MAX_HIERARCHY_DEPTH:
            raise ValidationError(
                {
                    "parent": (
                        f"That parent would make the hierarchy {levels} levels deep; "
                        f"the maximum is {self.MAX_HIERARCHY_DEPTH}."
                    )
                }
            )

    def _get_stored_parent_id(self):
        """
        The `parent_id` currently in the database, or None when this object has
        no row yet. Read through `_default_manager`, like the walks.
        """
        if not self.pk:
            return None
        return (
            type(self)
            ._default_manager.filter(pk=self.pk)
            .values_list("parent_id", flat=True)
            .first()
        )

    def clean(self):
        super().clean()

        # Same gate as save(): only a CHANGED parent can break the rules.
        # Re-checking an unchanged one would block an ordinary form edit - a
        # rename, say - on a tree that was already over the cap.
        if self._get_stored_parent_id() != self.parent_id:
            self.validate_hierarchy()

    @classmethod
    def get_ancestor_ids_from_id(cls, parent_id, max_levels=None) -> list:
        """
        Given a parent_id (or None), return that ancestor chain (parent,
        parent's parent, etc) NEAREST FIRST, without instantiating full objects.

        Returns an ordered list; it used to return an unordered set, and it used
        to loop forever on a cycle. See `walk_ancestor_ids`.
        """
        return walk_ancestor_ids(cls, parent_id, max_levels=max_levels)

    def save(self, *args, **kwargs):
        """
        Override save() to check if the parent field has changed. If so,
        validate the hierarchy rules and reset permissions for all ancestors,
        since their permission set needs to be updated.

        We must reset permissions both ancestors using the OLD value of
        `parent_id` as well as the NEW value of `parent_id`.

        The rules are enforced here as well as in `clean()`, because most writes
        to `parent` never pass through a ModelForm. A save that leaves `parent`
        alone does no hierarchy work at all.
        """

        model_class = type(self)

        # `parent` cannot change when it is absent from `update_fields`, so a
        # partial save such as save(update_fields=["name"]) can skip everything
        # below, including the query for the stored parent.
        update_fields = kwargs.get("update_fields")
        if update_fields is not None:
            # Django accepts ANY iterable here and materialises it itself, so
            # test a copy: a generator consumed below would reach super().save()
            # empty.
            update_fields = kwargs["update_fields"] = frozenset(update_fields)
            if not {"parent", "parent_id"} & update_fields:
                return super().save(*args, **kwargs)

        # Check if the parent has changed (1 query, which the ancestor reset
        # below needs anyway)
        old_parent_id = self._get_stored_parent_id()
        parent_changed = old_parent_id != self.parent_id

        # Only a CHANGED parent can break the rules, and only then is it worth
        # paying for the ancestor and descendant walks. This also keeps an
        # unrelated save from failing on a tree that was already non-compliant.
        if parent_changed:
            self.validate_hierarchy()

        # Save the object as usual
        result = super().save(*args, **kwargs)

        # When the parent has changed, reset permissions for ALL ANCESTORS
        # of the PREVIOUS parent as well as the CURRENT parent.
        # (because the permission set of the parent may have changed)
        if parent_changed:
            # Get the ancestor IDs for both the old and new ancestor chains
            old_ancestor_ids = model_class.get_ancestor_ids_from_id(old_parent_id)
            new_ancestor_ids = model_class.get_ancestor_ids_from_id(self.parent_id)

            # Get all ancestors that are in the union of the old and new ancestor chains
            # (because both old and new ancestor chains will have new CHILDREN)
            all_ancestors = model_class._default_manager.filter(
                pk__in=set(old_ancestor_ids) | set(new_ancestor_ids)
            )

            # Update all affected ancestors
            for ancestor in all_ancestors:
                ancestor.reset_domain_roles()

        return result
