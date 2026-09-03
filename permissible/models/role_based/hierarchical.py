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
    """
    The one-column queryset both ancestor walks step through.

    Uses `_default_manager` (not `objects`), so a model with a soft-delete
    default manager hides soft-deleted rows from the walk. See
    `walk_ancestor_ids` for what that means for the result.
    """
    return model._default_manager.filter(pk=current_id).values_list(
        "parent_id", flat=True
    )


def _accept_ancestor(model, current_id, ancestor_ids, seen, start_id, max_levels):
    """
    Decide whether the walk takes `current_id`, and record it if so.

    Shared by the sync and async walks so the stop conditions and their log
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


def _resolve_max_levels(model, max_levels):
    """
    Return the level cap to use, defaulting to one less than the model's
    `MAX_HIERARCHY_DEPTH` (the chain above a node, excluding the node itself).
    """
    if max_levels is None:
        return model.MAX_HIERARCHY_DEPTH - 1
    return max_levels


def walk_ancestor_ids(model, start_id, exclude_id=None, max_levels=None) -> list:
    """
    Walk the parent chain from `start_id` upwards and return the ids in order,
    nearest first.

    The walk costs one small query per level and instantiates no model rows.
    It stops:
    - at a `None` parent (the root);
    - at any repeated id (a cycle) - logged with `logger.error`;
    - at `max_levels` ids (default `model.MAX_HIERARCHY_DEPTH - 1`) - logged
      with `logger.warning`.

    Neither stop condition raises. A malformed chain neither hangs nor recurses.

    Pass `exclude_id` (normally the walking object's own pk) to seed the seen
    set, so a chain that loops back to that object stops on the first repeat
    instead of after a full lap.

    IMPORTANT: the walk reads through `model._default_manager`. For a model
    whose default manager hides rows (a soft-delete manager, for example), a
    hidden ancestor is invisible and therefore ENDS the chain: nothing above it
    is returned.
    """
    max_levels = _resolve_max_levels(model, max_levels)
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
    """
    Async version of `walk_ancestor_ids`. Same order, same stop conditions,
    same log lines.
    """
    max_levels = _resolve_max_levels(model, max_levels)
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

        The walk is iterative and breadth-first, one query per level rather
        than one query per node. A visited set keeps each node to a single
        yield, so a cycle in the tree yields each node once instead of raising
        `RecursionError`.
        """
        # First yield this object itself
        yield self

        if not self.pk:
            return

        manager = type(self)._default_manager
        seen = {self.pk}
        frontier = [self.pk]

        # Then yield all descendants, one level (and one query) at a time
        while frontier:
            children = list(manager.filter(parent_id__in=frontier).exclude(pk__in=seen))
            if not children:
                break
            child_ids = [child.pk for child in children]
            seen.update(child_ids)
            yield from children
            frontier = child_ids

    def get_ancestor_ids(self, max_levels=None) -> list:
        """
        Return the ids of this object's ancestors, NEAREST FIRST (parent,
        grandparent, ...), excluding this object itself.

        See `walk_ancestor_ids` for the stop conditions and for the effect of a
        filtering default manager.
        """
        return walk_ancestor_ids(
            type(self), self.parent_id, exclude_id=self.pk, max_levels=max_levels
        )

    async def aget_ancestor_ids(self, max_levels=None) -> list:
        """
        Async version of `get_ancestor_ids`.
        """
        return await awalk_ancestor_ids(
            type(self), self.parent_id, exclude_id=self.pk, max_levels=max_levels
        )

    def get_descendant_depth(self) -> int:
        """
        Return the number of levels below this object, 0 for a leaf.

        Breadth-first by id, one query per level, bounded by
        `MAX_HIERARCHY_DEPTH` and by an already-seen set, so a cycle cannot
        spin.
        """
        if not self.pk:
            return 0

        manager = type(self)._default_manager
        height = 0
        frontier = [self.pk]
        seen = {self.pk}

        while frontier and height < self.MAX_HIERARCHY_DEPTH:
            child_ids = list(
                manager.filter(parent_id__in=frontier)
                .exclude(pk__in=seen)
                .values_list("pk", flat=True)
            )
            if not child_ids:
                break
            seen.update(child_ids)
            frontier = child_ids
            height += 1

        return height

    def validate_hierarchy(self) -> None:
        """
        Check the PENDING `parent_id` against the hierarchy rules.

        Raises `ValidationError` keyed on "parent" when the new parent would:
        - make this object its own parent;
        - place this object inside its own ancestor chain (a cycle);
        - push the total chain past `MAX_HIERARCHY_DEPTH`.

        The depth check counts the ancestors above the new parent, plus this
        object, plus `get_descendant_depth()`, so an existing subtree cannot be
        re-parented under a deep node to slip past the cap.
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

    def clean(self):
        super().clean()
        self.validate_hierarchy()

    @classmethod
    def get_ancestor_ids_from_id(cls, parent_id, max_levels=None) -> list:
        """
        Given a parent_id (or None), return the ids of that ancestor chain
        (parent, parent's parent, etc), NEAREST FIRST, walking up the hierarchy
        without instantiating full objects.

        Returns an ordered list. It used to return an unordered set, and it used
        to loop forever on a cycle; see `walk_ancestor_ids` for the stop
        conditions.
        """
        if parent_id is None:
            return []
        return walk_ancestor_ids(cls, parent_id, max_levels=max_levels)

    def save(self, *args, **kwargs):
        """
        Override save() to check if the parent field has changed. If so,
        reset permissions for all ancestors, since their permission set needs
        to be updated.

        We must reset permissions both ancestors using the OLD value of
        `parent_id` as well as the NEW value of `parent_id`.

        The hierarchy rules (`validate_hierarchy`) are enforced here as well as
        in `clean()`, because most writes to `parent` never pass through a
        ModelForm.
        """

        model_class = type(self)

        # `parent` cannot change when it is absent from `update_fields`, so a
        # partial save such as save(update_fields=["name"]) pays for no
        # hierarchy queries at all.
        update_fields = kwargs.get("update_fields")
        if update_fields is not None and not (
            "parent" in update_fields or "parent_id" in update_fields
        ):
            return super().save(*args, **kwargs)

        # Enforce the cycle and depth rules (this also rejects self-parenting)
        self.validate_hierarchy()

        # Check if the parent has changed
        old_parent_id = None
        if self.pk:
            old_parent_id = (
                model_class.objects.filter(pk=self.pk)
                .values_list("parent_id", flat=True)
                .first()
            )

        # Save the object as usual
        result = super().save(*args, **kwargs)

        # When the parent has changed, reset permissions for ALL ANCESTORS
        # of the PREVIOUS parent as well as the CURRENT parent.
        # (because the permission set of the parent may have changed)
        if old_parent_id != self.parent_id:
            # Get the ancestor IDs for both the old and new ancestor chains
            old_ancestor_ids = set(model_class.get_ancestor_ids_from_id(old_parent_id))
            new_ancestor_ids = set(model_class.get_ancestor_ids_from_id(self.parent_id))

            # Get all ancestors that are in the union of the old and new ancestor chains
            # (because both old and new ancestor chains will have new CHILDREN)
            all_ancestors = model_class.objects.filter(
                pk__in=old_ancestor_ids.union(new_ancestor_ids)
            )

            # Update all affected ancestors
            for ancestor in all_ancestors:
                ancestor.reset_domain_roles()

        return result
