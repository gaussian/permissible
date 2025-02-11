"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from __future__ import annotations

from django.db import models

from .perm_root import PermRoot


class HierarchicalPermRoot(PermRoot):
    """
    HierarchicalPermRoot extends PermRoot by adding a parent/children relationship,
    and propagating permissions to all parents/ancestors.
    """

    parent = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="children",
    )

    class Meta:
        abstract = True

    def get_permission_targets(self):
        """
        Return an iterable (or generator) of PermRoot objects for which
        permissions should be set based on this instance.
        In this case, as opposed to the base class, we need to include
        all DESCENDANTS in the set of permission targets.
        """
        # First yield this object itself
        yield self

        # Then yield all children (recursive)
        for child in self.children.all():
            yield from child.get_permission_targets()

    @classmethod
    def get_ancestor_ids_from_id(cls, parent_id):
        """
        Given a parent_id (or None), return a set of all ancestor IDs, (parent,
        parent's parent, etc) walking up the hierarchy without instantiating full
        objects.
        """
        ancestor_ids = set()
        current_id = parent_id
        while current_id:
            ancestor_ids.add(current_id)
            # Retrieve only the parent_id of the current ancestor.
            current_id = (
                cls.objects.filter(pk=current_id)
                .values_list("parent_id", flat=True)
                .first()
            )
        return ancestor_ids

    def save(self, *args, **kwargs):
        """
        Override save() to check if the parent field has changed. If so,
        reset permissions for all ancestors, since their permission set needs
        to be updated.

        We must reset permissions both ancestors using the OLD value of
        `parent_id` as well as the NEW value of `parent_id`.
        """

        # Check if the parent has changed
        old_parent_id = None
        if self.pk:
            old_parent_id = (
                type(self)
                .objects.filter(pk=self.pk)
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
            old_ancestor_ids = (
                HierarchicalPermRoot.get_ancestor_ids_from_id(old_parent_id)
                if old_parent_id
                else set()
            )
            new_ancestor_ids = (
                HierarchicalPermRoot.get_ancestor_ids_from_id(self.parent_id)
                if self.parent_id
                else set()
            )

            # Compute the symmetric difference: only those ancestors that differ
            diff_ids = old_ancestor_ids.symmetric_difference(new_ancestor_ids)
            assert diff_ids

            # Update only the affected ancestors
            for ancestor in self.__class__.objects.filter(pk__in=diff_ids):
                ancestor.reset_perm_groups()

        return result
