import unittest
from unittest.mock import patch

from django.db import models
from django.test import TestCase
from django.contrib.auth.models import Group
from django.contrib.auth import get_user_model

from permissible.models.role_based.hierarchical import HierarchicalPermDomain
from permissible.models.role_based.core import PermDomainRole, PermDomainMember


# Define a dummy concrete model for HierarchicalPermDomain
class DummyHierarchicalDomain(HierarchicalPermDomain):
    name = models.CharField(max_length=100)
    groups = models.ManyToManyField(
        Group,
        through="DummyHierarchicalDomainRole",
        related_name="dummy_hierarchical_domains",
        blank=True,
    )
    users = models.ManyToManyField(
        get_user_model(),
        through="DummyHierarchicalDomainMember",
        related_name="dummy_hierarchical_domains",
        blank=True,
    )

    def __str__(self):
        return self.name

    class Meta:
        app_label = "permissible"  # Ensure proper app_label for testing


# Define a dummy domain role model that links DummyHierarchicalDomain to roles
class DummyHierarchicalDomainRole(PermDomainRole):
    domain = models.ForeignKey(
        DummyHierarchicalDomain, on_delete=models.CASCADE, related_name="domain_roles"
    )

    # Use the standard role definitions from PermDomainRole
    ROLE_DEFINITIONS = {
        "mem": ("Member", []),
        "view": ("Viewer", ["view"]),
        "adm": ("Admin", ["view", "change", "delete"]),
    }

    # Define role field using the build_role_field utility from PermDomainRole
    role = models.CharField(
        choices=[(k, v[0]) for k, v in ROLE_DEFINITIONS.items()],
        max_length=4,
        default="mem",
    )

    class Meta:
        app_label = "permissible"
        # Group and domain together must be unique
        unique_together = ("group", "domain")


class DummyHierarchicalDomainMember(PermDomainMember):
    """
    A concrete PermDomainMember. It joins HierarchicalPermDomain to a User.
    """

    dummydomain = models.ForeignKey(
        DummyHierarchicalDomain,
        on_delete=models.CASCADE,
        related_name="dummydomain_members",
    )

    class Meta:
        app_label = "permissible"


class HierarchicalPermDomainTests(TestCase):

    def setUp(self):
        # Create a simple hierarchy:
        #         Root
        #           |
        #        Child1
        #          /  \
        #    Child2   Child3
        self.domain = DummyHierarchicalDomain.objects.create(name="Root")
        self.child1 = DummyHierarchicalDomain.objects.create(
            name="Child1", parent=self.domain
        )
        self.child2 = DummyHierarchicalDomain.objects.create(
            name="Child2", parent=self.child1
        )
        self.child3 = DummyHierarchicalDomain.objects.create(
            name="Child3", parent=self.child1
        )

    def test_get_permission_targets(self):
        """
        Test that get_permission_targets returns self and all descendants recursively.
        """
        targets = list(self.domain.get_permission_targets())
        target_names = {t.name for t in targets}
        expected_names = {"Root", "Child1", "Child2", "Child3"}
        self.assertEqual(target_names, expected_names)

    def test_get_permission_targets_child(self):
        """
        Test that get_permission_targets on an intermediate node returns self and its descendants.
        """
        targets = list(self.child1.get_permission_targets())
        target_names = {t.name for t in targets}
        expected_names = {"Child1", "Child2", "Child3"}
        self.assertEqual(target_names, expected_names)

    def test_get_ancestor_ids_from_id(self):
        """
        Test that get_ancestor_ids_from_id returns the correct set of ancestor IDs.
        """
        # For child2, ancestors are child1 and domain (order doesn't matter).
        ancestor_ids = DummyHierarchicalDomain.get_ancestor_ids_from_id(self.child1.pk)
        self.assertIn(self.child1.pk, ancestor_ids)
        # For child2, get ancestors via parent chain.
        ancestor_ids_child2 = DummyHierarchicalDomain.get_ancestor_ids_from_id(
            self.child2.parent.pk
        )
        expected = {self.child1.pk, self.domain.pk}
        self.assertEqual(ancestor_ids_child2, expected)

    def test_get_ancestor_ids_from_none(self):
        """
        Test that get_ancestor_ids_from_id returns an empty set for a None parent_id.
        """
        ancestor_ids = DummyHierarchicalDomain.get_ancestor_ids_from_id(None)
        self.assertEqual(ancestor_ids, set())

    @patch.object(DummyHierarchicalDomain, "reset_domain_roles")
    def test_save_parent_changed_calls_reset_on_ancestors(self, mock_reset):
        """
        Test that when a HierarchicalPermDomain instance has its parent changed,
        reset_domain_roles is called on ancestors that differ.
        """
        # Initially, child1.parent is domain.
        # Change child1's parent to None.
        self.child1.parent = None
        self.child1.save()

        # The reset_domain_roles on affected ancestors should have been called.
        # We expect at least one call: on the old ancestor (domain) or on child1 itself.
        self.assertTrue(mock_reset.called)

    def test_save_no_parent_change_does_not_call_reset(self):
        """
        Test that saving an instance without changing its parent does not trigger ancestor resets.
        """
        # Save child1 without changing the parent.
        with patch.object(DummyHierarchicalDomain, "reset_domain_roles") as mock_reset:
            self.child1.name = "Child1 Updated"
            self.child1.save()
            mock_reset.assert_not_called()


if __name__ == "__main__":
    unittest.main()
