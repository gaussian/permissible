"""
Tests for bulk_update_permissions_for_objects function.
"""
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.db import models

from guardian.shortcuts import get_group_perms

from permissible.models import PermDomain, PermDomainRole, PermDomainMember
from permissible.models.utils import bulk_update_permissions_for_objects, ObjectGroupPermSpec


# Dummy concrete models for testing (renamed to avoid conflicts)
class BulkTestDomain(PermDomain):
    """A concrete PermDomain for testing."""

    name = models.CharField(max_length=100)

    groups = models.ManyToManyField(
        Group, through="BulkTestDomainRole", related_name="bulk_test_domain_groups"
    )
    users = models.ManyToManyField(
        get_user_model(), through="BulkTestDomainMember", related_name="bulk_test_domain_users"
    )

    class Meta:
        app_label = "permissible"
        abstract = False

    def __str__(self):
        return self.name

    @classmethod
    def get_permission_codenames(cls, short_perm_codes, include_app_label):
        """Return custom permission codenames for testing."""
        if include_app_label:
            return {f"permissible.bulk_test_{code}" for code in short_perm_codes}
        else:
            return {f"bulk_test_{code}" for code in short_perm_codes}


class BulkTestDomainRole(PermDomainRole):
    """A concrete PermDomainRole for testing."""

    bulktestdomain = models.ForeignKey(
        BulkTestDomain, on_delete=models.CASCADE, related_name="bulk_test_domain_roles"
    )

    class Meta:
        app_label = "permissible"
        abstract = False


class BulkTestDomainMember(PermDomainMember):
    """A concrete PermDomainMember for testing."""

    bulktestdomain = models.ForeignKey(
        BulkTestDomain, on_delete=models.CASCADE, related_name="bulk_test_domain_members"
    )

    class Meta:
        app_label = "permissible"
        abstract = False
        unique_together = ("bulktestdomain", "user")


class BulkUpdatePermissionsTests(TestCase):
    """Tests for bulk_update_permissions_for_objects function."""

    @classmethod
    def setUpTestData(cls):
        cls.User = get_user_model()

    def setUp(self):
        """Clean up before each test."""
        BulkTestDomainRole.objects.all().delete()
        BulkTestDomainMember.objects.all().delete()
        Group.objects.all().delete()
        BulkTestDomain.objects.all().delete()

    def test_bulk_update_single_object_single_permission(self):
        """Test updating permissions for a single object with a single permission."""
        # Create test data
        domain = BulkTestDomain.objects.create(name="Test Domain 1")
        group = Group.objects.create(name="Test Group 1")

        # Create spec
        specs = [
            ObjectGroupPermSpec(
                obj=domain,
                group=group,
                short_perm_codes=["view"],
            )
        ]

        # Call bulk update
        bulk_update_permissions_for_objects(specs)

        # Verify permissions were set
        perms = get_group_perms(group, domain)
        expected_perms = BulkTestDomain.get_permission_codenames(["view"], include_app_label=False)
        self.assertEqual(set(perms), expected_perms)

    def test_bulk_update_single_object_multiple_permissions(self):
        """Test updating permissions for a single object with multiple permissions."""
        domain = BulkTestDomain.objects.create(name="Test Domain 2")
        group = Group.objects.create(name="Test Group 2")

        specs = [
            ObjectGroupPermSpec(
                obj=domain,
                group=group,
                short_perm_codes=["view", "add", "change"],
            )
        ]

        bulk_update_permissions_for_objects(specs)

        perms = get_group_perms(group, domain)
        expected_perms = BulkTestDomain.get_permission_codenames(
            ["view", "add", "change"], include_app_label=False
        )
        self.assertEqual(set(perms), expected_perms)

    def test_bulk_update_multiple_objects_same_group(self):
        """Test updating permissions for multiple objects with the same group."""
        domain1 = BulkTestDomain.objects.create(name="Test Domain 3a")
        domain2 = BulkTestDomain.objects.create(name="Test Domain 3b")
        group = Group.objects.create(name="Test Group 3")

        specs = [
            ObjectGroupPermSpec(obj=domain1, group=group, short_perm_codes=["view"]),
            ObjectGroupPermSpec(obj=domain2, group=group, short_perm_codes=["view", "change"]),
        ]

        bulk_update_permissions_for_objects(specs)

        # Verify permissions for domain1
        perms1 = get_group_perms(group, domain1)
        expected_perms1 = BulkTestDomain.get_permission_codenames(["view"], include_app_label=False)
        self.assertEqual(set(perms1), expected_perms1)

        # Verify permissions for domain2
        perms2 = get_group_perms(group, domain2)
        expected_perms2 = BulkTestDomain.get_permission_codenames(
            ["view", "change"], include_app_label=False
        )
        self.assertEqual(set(perms2), expected_perms2)

    def test_bulk_update_multiple_groups_same_object(self):
        """Test updating permissions for multiple groups on the same object."""
        domain = BulkTestDomain.objects.create(name="Test Domain 4")
        group1 = Group.objects.create(name="Test Group 4a")
        group2 = Group.objects.create(name="Test Group 4b")

        specs = [
            ObjectGroupPermSpec(obj=domain, group=group1, short_perm_codes=["view"]),
            ObjectGroupPermSpec(obj=domain, group=group2, short_perm_codes=["view", "change", "delete"]),
        ]

        bulk_update_permissions_for_objects(specs)

        # Verify permissions for group1
        perms1 = get_group_perms(group1, domain)
        expected_perms1 = BulkTestDomain.get_permission_codenames(["view"], include_app_label=False)
        self.assertEqual(set(perms1), expected_perms1)

        # Verify permissions for group2
        perms2 = get_group_perms(group2, domain)
        expected_perms2 = BulkTestDomain.get_permission_codenames(
            ["view", "change", "delete"], include_app_label=False
        )
        self.assertEqual(set(perms2), expected_perms2)

    def test_bulk_update_removes_old_permissions(self):
        """Test that old permissions are removed when updating."""
        domain = BulkTestDomain.objects.create(name="Test Domain 5")
        group = Group.objects.create(name="Test Group 5")

        # First, set some permissions
        specs1 = [
            ObjectGroupPermSpec(
                obj=domain, group=group, short_perm_codes=["view", "change", "delete"]
            )
        ]
        bulk_update_permissions_for_objects(specs1)

        # Verify initial permissions
        perms_before = get_group_perms(group, domain)
        expected_perms_before = BulkTestDomain.get_permission_codenames(
            ["view", "change", "delete"], include_app_label=False
        )
        self.assertEqual(set(perms_before), expected_perms_before)

        # Now update to only have "view" permission
        specs2 = [
            ObjectGroupPermSpec(obj=domain, group=group, short_perm_codes=["view"])
        ]
        bulk_update_permissions_for_objects(specs2)

        # Verify updated permissions
        perms_after = get_group_perms(group, domain)
        expected_perms_after = BulkTestDomain.get_permission_codenames(
            ["view"], include_app_label=False
        )
        self.assertEqual(set(perms_after), expected_perms_after)

    def test_bulk_update_adds_new_permissions(self):
        """Test that new permissions are added when updating."""
        domain = BulkTestDomain.objects.create(name="Test Domain 6")
        group = Group.objects.create(name="Test Group 6")

        # First, set minimal permissions
        specs1 = [
            ObjectGroupPermSpec(obj=domain, group=group, short_perm_codes=["view"])
        ]
        bulk_update_permissions_for_objects(specs1)

        # Verify initial permissions
        perms_before = get_group_perms(group, domain)
        expected_perms_before = BulkTestDomain.get_permission_codenames(
            ["view"], include_app_label=False
        )
        self.assertEqual(set(perms_before), expected_perms_before)

        # Now update to add more permissions
        specs2 = [
            ObjectGroupPermSpec(
                obj=domain, group=group, short_perm_codes=["view", "change", "delete"]
            )
        ]
        bulk_update_permissions_for_objects(specs2)

        # Verify updated permissions
        perms_after = get_group_perms(group, domain)
        expected_perms_after = BulkTestDomain.get_permission_codenames(
            ["view", "change", "delete"], include_app_label=False
        )
        self.assertEqual(set(perms_after), expected_perms_after)

    def test_bulk_update_empty_permissions(self):
        """Test setting empty permissions removes all permissions."""
        domain = BulkTestDomain.objects.create(name="Test Domain 7")
        group = Group.objects.create(name="Test Group 7")

        # First, set some permissions
        specs1 = [
            ObjectGroupPermSpec(obj=domain, group=group, short_perm_codes=["view", "change"])
        ]
        bulk_update_permissions_for_objects(specs1)

        # Verify initial permissions
        perms_before = get_group_perms(group, domain)
        self.assertTrue(len(perms_before) > 0)

        # Now update to empty permissions
        specs2 = [
            ObjectGroupPermSpec(obj=domain, group=group, short_perm_codes=[])
        ]
        bulk_update_permissions_for_objects(specs2)

        # Verify all permissions removed
        perms_after = get_group_perms(group, domain)
        self.assertEqual(len(perms_after), 0)

    def test_bulk_update_many_objects_many_groups(self):
        """Test bulk update with many objects and groups for performance."""
        # Create multiple domains and groups
        domains = [BulkTestDomain.objects.create(name=f"Test Domain {i}") for i in range(10)]
        groups = [Group.objects.create(name=f"Test Group {i}") for i in range(5)]

        # Create specs for all combinations
        specs = []
        for domain in domains:
            for group in groups:
                specs.append(
                    ObjectGroupPermSpec(
                        obj=domain,
                        group=group,
                        short_perm_codes=["view", "change"],
                    )
                )

        # Call bulk update (should be efficient)
        bulk_update_permissions_for_objects(specs)

        # Verify a few random combinations
        perms = get_group_perms(groups[0], domains[0])
        expected_perms = BulkTestDomain.get_permission_codenames(
            ["view", "change"], include_app_label=False
        )
        self.assertEqual(set(perms), expected_perms)

        perms = get_group_perms(groups[4], domains[9])
        self.assertEqual(set(perms), expected_perms)

    def test_bulk_update_creates_missing_permissions(self):
        """Test that bulk update creates missing Permission objects."""
        domain = BulkTestDomain.objects.create(name="Test Domain 8")
        group = Group.objects.create(name="Test Group 8")

        ct = ContentType.objects.get_for_model(BulkTestDomain)

        # Ensure the custom permission doesn't exist
        Permission.objects.filter(content_type=ct, codename="dummy_newperm").delete()

        # Create spec with a permission that doesn't exist
        specs = [
            ObjectGroupPermSpec(obj=domain, group=group, short_perm_codes=["newperm"])
        ]

        # Call bulk update - should create the permission
        bulk_update_permissions_for_objects(specs)

        # Verify the permission was created
        perm_exists = Permission.objects.filter(
            content_type=ct, codename="bulk_test_newperm"
        ).exists()
        self.assertTrue(perm_exists, "Missing permission should have been created")

        # Verify the permission was assigned
        perms = get_group_perms(group, domain)
        expected_perms = BulkTestDomain.get_permission_codenames(
            ["newperm"], include_app_label=False
        )
        self.assertEqual(set(perms), expected_perms)

    def test_bulk_update_no_changes_needed(self):
        """Test that bulk update handles the case where no changes are needed."""
        domain = BulkTestDomain.objects.create(name="Test Domain 9")
        group = Group.objects.create(name="Test Group 9")

        # Set permissions
        specs = [
            ObjectGroupPermSpec(obj=domain, group=group, short_perm_codes=["view"])
        ]
        bulk_update_permissions_for_objects(specs)

        # Call again with same permissions - should be a no-op
        bulk_update_permissions_for_objects(specs)

        # Verify permissions are still correct
        perms = get_group_perms(group, domain)
        expected_perms = BulkTestDomain.get_permission_codenames(["view"], include_app_label=False)
        self.assertEqual(set(perms), expected_perms)

    def test_bulk_update_with_empty_spec_list(self):
        """Test that bulk update handles empty spec list gracefully."""
        # Should not raise an error
        bulk_update_permissions_for_objects([])

    def test_bulk_update_idempotent(self):
        """Test that calling bulk update multiple times with same specs is idempotent."""
        domain = BulkTestDomain.objects.create(name="Test Domain 10")
        group = Group.objects.create(name="Test Group 10")

        specs = [
            ObjectGroupPermSpec(
                obj=domain, group=group, short_perm_codes=["view", "change"]
            )
        ]

        # Call multiple times
        bulk_update_permissions_for_objects(specs)
        bulk_update_permissions_for_objects(specs)
        bulk_update_permissions_for_objects(specs)

        # Verify permissions are correct
        perms = get_group_perms(group, domain)
        expected_perms = BulkTestDomain.get_permission_codenames(
            ["view", "change"], include_app_label=False
        )
        self.assertEqual(set(perms), expected_perms)
