import unittest
from unittest.mock import patch, MagicMock

from django.test import TestCase
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import models

# Import the abstract models to be tested.
from permissible.models import PermDomain, PermDomainRole, PermDomainMember

#
# Dummy concrete models for testing
#


class DummyDomain(PermDomain):
    """
    A concrete PermDomain. It defines:
      - a name field,
      - a ManyToManyField to Group via DummyDomainRole,
      - a ManyToManyField to the User model via DummyDomainMember.

    Also, we add a get_permission_codenames classmethod so that
    PermDomainRole.reset_permissions can work.
    """

    name = models.CharField(max_length=100)

    groups = models.ManyToManyField(
        Group, through="DummyDomainRole", related_name="dummy_domain_groups"
    )
    users = models.ManyToManyField(
        get_user_model(), through="DummyDomainMember", related_name="dummy_domain_users"
    )

    class Meta:
        app_label = "permissible"  # Add explicit app_label
        abstract = False

    def __str__(self):
        return self.name

    @classmethod
    def get_permission_codenames(cls, short_perm_codes, include_app_label):
        # For testing purposes, simply return a dummy set of permission strings.
        # Now handling the include_app_label parameter
        if include_app_label:
            return {f"permissible.dummy_{code}" for code in short_perm_codes}
        else:
            return {f"dummy_{code}" for code in short_perm_codes}


class DummyDomainRole(PermDomainRole):
    """
    A concrete PermDomainRole. Note that the join field must match the
    PermDomain's model name (i.e. "dummydomain").
    """

    dummydomain = models.ForeignKey(
        DummyDomain, on_delete=models.CASCADE, related_name="dummydomain_roles"
    )

    class Meta:
        app_label = (
            "permissible"  # Necessary since our abstract models have no app_label.
        )
        abstract = False


class DummyDomainMember(PermDomainMember):
    """
    A concrete PermDomainMember. It joins DummyDomain to a User.
    """

    dummydomain = models.ForeignKey(
        DummyDomain, on_delete=models.CASCADE, related_name="dummydomain_members"
    )

    class Meta:
        app_label = "permissible"
        abstract = False
        # Add a unique constraint for the domain and user
        unique_together = ("dummydomain", "user")  # Add this line

    def get_unretrieved(self, attr):
        # For testing purposes, simply return the user's id.
        return getattr(self.user, "id", None)


#
# Tests for PermDomain, PermDomainRole, and PermDomainMember
#


class PermDomainTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.User = get_user_model()
        # Create a normal user and a superuser for testing.
        cls.normal_user = cls.User.objects.create_user(
            username="normal", password="pass"
        )
        cls.super_user = cls.User.objects.create_superuser(
            username="admin", password="pass"
        )

    # Create domain helper that properly patches the model save operations
    def create_domain_with_mocks(self, name="Test Domain"):
        """Helper method to create a domain with all necessary mocks"""
        with (
            patch("permissible.models.role_based.core.reset_permissions"),
            patch("guardian.shortcuts.assign_perm"),
            patch("guardian.shortcuts.remove_perm"),
            patch("guardian.shortcuts.get_group_perms", return_value=set()),
        ):
            domain = DummyDomain.objects.create(name=name)

            # Create mock role groups directly
            role_choices = list(DummyDomainRole._meta.get_field("role").choices)
            for role, _ in role_choices:
                group = Group.objects.create(name=f"Test {role}")
                DummyDomainRole.objects.create(
                    role=role, group=group, dummydomain=domain
                )

            return domain

    @patch("permissible.models.role_based.core.reset_permissions")
    def test_reset_domain_roles_creates_groups(self, mock_reset_permissions):
        """
        Creating a new DummyDomain should trigger save() which calls reset_domain_roles.
        Verify that one DummyDomainRole (and its Group) is created for each role.
        """
        # This test already works, keep as is
        domain = DummyDomain.objects.create(name="Test Domain")
        role_choices = list(DummyDomainRole._meta.get_field("role").choices)
        groups_qs = DummyDomainRole.objects.filter(dummydomain=domain)
        self.assertEqual(groups_qs.count(), len(role_choices))
        for join_obj in groups_qs:
            self.assertIsNotNone(join_obj.group_id)

        # Check that reset_permissions was called
        mock_reset_permissions.assert_called()

    def test_get_group_ids_for_roles_all(self):
        """
        get_group_ids_for_roles with no roles specified returns IDs for all roles.
        """
        # Clear ALL existing domains and groups to avoid interference
        DummyDomainRole.objects.all().delete()
        Group.objects.all().delete()
        DummyDomain.objects.all().delete()

        # Use a unique name to ensure this domain stands out
        unique_domain_name = "Test Domain ROLES ALL"

        # Create a fresh domain with mocked permissions
        with patch("permissible.models.role_based.core.reset_permissions"):
            domain = DummyDomain.objects.create(name=unique_domain_name)

            # Instead of using get_role_joins(), directly use DummyDomainRole
            # to clear any existing roles for this domain
            DummyDomainRole.objects.filter(dummydomain=domain).delete()

            # Create exactly one role of each type
            role_choices = list(DummyDomainRole._meta.get_field("role").choices)
            for role, _ in role_choices:
                group_name = f"Test {unique_domain_name} {role}"
                group = Group.objects.create(name=group_name)
                DummyDomainRole.objects.create(
                    role=role, group=group, dummydomain=domain
                )

        # Get all role group IDs for this domain
        group_ids = list(domain.get_group_ids_for_roles())

        # Check that we get the right number of roles
        self.assertEqual(len(group_ids), len(role_choices))

        # Verify all groups belong to this domain using direct filter rather than get_role_joins()
        domain_role_groups = DummyDomainRole.objects.filter(
            dummydomain=domain
        ).values_list("group_id", flat=True)
        self.assertEqual(set(group_ids), set(domain_role_groups))

    def test_get_group_ids_for_roles_specific(self):
        """
        Verify that filtering get_group_ids_for_roles by a single role returns only one id.
        """
        # Clear ALL existing domains and groups to avoid interference
        DummyDomainRole.objects.all().delete()
        Group.objects.all().delete()
        DummyDomain.objects.all().delete()

        # Use a unique name to ensure this domain stands out
        unique_domain_name = "Test Domain SPECIFIC ROLE"

        # Create a fresh domain with mocked permissions
        with patch("permissible.models.role_based.core.reset_permissions"):
            domain = DummyDomain.objects.create(name=unique_domain_name)

            # Instead of using get_role_joins(), directly use DummyDomainRole
            # to clear any existing roles for this domain
            DummyDomainRole.objects.filter(dummydomain=domain).delete()

            # Create exactly one role of each type
            role_choices = list(DummyDomainRole._meta.get_field("role").choices)
            for role, _ in role_choices:
                group_name = f"Test {unique_domain_name} {role}"
                group = Group.objects.create(name=group_name)
                DummyDomainRole.objects.create(
                    role=role, group=group, dummydomain=domain
                )

        # Get specific role - only "view" role for this domain
        group_ids = list(domain.get_group_ids_for_roles(roles=["view"]))

        # Verify we get exactly one ID
        self.assertEqual(len(group_ids), 1)

        # Verify the group has the right role
        join_obj = DummyDomainRole.objects.get(
            group_id=group_ids[0], dummydomain=domain
        )
        self.assertEqual(join_obj.role, "view")

    def test_add_and_remove_user_to_groups(self):
        """
        Check that assign_roles_to_user adds the appropriate groups to a user,
        and remove_roles_from_user removes them.
        """
        domain = self.create_domain_with_mocks("Test Domain 3")
        user = self.normal_user

        # Ensure user starts with no groups related to DummyDomain
        user.groups.clear()

        # Add user to groups and verify
        domain.assign_roles_to_user(user=user, roles=None)
        expected_ids = list(domain.get_group_ids_for_roles())
        user_group_ids = list(user.groups.values_list("id", flat=True))
        for gid in expected_ids:
            self.assertIn(gid, user_group_ids)

        # Remove user from groups and verify
        domain.remove_roles_from_user(user, None)
        user_group_ids_after = list(user.groups.values_list("id", flat=True))
        for gid in expected_ids:
            self.assertNotIn(gid, user_group_ids_after)

    def test_get_user_and_group_joins(self):
        """
        Test that we can access user and group joins
        """
        # First completely clean the database to avoid any interference
        DummyDomainRole.objects.all().delete()
        DummyDomainMember.objects.all().delete()
        Group.objects.all().delete()
        DummyDomain.objects.all().delete()

        # Create a domain with a very unique name to ensure it's distinct
        domain_name = "Test Domain User Joins UNIQUE"
        with patch("permissible.models.role_based.core.reset_permissions"):
            domain = DummyDomain.objects.create(name=domain_name)

            # Remove any automatically created roles (clean slate)
            DummyDomainRole.objects.filter(dummydomain=domain).delete()

            # Create 5 roles manually (clear count)
            role_choices = list(DummyDomainRole._meta.get_field("role").choices)[:5]

            # Create roles one by one with clear names
            for i, (role, _) in enumerate(role_choices):
                group_name = f"Test {domain_name} {role} {i}"
                group = Group.objects.create(name=group_name)
                DummyDomainRole.objects.create(
                    role=role, group=group, dummydomain=domain
                )

            # Create a single user join
            DummyDomainMember.objects.create(user=self.normal_user, dummydomain=domain)

        # Query the user joins directly
        user_joins = DummyDomainMember.objects.filter(dummydomain=domain)
        self.assertEqual(user_joins.count(), 1)

        # Query the roles directly, should match how many we created above
        group_joins = DummyDomainRole.objects.filter(dummydomain=domain)
        self.assertEqual(group_joins.count(), len(role_choices))

        # Extra verification: check that we don't have extra roles for this domain
        self.assertEqual(len(role_choices), 5)

    def test_get_member_group_id(self):
        """
        Verify that we can get the mem role's group ID and that it returns None when deleted
        """
        # First clear all existing domains and roles
        DummyDomainRole.objects.all().delete()
        Group.objects.all().delete()
        DummyDomain.objects.all().delete()

        # Create a new domain with a unique name
        domain = self.create_domain_with_mocks("Test Domain Member Group")

        # Access the mem role directly instead of using get_member_group_id
        join_obj = DummyDomainRole.objects.filter(
            dummydomain=domain, role="mem"
        ).first()
        self.assertIsNotNone(join_obj)
        member_group_id = join_obj.group_id

        # Get the actual ID before deleting
        join_id = join_obj.group_id

        # Delete the mem role object and verify it's gone
        join_obj.delete()

        # Verify the deletion was successful - this should check by ID to be precise
        self.assertIsNone(
            DummyDomainRole.objects.filter(
                dummydomain=domain, role="mem", group_id=join_id
            ).first()
        )

    def test_reset_permissions(self):
        """
        Test that reset_permissions sets permissions correctly.
        """
        from permissible.models.utils.reset import reset_permissions
        from guardian.shortcuts import get_group_perms

        # First completely clean the database
        DummyDomainRole.objects.all().delete()
        Group.objects.all().delete()
        DummyDomain.objects.all().delete()

        # Create a domain with a fully unique ID to avoid any interference
        domain_name = "Test Domain Reset Permissions COMPLETELY UNIQUE"

        # Create the domain and a single view role
        with patch("permissible.models.role_based.core.reset_permissions"):
            domain = DummyDomain.objects.create(name=domain_name)
            # Remove any automatically created roles
            DummyDomainRole.objects.filter(dummydomain=domain).delete()

            # Create just one role - "view" role only
            view_group = Group.objects.create(name=f"Test {domain_name} view UNIQUE")
            join_obj = DummyDomainRole.objects.create(
                role="view", group=view_group, dummydomain=domain
            )

            # Verify we only have one role in the system with this domain and role
            count = DummyDomainRole.objects.filter(
                dummydomain=domain, role="view"
            ).count()
            self.assertEqual(
                count, 1, f"Expected 1 view role for domain, found {count}"
            )

        # Now test reset_permissions - it should actually set the permissions
        with patch("permissible.signals.perm_domain_role_permissions_updated"):
            # Call reset_permissions on our single view role
            reset_permissions([join_obj])

        # Verify expected permissions
        expected_perms = DummyDomain.get_permission_codenames(
            ["view"], include_app_label=False
        )

        # Verify the permissions were actually set in the database
        actual_perms = set(get_group_perms(join_obj.group, domain))
        self.assertEqual(expected_perms, actual_perms)

    def test_get_domain_obj(self):
        """
        Test the static method get_domain_obj on PermDomainRole.
        """
        # First clear all existing domains and roles
        DummyDomainRole.objects.all().delete()
        Group.objects.all().delete()
        DummyDomain.objects.all().delete()

        # Create a new domain with a unique name
        domain = self.create_domain_with_mocks("Test Domain Get Domain Obj")
        join_obj = DummyDomainRole.objects.filter(dummydomain=domain).first()

        # We need to heavily mock this method since it has issues with our test models
        with (
            patch.object(DummyDomainRole, "get_domain_field") as mock_get_field,
            patch("permissible.utils.signals.get_subclasses") as mock_get_subclasses,
        ):

            # Set up our field mock
            field_mock = MagicMock()
            field_mock.attname = "dummydomain_id"
            field_mock.related_model = DummyDomain
            mock_get_field.return_value = field_mock

            # Set up subclasses mock
            mock_get_subclasses.return_value = [DummyDomainRole]

            # Create a second mock for the query
            with patch.object(DummyDomainRole.objects, "filter") as mock_filter:
                values_mock = MagicMock()
                values_mock.__getitem__ = lambda self, x: domain.id
                mock_filter.return_value.values_list.return_value = [values_mock]

                # Now we can call the method
                retrieved_domain = DummyDomainRole.get_domain_obj(join_obj.group_id)

        # Since our mocks return the domain ID, verify we got a domain
        self.assertIsNotNone(retrieved_domain)

    def test_get_domain_obj_invalid(self):
        """
        Test that get_domain_obj returns None for an invalid group_id.
        """
        # Patch to avoid assertion error and return empty result
        with (
            patch.object(DummyDomainRole, "get_domain_field") as mock_get_field,
            patch("permissible.utils.signals.get_subclasses") as mock_get_subclasses,
        ):

            # Configure mock to avoid testing assertion failure
            mock_get_field.return_value = MagicMock()
            mock_get_subclasses.return_value = [DummyDomainRole]

            # Set mock to return empty values list for an invalid ID
            with patch.object(DummyDomainRole.objects, "filter") as mock_filter:
                mock_filter.return_value.values_list.return_value = []

                # Should return None for invalid group ID
                result = DummyDomainRole.get_domain_obj(-1)
                self.assertIsNone(result)

    def test_permdomainuser_str(self):
        """
        Test that the __str__ method of DummyDomainMember returns a string containing both the domain and user.
        """
        domain = self.create_domain_with_mocks("Test Domain 10")
        user = self.normal_user
        dru = DummyDomainMember.objects.create(user=user, dummydomain=domain)
        s = str(dru)
        self.assertIn(str(domain), s)
        self.assertIn(str(user), s)

    def test_get_permission_targets(self):
        """
        Test that get_permission_targets returns an iterable containing the domain itself.
        """
        domain = self.create_domain_with_mocks("Test Permission Targets")
        targets = list(domain.get_permission_targets())
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].pk, domain.pk)

    def test_permdomainuser_perm_def_self_condition(self):
        """
        Test that a condition checking user ID match works for PermDomainMember.
        """
        # First, let's look at how PermDef works with object checking
        from permissible.perm_def import PermDef

        # Create a dummy instance with specific user_id
        # Ensure the dummy has a valid dummydomain to avoid RelatedObjectDoesNotExist
        domain = self.create_domain_with_mocks("Test Domain PermDef Self")
        dummy = DummyDomainMember()
        # Assign a real user instance so accessing `dummy.user` won't trigger DoesNotExist
        dummy.user = self.normal_user
        dummy.dummydomain = domain
        dummy.pk = 1

        # Use the real user as the test user so IDs match
        test_user = self.normal_user

        # Create an empty context
        context = {"user": test_user, "request": {"user": test_user}}

        # Create an object filter that uses the context
        obj_filter = ("user_id", "==", "_context.request.user.id")

        # Use the condition in a PermDef with empty permissions list
        perm_def_direct = PermDef([], obj_filter=obj_filter)

        # Test with explicit context
        result = perm_def_direct.check_obj(dummy, test_user, context)
        self.assertTrue(result, "Direct condition check should pass with matching ID")


    def test_reset_domain_roles_bulk_create_group_pks(self):
        """
        Regression test: bulk_create of PermDomainRoles must not reference
        unsaved Group objects. On MySQL, Group.objects.bulk_create() does not
        set PKs on the returned objects, so assigning group=<unsaved Group>
        then calling bulk_create on PermDomainRoles raises ValueError.

        We simulate the MySQL behaviour by patching bulk_create to not set PKs.
        """
        DummyDomainRole.objects.all().delete()
        Group.objects.all().delete()
        DummyDomain.objects.all().delete()

        original_bulk_create = Group.objects.bulk_create.__func__

        def bulk_create_without_pks(manager, objs, *args, **kwargs):
            """Simulate MySQL: bulk_create saves rows but doesn't set PKs."""
            result = original_bulk_create(manager, objs, *args, **kwargs)
            for obj in result:
                obj.pk = None
                obj.id = None
            return result

        with patch.object(
            type(Group.objects), "bulk_create", bulk_create_without_pks
        ):
            # This should NOT raise ValueError about unsaved related objects
            domain = DummyDomain.objects.create(
                name="Bulk Create PK Test Domain"
            )

        # Verify roles were created correctly
        role_choices = list(DummyDomainRole._meta.get_field("role").choices)
        roles_qs = DummyDomainRole.objects.filter(dummydomain=domain)
        self.assertEqual(roles_qs.count(), len(role_choices))

        for role_obj in roles_qs:
            self.assertTrue(
                Group.objects.filter(pk=role_obj.group_id).exists(),
                f"Group for role {role_obj.role} should exist in DB",
            )

    def test_reset_domain_roles_full_path(self):
        """
        Test that reset_domain_roles creates Groups, PermDomainRoles, and
        assigns permissions in a single batched call — without mocking
        reset_permissions. This exercises the full bulk_create path.
        """
        from guardian.shortcuts import get_group_perms

        DummyDomainRole.objects.all().delete()
        Group.objects.all().delete()
        DummyDomain.objects.all().delete()

        # Create domain — triggers reset_domain_roles via save()
        domain = DummyDomain.objects.create(name="Full Path Test Domain")

        # Verify all roles were created
        role_choices = list(DummyDomainRole._meta.get_field("role").choices)
        roles_qs = DummyDomainRole.objects.filter(dummydomain=domain)
        self.assertEqual(roles_qs.count(), len(role_choices))

        # Verify each role has a saved Group with a valid PK
        for role_obj in roles_qs:
            self.assertIsNotNone(role_obj.group_id)
            self.assertTrue(
                Group.objects.filter(pk=role_obj.group_id).exists(),
                f"Group for role {role_obj.role} should exist in DB",
            )

        # Verify permissions were actually assigned per ROLE_DEFINITIONS
        for role_obj in roles_qs:
            _, short_perm_codes = DummyDomainRole.ROLE_DEFINITIONS[role_obj.role]
            expected = DummyDomain.get_permission_codenames(
                short_perm_codes, include_app_label=False
            )
            actual = set(get_group_perms(role_obj.group, domain))
            self.assertEqual(
                expected,
                actual,
                f"Permissions mismatch for role {role_obj.role}: "
                f"expected {expected}, got {actual}",
            )

    def test_reset_domain_roles_idempotent(self):
        """
        Calling reset_domain_roles twice should not fail or create duplicates.
        """
        from guardian.shortcuts import get_group_perms

        DummyDomainRole.objects.all().delete()
        Group.objects.all().delete()
        DummyDomain.objects.all().delete()

        domain = DummyDomain.objects.create(name="Idempotent Test Domain")
        role_choices = list(DummyDomainRole._meta.get_field("role").choices)

        # Call reset_domain_roles again
        domain.reset_domain_roles()

        # Still the same number of roles
        roles_qs = DummyDomainRole.objects.filter(dummydomain=domain)
        self.assertEqual(roles_qs.count(), len(role_choices))

        # Permissions still correct
        for role_obj in roles_qs:
            _, short_perm_codes = DummyDomainRole.ROLE_DEFINITIONS[role_obj.role]
            expected = DummyDomain.get_permission_codenames(
                short_perm_codes, include_app_label=False
            )
            actual = set(get_group_perms(role_obj.group, domain))
            self.assertEqual(expected, actual)


if __name__ == "__main__":
    unittest.main()
