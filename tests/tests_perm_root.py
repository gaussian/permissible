import unittest
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import models
from permissible.models.perm_root import PermRoot, PermRootGroup, PermRootUser

# Pseudocode:
# 1. Define dummy concrete models for testing:
#    a. DummyRoot (subclasses PermRoot):
#         - Has a "name" CharField.
#         - Defines "groups" as a ManyToManyField to auth.Group via DummyRootGroup.
#         - Defines "users" as a ManyToManyField to the User model via DummyRootUser.
#         - Implements __str__.
#    b. DummyRootGroup (subclasses PermRootGroup):
#         - Adds a ForeignKey to DummyRoot (field name matching DummyRoot _meta.model_name).
#         - Set Meta options to be concrete (abstract=False).
#    c. DummyRootUser (subclasses PermRootUser):
#         - Adds a ForeignKey to DummyRoot.
#         - Implements get_unretrieved to return a dummy value.
#
# 2. Write tests using Django's TestCase:
#    a. test_reset_perm_groups_creates_groups:
#         - Create a DummyRoot instance. Its save() calls reset_perm_groups.
#         - Verify that a DummyRootGroup instance exists for each role in the role choices.
#    b. test_get_group_ids_for_roles:
#         - Call get_group_ids_for_roles and verify the count matches the role choices.
#    c. test_add_and_remove_user_to_groups:
#         - Add a User via add_user_to_groups and check that the user.groups includes the groups.
#         - Remove the user and verify the groups are removed.
#    d. test_permrootuser_get_permissions_root_obj:
#         - Create a DummyRootUser instance and verify that get_permissions_root_obj returns the expected value.
#
# 3. Import the models from a relative import.
#


# Dummy concrete models for testing


class DummyRoot(PermRoot):
    name = models.CharField(max_length=100)

    groups = models.ManyToManyField(
        Group, through="DummyRootGroup", related_name="dummy_roots"
    )
    users = models.ManyToManyField(
        get_user_model(), through="DummyRootUser", related_name="dummy_roots"
    )

    def __str__(self):
        return self.name


class DummyRootGroup(PermRootGroup):
    # The join field must match the model_name of DummyRoot, which is "dummyroot"
    dummyroot = models.ForeignKey(DummyRoot, on_delete=models.CASCADE)

    class Meta:
        app_label = "permissible"
        abstract = False


class DummyRootUser(PermRootUser):
    dummyroot = models.ForeignKey(DummyRoot, on_delete=models.CASCADE)

    class Meta:
        app_label = "permissible"
        abstract = False

    def get_unretrieved(self, attr):
        # For testing purposes, simply return the user's id.
        return getattr(self.user, "id", None)


# Unit tests for PermRoot, PermRootGroup, PermRootUser


class PermRootTests(TestCase):

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

    def test_reset_perm_groups_creates_groups(self):
        # Creating a new DummyRoot instance will call save() -> reset_perm_groups.
        root = DummyRoot.objects.create(name="Test Root")
        # Retrieve role choices from DummyRootGroup role field.
        role_choices = list(DummyRootGroup._meta.get_field("role").choices)
        groups = DummyRootGroup.objects.filter(dummyroot=root)
        self.assertEqual(groups.count(), len(role_choices))
        # Verify that each created join model has an associated Group.
        for join_obj in groups:
            self.assertIsNotNone(join_obj.group_id)

    def test_get_group_ids_for_roles(self):
        root = DummyRoot.objects.create(name="Test Root 2")
        group_ids = list(root.get_group_ids_for_roles())
        role_choices = list(DummyRootGroup._meta.get_field("role").choices)
        self.assertEqual(len(group_ids), len(role_choices))

    def test_add_and_remove_user_to_groups(self):
        root = DummyRoot.objects.create(name="Test Root 3")
        user = self.normal_user
        # Initially, ensure the user's groups do not include the DummyRoot groups.
        initial_group_ids = list(user.groups.values_list("id", flat=True))
        root.add_user_to_groups(user)
        expected_ids = list(root.get_group_ids_for_roles())
        # After adding, each expected group id should be in the user's groups.
        user_group_ids = list(user.groups.values_list("id", flat=True))
        for gid in expected_ids:
            self.assertIn(gid, user_group_ids)
        # Now remove the user from these groups.
        root.remove_user_from_groups(user)
        user_group_ids_after = list(user.groups.values_list("id", flat=True))
        for gid in expected_ids:
            self.assertNotIn(gid, user_group_ids_after)

    def test_permrootuser_get_permissions_root_obj(self):
        root = DummyRoot.objects.create(name="Test Root 4")
        user = self.normal_user
        # Create a DummyRootUser instance linking the user and the root.
        dru = DummyRootUser.objects.create(user=user, dummyroot=root)
        # get_permissions_root_obj should invoke get_unretrieved which returns user's id.
        self.assertEqual(dru.get_permissions_root_obj(), user.id)


if __name__ == "__main__":
    unittest.main()
