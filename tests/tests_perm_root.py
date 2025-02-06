import unittest
from unittest.mock import patch

from django.test import TestCase
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import models

# Import the abstract models to be tested.
from permissible.models.perm_root import PermRoot, PermRootGroup, PermRootUser

#
# Dummy concrete models for testing
#


class DummyRoot(PermRoot):
    """
    A concrete PermRoot. It defines:
      - a name field,
      - a ManyToManyField to Group via DummyRootGroup,
      - a ManyToManyField to the User model via DummyRootUser.

    Also, we add a get_permission_codenames classmethod so that
    PermRootGroup.reset_permissions_for_group can work.
    """

    name = models.CharField(max_length=100)

    groups = models.ManyToManyField(
        Group, through="DummyRootGroup", related_name="dummy_roots"
    )
    users = models.ManyToManyField(
        get_user_model(), through="DummyRootUser", related_name="dummy_roots"
    )

    def __str__(self):
        return self.name

    @classmethod
    def get_permission_codenames(cls, short_perm_codes):
        # For testing purposes, simply return a dummy set of permission strings.
        return {f"dummy_{code}" for code in short_perm_codes}


class DummyRootGroup(PermRootGroup):
    """
    A concrete PermRootGroup. Note that the join field must match the
    PermRoot’s model name (i.e. "dummyroot").
    """

    dummyroot = models.ForeignKey(DummyRoot, on_delete=models.CASCADE)

    class Meta:
        app_label = (
            "permissible"  # Necessary since our abstract models have no app_label.
        )
        abstract = False


class DummyRootUser(PermRootUser):
    """
    A concrete PermRootUser. It joins DummyRoot to a User.
    """

    dummyroot = models.ForeignKey(DummyRoot, on_delete=models.CASCADE)

    class Meta:
        app_label = "permissible"
        abstract = False

    def get_unretrieved(self, attr):
        # For testing purposes, simply return the user's id.
        return getattr(self.user, "id", None)


#
# Tests for PermRoot, PermRootGroup, and PermRootUser
#


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
        """
        Creating a new DummyRoot should trigger save() which calls reset_perm_groups.
        Verify that one DummyRootGroup (and its Group) is created for each role.
        """
        root = DummyRoot.objects.create(name="Test Root")
        role_choices = list(DummyRootGroup._meta.get_field("role").choices)
        groups_qs = DummyRootGroup.objects.filter(dummyroot=root)
        self.assertEqual(groups_qs.count(), len(role_choices))
        for join_obj in groups_qs:
            self.assertIsNotNone(join_obj.group_id)

    def test_get_group_ids_for_roles_all(self):
        """
        get_group_ids_for_roles with no roles specified returns IDs for all roles.
        """
        root = DummyRoot.objects.create(name="Test Root 2")
        group_ids = list(root.get_group_ids_for_roles())
        role_choices = list(DummyRootGroup._meta.get_field("role").choices)
        self.assertEqual(len(group_ids), len(role_choices))

    def test_get_group_ids_for_roles_specific(self):
        """
        Verify that filtering get_group_ids_for_roles by a single role returns only one id.
        """
        root = DummyRoot.objects.create(name="Test Root Specific")
        group_ids = list(root.get_group_ids_for_roles(roles=["view"]))
        self.assertEqual(len(group_ids), 1)
        join_obj = DummyRootGroup.objects.get(group_id=group_ids[0], dummyroot=root)
        self.assertEqual(join_obj.role, "view")

    def test_add_and_remove_user_to_groups(self):
        """
        Check that add_user_to_groups adds the appropriate groups to a user,
        and remove_user_from_groups removes them.
        """
        root = DummyRoot.objects.create(name="Test Root 3")
        user = self.normal_user
        # Ensure user starts with no groups related to DummyRoot.
        initial_group_ids = list(user.groups.values_list("id", flat=True))
        root.add_user_to_groups(user)
        expected_ids = list(root.get_group_ids_for_roles())
        user_group_ids = list(user.groups.values_list("id", flat=True))
        for gid in expected_ids:
            self.assertIn(gid, user_group_ids)
        root.remove_user_from_groups(user)
        user_group_ids_after = list(user.groups.values_list("id", flat=True))
        for gid in expected_ids:
            self.assertNotIn(gid, user_group_ids_after)

    def test_permrootuser_get_permissions_root_obj(self):
        """
        Verify that DummyRootUser.get_permissions_root_obj returns the value
        from get_unretrieved (i.e. the user's id).
        """
        root = DummyRoot.objects.create(name="Test Root 4")
        user = self.normal_user
        dru = DummyRootUser.objects.create(user=user, dummyroot=root)
        self.assertEqual(dru.get_permissions_root_obj(), user.id)

    def test_get_user_and_group_joins(self):
        """
        Test that get_user_joins and get_group_joins return the proper related managers.
        """
        root = DummyRoot.objects.create(name="Test Root 5")
        # Create a DummyRootUser join.
        DummyRootUser.objects.create(user=self.normal_user, dummyroot=root)
        # get_user_joins (should return the RelatedManager for DummyRootUser).
        user_joins = root.get_user_joins()
        self.assertEqual(user_joins.count(), 1)
        # get_group_joins (should return the RelatedManager for DummyRootGroup).
        group_joins = root.get_group_joins()
        role_choices = list(DummyRootGroup._meta.get_field("role").choices)
        self.assertEqual(group_joins.count(), len(role_choices))

    def test_get_member_group_id(self):
        """
        Verify that get_member_group_id returns the group_id for the 'mem' role.
        Then, after deleting that join, it should return None.
        """
        root = DummyRoot.objects.create(name="Test Root 6")
        member_group_id = root.get_member_group_id()
        join_obj = DummyRootGroup.objects.filter(dummyroot=root, role="mem").first()
        self.assertIsNotNone(join_obj)
        self.assertEqual(member_group_id, join_obj.group_id)
        # Delete the 'mem' join and test again.
        join_obj.delete()
        self.assertIsNone(root.get_member_group_id())

    def test_copy_related_records(self):
        """
        Test that copy_related_records copies the DummyRootGroup join objects from one root
        to another. (The new copies will get new Group records created on save.)
        """
        root1 = DummyRoot.objects.create(name="Original Root")
        # (Optionally create a DummyRootUser join; copy_related_records only copies group joins.)
        DummyRootUser.objects.create(user=self.normal_user, dummyroot=root1)
        original_count = DummyRootGroup.objects.filter(dummyroot=root1).count()
        # Create a new DummyRoot instance.
        root2 = DummyRoot.objects.create(name="Copied Root")
        # Copy the join records from root1 to root2.
        root1.copy_related_records(root2)
        copied_groups = DummyRootGroup.objects.filter(dummyroot=root2)
        self.assertEqual(copied_groups.count(), original_count)
        # Ensure that each copied join now has a valid (non-null) group.
        for join_obj in copied_groups:
            self.assertIsNotNone(join_obj.group_id)

    def test_permrootgroup_str(self):
        """
        Test the __str__ output of a DummyRootGroup instance.
        """
        root = DummyRoot.objects.create(name="Test Root 7")
        join_obj = DummyRootGroup.objects.filter(dummyroot=root).first()
        s = str(join_obj)
        self.assertIn(join_obj.role, s)
        self.assertIn("DummyRoot", s)
        self.assertIn(str(root), s)
        self.assertIn(str(root.id), s)

    @patch("permissible.models.perm_root.assign_perm")
    @patch("permissible.models.perm_root.remove_perm")
    @patch("permissible.models.perm_root.get_group_perms", return_value=set())
    def test_reset_permissions_for_group(
        self, mock_get_group_perms, mock_remove_perm, mock_assign_perm
    ):
        """
        Test that reset_permissions_for_group (called from save())
        uses guardian’s assign_perm to set permissions based on the role.
        (For role "view", DummyRoot.get_permission_codenames returns {"dummy_view"}).
        """
        root = DummyRoot.objects.create(name="Test Root 8")
        join_obj = DummyRootGroup.objects.get(dummyroot=root, role="view")
        # (Changing the role to 'view' explicitly; it is already "view".)
        join_obj.role = "view"
        join_obj.save()  # This calls reset_permissions_for_group internally.
        expected_perms = DummyRoot.get_permission_codenames(["view"])
        for perm in expected_perms:
            mock_assign_perm.assert_any_call(perm, join_obj.group, root)
        mock_remove_perm.assert_not_called()

    def test_get_root_obj(self):
        """
        Test the static method get_root_obj on PermRootGroup.
        Given a group_id from one of DummyRootGroup’s, it should return the corresponding DummyRoot.
        (Note: This test exposes a bug in the current implementation, since it uses a QuerySet instead of a single value.)
        """
        root = DummyRoot.objects.create(name="Test Root 9")
        join_obj = DummyRootGroup.objects.filter(dummyroot=root).first()
        retrieved_root = DummyRootGroup.get_root_obj(join_obj.group_id)
        self.assertIsNotNone(retrieved_root)
        self.assertIsInstance(retrieved_root, DummyRoot)
        # Expect the pk to match – if not, the implementation needs to be fixed.
        self.assertEqual(
            retrieved_root.pk,
            root.pk,
            "get_root_obj did not return the correct root instance.",
        )

    def test_permrootuser_str(self):
        """
        Test that the __str__ method of DummyRootUser returns a string containing both the root and user.
        """
        root = DummyRoot.objects.create(name="Test Root 10")
        user = self.normal_user
        dru = DummyRootUser.objects.create(user=user, dummyroot=root)
        s = str(dru)
        self.assertIn(str(root), s)
        self.assertIn(str(user), s)


if __name__ == "__main__":
    unittest.main()
