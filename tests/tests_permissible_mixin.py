import unittest
from django.http import Http404
from permissible.models.permissible_mixin import PermissibleDenyDefaultMixin
from permissible.perm_def import IS_AUTHENTICATED

# Pseudocode:
# 1. Create a DummyUser class to simulate a PermissionsMixin user with attributes id and is_superuser.
# 2. Create a DummyModel class that inherits from PermissibleDenyDefaultMixin to test its methods.
# 3. Write tests for:
#    a. get_permissions_root_obj: It should return None.
#    b. has_object_permission for non-list actions ("create", "retrieve", "update", "partial_update", "destroy"):
#       - For a normal authenticated user (non-superuser), it should return False because DENY_ALL denies action.
#       - For a superuser, it should return True.
#    c. has_global_permission:
#       - For action "list", with an authenticated non-superuser (user.id is truthy) should return True.
#       - For an action not defined in global_action_perm_map, it should return True.
#


# Dummy user simulating Django's PermissionsMixin
class DummyUser:
    def __init__(self, id, is_superuser=False):
        self.id = id
        self.is_superuser = is_superuser


# Create a dummy model class for tests by inheriting from PermissibleDenyDefaultMixin.
class DummyDenyDefaultModel(PermissibleDenyDefaultMixin):
    pass


class TestPermissibleDenyDefaultMixin(unittest.TestCase):

    def setUp(self):
        self.normal_user = DummyUser(id=1, is_superuser=False)
        self.superuser = DummyUser(id=1, is_superuser=True)
        self.instance = DummyDenyDefaultModel()

    def test_get_permissions_root_obj(self):
        # get_permissions_root_obj should return None as defined in PermissibleDenyDefaultMixin.
        self.assertIsNone(self.instance.get_permissions_root_obj())

    def test_has_object_permission_denies_actions_for_normal_user(self):
        # For actions mapped to DENY_ALL, has_object_permission should return False for normal user.
        actions = ["create", "retrieve", "update", "partial_update", "destroy"]
        for action in actions:
            with self.subTest(action=action):
                result = self.instance.has_object_permission(
                    user=self.normal_user, action=action
                )
                self.assertFalse(result)

    def test_has_object_permission_allows_actions_for_superuser(self):
        # Superuser bypasses permissions irrespective of mapping.
        actions = [
            "create",
            "retrieve",
            "update",
            "partial_update",
            "destroy",
            "list",
            "unknown",
        ]
        for action in actions:
            with self.subTest(action=action):
                result = self.instance.has_object_permission(
                    user=self.superuser, action=action
                )
                self.assertTrue(result)

    def test_has_global_permission_list_action(self):
        # Global actions come from PermissibleAuthenticatedListingMixin, which defines "list" action
        # with IS_AUTHENTICATED, so for a normal user with a valid id, it should return True.
        result = DummyDenyDefaultModel.has_global_permission(
            user=self.normal_user, action="list", context={}
        )
        self.assertTrue(result)

    def test_has_global_permission_unknown_action(self):
        # If action is not in global_action_perm_map, permission is granted automatically.
        result = DummyDenyDefaultModel.has_global_permission(
            user=self.normal_user, action="unknown", context={}
        )
        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()
