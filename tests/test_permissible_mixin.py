import unittest
from unittest.mock import MagicMock, patch

from django.db import models

from permissible.models.permissible_mixin import PermissibleMixin
from permissible.perm_def import p, BasePermDefObj


# Mock the policies module with ACTION_POLICIES
mock_action_policies = {
    "tests.TestModel": {
        "global": {
            "list": p(["view"]),
            "create": p(["add"]),
            "retrieve": p(["view"]),
            "update": p(["change"]),
            "partial_update": p(["change"]),
            "destroy": p(["delete"]),
        },
        "object": {
            "list": p(["view"]),
            "retrieve": p(["view"]),
            "update": p(["change"]),
            "partial_update": p(["change"]),
            "destroy": p(["delete"]),
        },
        "domains": ["domain_object", "parent.domain"],
    },
    "tests.RelatedModel": {
        "global": {
            "list": p(
                ["view"], global_condition_checker=lambda u, c: c.get("allowed", False)
            ),
            "retrieve": p(
                ["view"], global_condition_checker=lambda u, c: c.get("allowed", False)
            ),
            "create": p(["add"], obj_path="test_model"),
            "update": p(["change"], obj_path="test_model"),
            "partial_update": p(["change"], obj_path="test_model"),
            "destroy": p(["delete"], obj_path="test_model"),
        },
        "object": {
            "list": p(["view"]),
            "retrieve": p(["view"]),
            "update": p(["change"], obj_path="test_model"),
            "partial_update": p(["change"], obj_path="test_model"),
            "destroy": p(["delete"], obj_path="test_model"),
        },
    },
    "tests.FilteredModel": {
        "global": {
            "list": p(["view"]),
            "retrieve": p(["view"]),
        },
        "object": {
            "list": p(["view"], obj_filter=("status", "==", "public")),
            "retrieve": p(["view"], obj_filter=("status", "==", "public")),
        },
    },
    "tests.DomainModel": {
        "global": {
            "list": p(["view"]),
            "retrieve": p(["view"]),
        },
        "object": {
            "list": p(["view"], obj_path="domain"),
            "retrieve": p(["view"], obj_path="domain"),
        },
    },
}


# Create a mock user class
class MockUser:
    def __init__(self, perms=None, is_superuser=False):
        self.perms = perms or {}
        self.is_superuser = is_superuser

    def has_perms(self, perm_list, obj=None):
        """
        Mocked permission check to simplify testing
        """
        # For object permissions, strip app label if present to match our test data format
        if obj:
            stripped_perms = []
            for perm in perm_list:
                # Handle permission format with or without app label
                if "." in perm:
                    _, short_perm = perm.split(".")
                    stripped_perms.append(short_perm)
                else:
                    stripped_perms.append(perm)

            return all(
                (perm, getattr(obj, "id", None)) in self.perms
                for perm in stripped_perms
            )
        else:
            # Global permissions stored with None as obj_id
            return all((perm, None) in self.perms for perm in perm_list)


# Create test models that use PermissibleMixin
class TestModel(PermissibleMixin, models.Model):
    name = models.CharField(max_length=100)

    # Store policies locally for the mock to use
    _policies = mock_action_policies.get("tests.TestModel")

    class Meta:
        app_label = "testapp"  # Add explicit app_label
        managed = False  # Tell Django not to manage the table


class RelatedModel(PermissibleMixin, models.Model):
    name = models.CharField(max_length=100)
    test_model = models.ForeignKey(TestModel, on_delete=models.CASCADE)

    # Store policies locally for the mock to use
    _policies = mock_action_policies.get("tests.RelatedModel")

    class Meta:
        app_label = "testapp"
        managed = False


class FilteredModel(PermissibleMixin, models.Model):
    name = models.CharField(max_length=100)
    status = models.CharField(max_length=20)

    # Store policies locally for the mock to use
    _policies = mock_action_policies.get("tests.FilteredModel")

    class Meta:
        app_label = "testapp"
        managed = False


class DomainObject(BasePermDefObj, models.Model):
    name = models.CharField(max_length=100)

    class Meta:
        app_label = "testapp"
        managed = False


class DomainModel(PermissibleMixin, models.Model):
    name = models.CharField(max_length=100)
    domain = models.ForeignKey(DomainObject, on_delete=models.CASCADE)

    # Store policies locally for the mock to use
    _policies = mock_action_policies.get("tests.DomainModel")

    class Meta:
        app_label = "testapp"
        managed = False


class TestPermissibleMixin(unittest.TestCase):
    def setUp(self):
        """Set up test data"""
        self.test_model = TestModel(id=1, name="Test Object")
        self.test_model._state.adding = False
        self.related_model = RelatedModel(
            id=2, name="Related Object", test_model=self.test_model
        )
        self.public_model = FilteredModel(id=3, name="Public Model", status="public")
        self.private_model = FilteredModel(id=4, name="Private Model", status="private")

        self.domain_obj = DomainObject(id=5, name="Domain Object")
        self.domain_model = DomainModel(
            id=6, name="Domain Model", domain=self.domain_obj
        )

        # Mock users with different permissions
        self.superuser = MockUser(is_superuser=True)
        self.unprivileged_user = MockUser()
        self.view_user = MockUser(
            perms={
                # Global permissions
                ("testapp.view_testmodel", None): True,
                ("testapp.view_relatedmodel", None): True,
                ("testapp.view_filteredmodel", None): True,
                ("testapp.view_domainmodel", None): True,
                # Object permissions
                ("view_testmodel", 1): True,
                ("view_relatedmodel", 2): True,
                ("view_filteredmodel", 3): True,
                ("view_filteredmodel", 4): True,
                ("view_domainmodel", 6): True,
                ("view_domainobject", 5): True,
            }
        )
        self.change_user = MockUser(
            perms={
                # Global permissions
                ("testapp.view_testmodel", None): True,
                ("testapp.change_testmodel", None): True,
                ("testapp.view_relatedmodel", None): True,
                ("testapp.change_relatedmodel", None): True,
                # Object permissions
                ("view_testmodel", 1): True,
                ("change_testmodel", 1): True,
                ("view_relatedmodel", 2): True,
                ("change_relatedmodel", 2): True,
            }
        )

    @patch("permissible.models.permissible_mixin.PolicyLooupMixin.get_policies")
    def test_global_permissions_superuser(self, mock_get_policies):
        """Test that superusers can always access any action"""
        mock_get_policies.return_value = self.test_model._policies

        # Test all common actions
        for action in [
            "list",
            "create",
            "retrieve",
            "update",
            "partial_update",
            "destroy",
        ]:
            self.assertTrue(
                TestModel.has_global_permission(self.superuser, action),
                f"Superuser should have global {action} permission",
            )

    @patch("permissible.models.permissible_mixin.PolicyLooupMixin.get_policies")
    def test_global_permissions_view_only(self, mock_get_policies):
        """Test that view-only users have appropriate permissions"""
        mock_get_policies.return_value = self.test_model._policies

        # User with view permission should be able to list and retrieve
        self.assertTrue(
            TestModel.has_global_permission(self.view_user, "list"),
            "User with view permission should have list permission",
        )
        self.assertTrue(
            TestModel.has_global_permission(self.view_user, "retrieve"),
            "User with view permission should have retrieve permission",
        )

        # But not update, create, etc.
        self.assertFalse(
            TestModel.has_global_permission(self.view_user, "update"),
            "User with only view permission should not have update permission",
        )
        self.assertFalse(
            TestModel.has_global_permission(self.view_user, "create"),
            "User with only view permission should not have create permission",
        )
        self.assertFalse(
            TestModel.has_global_permission(self.view_user, "destroy"),
            "User with only view permission should not have destroy permission",
        )

    @patch("permissible.models.permissible_mixin.PolicyLooupMixin.get_policies")
    def test_object_permissions_superuser(self, mock_get_policies):
        """Test that superusers can always access any object action"""
        mock_get_policies.return_value = self.test_model._policies

        # Test all common object actions
        for action in ["retrieve", "update", "partial_update", "destroy"]:
            self.assertTrue(
                self.test_model.has_object_permission(self.superuser, action),
                f"Superuser should have object {action} permission",
            )

    @patch("permissible.models.permissible_mixin.PolicyLooupMixin.get_policies")
    def test_object_permissions_view_only(self, mock_get_policies):
        """Test that view-only users have appropriate object permissions"""
        mock_get_policies.return_value = self.test_model._policies

        # User with view permission should be able to retrieve
        self.assertTrue(
            self.test_model.has_object_permission(self.view_user, "retrieve"),
            "User with view permission should have retrieve permission",
        )

        # But not update, etc.
        self.assertFalse(
            self.test_model.has_object_permission(self.view_user, "update"),
            "User with only view permission should not have update permission",
        )
        self.assertFalse(
            self.test_model.has_object_permission(self.view_user, "destroy"),
            "User with only view permission should not have destroy permission",
        )

    @patch("permissible.models.permissible_mixin.PolicyLooupMixin.get_policies")
    def test_context_based_permissions(self, mock_get_policies):
        """Test permissions that depend on context"""
        mock_get_policies.return_value = self.related_model._policies

        # Without context, permissions should fail
        self.assertFalse(
            RelatedModel.has_global_permission(self.view_user, "list"),
            "Permission should fail without proper context",
        )

        # With proper context, permissions should succeed
        self.assertTrue(
            RelatedModel.has_global_permission(
                self.view_user, "list", context={"allowed": True}
            ),
            "Permission should succeed with proper context",
        )
        self.assertTrue(
            RelatedModel.has_global_permission(
                self.view_user, "retrieve", context={"allowed": True}
            ),
            "Permission should succeed with proper context",
        )

    @patch("permissible.models.permissible_mixin.PolicyLooupMixin.get_policies")
    def test_obj_filter_permissions(self, mock_get_policies):
        """Test obj_filter permission checking"""
        mock_get_policies.return_value = self.public_model._policies

        # Public objects should be accessible
        self.assertTrue(
            self.public_model.has_object_permission(self.view_user, "retrieve"),
            "Public objects should be accessible",
        )

        # Private objects should not be accessible even with view permission on the object
        mock_get_policies.return_value = self.private_model._policies
        self.assertFalse(
            self.private_model.has_object_permission(self.view_user, "retrieve"),
            "Private objects should not be accessible",
        )

    @patch("permissible.models.permissible_mixin.PolicyLooupMixin.get_policies")
    def test_obj_path_permissions(self, mock_get_policies):
        """Test obj_path permission checking"""
        mock_get_policies.return_value = self.related_model._policies

        # Test that update permission checks the related model's permissions
        self.assertFalse(
            self.related_model.has_object_permission(self.view_user, "update"),
            "User without change permission on test_model shouldn't update related model",
        )

        self.assertTrue(
            self.related_model.has_object_permission(self.change_user, "update"),
            "User with change permission on test_model should update related model",
        )

    @patch("permissible.models.permissible_mixin.PolicyLooupMixin.get_policies")
    def test_domain_permissions(self, mock_get_policies):
        """Test domain object permission checking"""
        mock_get_policies.return_value = self.domain_model._policies

        # Test that permissions are checked on the domain object
        self.assertTrue(
            self.domain_model.has_object_permission(self.view_user, "retrieve"),
            "User with view permission on domain should view domain model",
        )

    @patch("permissible.models.permissible_mixin.PolicyLooupMixin.get_policies")
    def test_get_domains(self, mock_get_policies):
        """Test get_domains method"""
        mock_get_policies.return_value = self.test_model._policies

        # Mock get_unretrieved instead of trying to add attributes to TestModel class
        with patch.object(self.test_model, "get_unretrieved") as mock_get_unretrieved:
            # Configure the mock to return different values for different paths
            domain_obj = MagicMock(name="domain_object")
            parent_domain = MagicMock(name="parent.domain")

            def side_effect(path):
                if path == "domain_object":
                    return domain_obj
                elif path == "parent.domain":
                    return parent_domain
                return None

            mock_get_unretrieved.side_effect = side_effect

            # Call the method being tested
            domains = self.test_model.get_domains()

            # Verify results
            self.assertEqual(len(domains), 2, "Should return 2 domain objects")
            self.assertEqual(domains[0], domain_obj)
            self.assertEqual(domains[1], parent_domain)

            # Verify the method was called with the correct paths
            mock_get_unretrieved.assert_any_call("domain_object")
            mock_get_unretrieved.assert_any_call("parent.domain")


if __name__ == "__main__":
    unittest.main()
