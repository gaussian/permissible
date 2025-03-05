"""
Integration tests for PermissibleFilter with Django Guardian.
This tests whether filtering works correctly based on permissions.
"""

import unittest

from django.contrib.auth import get_user_model
from django.db import models
from django.test import TestCase, override_settings
from rest_framework.test import APIRequestFactory
from rest_framework.viewsets import ModelViewSet
from rest_framework import serializers

from permissible.permissions import PermissiblePerms
from permissible.filters import PermissibleFilter
from permissible.perm_def import p, ALLOW_ALL, IS_PUBLIC
from permissible.models import PermissibleMixin, assign_short_perms


# Define models for testing
class TestFilterIntegrationModel(PermissibleMixin, models.Model):
    name = models.CharField(max_length=100)
    is_public = models.BooleanField(default=False)
    status = models.CharField(max_length=20, default="active")
    owner = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, null=True)

    class Meta:
        app_label = "permissible"

    def __str__(self):
        return self.name

    @classmethod
    def get_policies(cls):
        """Define policies for test model"""
        perm_def_is_active = p([], obj_filter=("status", "==", "active"))
        return {
            "global": {
                "retrieve": ALLOW_ALL,
                "custom_list": ALLOW_ALL,
            },
            "object": {
                # List filtering will use "retrieve"" for PermissibleFilter
                "retrieve": p(["view"]) | (IS_PUBLIC & perm_def_is_active),
                "custom_list": p(["view"]) | (IS_PUBLIC & perm_def_is_active),
            },
        }


# Serializer for testing
class FilterTestModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = TestFilterIntegrationModel
        fields = ["id", "name", "is_public", "status", "owner"]


# ViewSet for testing
class FilterTestModelViewSet(ModelViewSet):
    queryset = TestFilterIntegrationModel.objects.all()
    serializer_class = FilterTestModelSerializer
    permission_classes = [PermissiblePerms]
    filter_backends = [PermissibleFilter]
    base_model = TestFilterIntegrationModel  # Required for PermissibleFilter


@override_settings(
    AUTHENTICATION_BACKENDS=(
        "django.contrib.auth.backends.ModelBackend",
        "guardian.backends.ObjectPermissionBackend",
    )
)
class PermissibleFilterIntegrationTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        # Create users
        User = get_user_model()
        cls.admin_user = User.objects.create_superuser(
            username="admin", password="admin", email="admin@example.com"
        )
        cls.user1 = User.objects.create_user(username="user1", password="user1")
        cls.user2 = User.objects.create_user(username="user2", password="user2")

        # Create test objects with different owners and states
        cls.public_active_obj = TestFilterIntegrationModel.objects.create(
            name="Public Active", is_public=True, status="active"
        )
        cls.public_inactive_obj = TestFilterIntegrationModel.objects.create(
            name="Public Inactive", is_public=True, status="inactive"
        )
        cls.private_user1_obj = TestFilterIntegrationModel.objects.create(
            name="Private User1", is_public=False, owner=cls.user1
        )
        cls.private_user2_obj = TestFilterIntegrationModel.objects.create(
            name="Private User2", is_public=False, owner=cls.user2
        )
        cls.private_inactive_obj = TestFilterIntegrationModel.objects.create(
            name="Private Inactive", is_public=False, status="inactive"
        )

        # Assign object permissions - user1 can view their own private object
        assign_short_perms(["view"], cls.user1, cls.private_user1_obj)

        # Set up request factory
        cls.factory = APIRequestFactory()

    def test_superuser_sees_all_objects(self):
        """Test that superuser can see all objects regardless of permissions"""
        view = FilterTestModelViewSet.as_view({"get": "list"})
        request = self.factory.get("/filter-test-models/")
        request.user = self.admin_user

        response = view(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 5)  # Should see all objects

    def test_filter_by_permissions(self):
        """Test that users only see objects they have permission for"""
        view = FilterTestModelViewSet.as_view({"get": "list"})

        # User1 should see public objects + their own private object
        request = self.factory.get("/filter-test-models/")
        request.user = self.user1
        response = view(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 2)  # 1 public active + 1 with permission

        # User2 should only see public objects
        request = self.factory.get("/filter-test-models/")
        request.user = self.user2
        response = view(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 1)  # 1 public active object

    # def test_filter_by_query_params(self):
    #     """Test filtering by query parameters (defined in 'filters')"""
    #     view = FilterTestModelViewSet.as_view({"get": "list"})

    #     # Filter by status
    #     request = self.factory.get("/filter-test-models/?status=active")
    #     request.user = self.user1
    #     response = view(request)

    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(
    #         len(response.data), 2
    #     )  # Public active + private user1 (active)

    #     # Filter by owner_id
    #     request = self.factory.get(f"/filter-test-models/?owner_id={self.user1.id}")
    #     request.user = self.user1
    #     response = view(request)

    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(len(response.data), 1)  # Only user1's object

    #     # Combine filters
    #     request = self.factory.get(
    #         f"/filter-test-models/?status=active&owner_id={self.user1.id}"
    #     )
    #     request.user = self.user1
    #     response = view(request)

    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(len(response.data), 1)  # Only user1's active object

    # def test_filter_respects_permissions(self):
    #     """Test that filtering respects permissions (doesn't bypass them)"""
    #     view = FilterTestModelViewSet.as_view({"get": "list"})

    #     # User2 trying to filter by user1's id should return empty results
    #     request = self.factory.get(f"/filter-test-models/?owner_id={self.user1.id}")
    #     request.user = self.user2
    #     response = view(request)

    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(len(response.data), 0)  # No results (no permission)

    def test_filter_with_different_actions(self):
        """Test that filtering works correctly with different view actions"""

        # Set up a view with a custom action
        class CustomActionViewSet(FilterTestModelViewSet):
            def get_queryset(self):
                if self.action == "custom_list":
                    return TestFilterIntegrationModel.objects.filter(status="active")
                return super().get_queryset()

            @classmethod
            def as_view(cls, actions, **initkwargs):
                if "custom_list" in actions.values():
                    initkwargs["detail"] = False
                return super().as_view(actions, **initkwargs)

            def custom_list(self, request):
                return self.list(request)

        # Test with regular list action
        view = CustomActionViewSet.as_view({"get": "list"})
        request = self.factory.get("/filter-test-models/")
        request.user = self.user1
        response = view(request)
        self.assertEqual(len(response.data), 2)  # 1 public active + 1 with permission

        # Test with custom list action - should apply same filtering
        view = CustomActionViewSet.as_view({"get": "custom_list"})
        request = self.factory.get("/filter-test-models/custom/")
        request.user = self.user1
        response = view(request)
        self.assertEqual(
            len(response.data), 2
        )  # Only active objects that have permission


if __name__ == "__main__":
    unittest.main()
