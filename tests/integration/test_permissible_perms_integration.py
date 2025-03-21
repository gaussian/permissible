"""
Integration tests for PermissiblePerms with Django Guardian.
This tests full permission checking functionality without mocks.
"""

import unittest

from django.contrib.auth import get_user_model
from django.db import models
from django.test import TestCase, override_settings
from rest_framework.test import APIRequestFactory
from rest_framework.viewsets import ModelViewSet
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework import serializers
from guardian.shortcuts import assign_perm

from permissible.filters import PermissibleFilter
from permissible.permissions import PermissiblePerms
from permissible.perm_def import p, IS_PUBLIC, ALLOW_ALL
from permissible.models import PermissibleMixin, assign_short_perms


# Define models for testing
class TestPermIntegrationModel(PermissibleMixin, models.Model):
    name = models.CharField(max_length=100)
    is_public = models.BooleanField(default=False)
    owner = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, null=True)

    class Meta:
        app_label = "permissible"

    def __str__(self):
        return self.name

    @classmethod
    def get_policies(cls):
        """Define policies for test model"""
        return {
            "global": {
                "create": p(["add"]),
                "retrieve": ALLOW_ALL,
                "update": ALLOW_ALL,
                "partial_update": ALLOW_ALL,
                "destroy": ALLOW_ALL,
                "custom_action": ALLOW_ALL,
            },
            "object": {
                "create": ALLOW_ALL,
                "retrieve": p(["view"]) | IS_PUBLIC,
                "update": p(["change"]),
                "partial_update": p(["change"]),
                "destroy": p(["delete"]),
                "custom_action": p(["view"]),
            },
        }


# Serializer for TestModel
class TestModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = TestPermIntegrationModel
        fields = ["id", "name", "is_public", "owner"]


# ViewSet for testing
class TestModelViewSet(ModelViewSet):
    queryset = TestPermIntegrationModel.objects.all()
    serializer_class = TestModelSerializer
    permission_classes = [PermissiblePerms]
    filter_backends = [PermissibleFilter]

    @action(detail=True, methods=["get"])
    def custom_action(self, request, pk=None):
        """Custom action to test permissions"""
        self.get_object()  # this triggers permission check
        return Response({"detail": "Custom action permitted"})


@override_settings(
    AUTHENTICATION_BACKENDS=(
        "django.contrib.auth.backends.ModelBackend",
        "guardian.backends.ObjectPermissionBackend",
    )
)
class PermissiblePermsIntegrationTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        # Create users
        User = get_user_model()
        cls.admin_user = User.objects.create_superuser(
            username="admin", password="admin", email="admin@example.com"
        )
        cls.staff_user = User.objects.create_user(
            username="staff", password="staff", email="staff@example.com"
        )
        cls.regular_user = User.objects.create_user(
            username="user", password="user", email="user@example.com"
        )
        cls.owner_user = User.objects.create_user(
            username="owner", password="owner", email="owner@example.com"
        )

        # Create test objects
        cls.public_obj = TestPermIntegrationModel.objects.create(
            name="Public Object", is_public=True
        )
        cls.private_obj = TestPermIntegrationModel.objects.create(
            name="Private Object", is_public=False
        )
        cls.owned_obj = TestPermIntegrationModel.objects.create(
            name="Owned Object", is_public=False, owner=cls.owner_user
        )
        # Assign object permissions
        assign_short_perms(["view", "change"], cls.regular_user, cls.private_obj)
        assign_short_perms(["view", "change"], cls.owner_user, cls.owned_obj)

        # Assign global permissions
        assign_perm("permissible.add_testpermintegrationmodel", cls.staff_user)

        # Set up request factory
        cls.factory = APIRequestFactory()

    def test_superuser_permissions(self):
        """Test that superuser has all permissions"""
        view = TestModelViewSet.as_view({"get": "retrieve"})
        request = self.factory.get("/test-models/1/")
        request.user = self.admin_user

        # Test retrieve permission for superuser (should be allowed for any object)
        response = view(request, pk=self.private_obj.pk)
        self.assertEqual(response.status_code, 200)

        # Test custom action permission for superuser
        view = TestModelViewSet.as_view({"get": "custom_action"})
        response = view(request, pk=self.private_obj.pk)
        self.assertEqual(response.status_code, 200)

    def test_create_global_permissions(self):
        """Test global create permissions for staff user"""
        # Test list permission with global view permission
        view = TestModelViewSet.as_view({"get": "list"})
        request = self.factory.get("/test-models/")
        request.user = self.staff_user

        response = view(request)
        self.assertEqual(response.status_code, 200)

        # Test create permission with global add permission
        view = TestModelViewSet.as_view({"post": "create"})
        request = self.factory.post("/test-models/", {"name": "New Object"})
        request.user = self.staff_user

        response = view(request)
        self.assertEqual(response.status_code, 201)

    def test_object_permissions(self):
        """Test object-level permissions"""
        # Regular user has view permission on private_obj but not others
        view = TestModelViewSet.as_view({"get": "retrieve"})

        # Test object they have permission for
        request = self.factory.get(f"/test-models/{self.private_obj.pk}/")
        request.user = self.regular_user
        response = view(request, pk=self.private_obj.pk)
        self.assertEqual(response.status_code, 200)

        # Test object they don't have permission for
        request = self.factory.get(f"/test-models/{self.owned_obj.pk}/")
        request.user = self.regular_user
        response = view(request, pk=self.owned_obj.pk)
        self.assertEqual(
            response.status_code, 404
        )  # Should be forbidden, but shown as a 404 because they don't have read permissions to know that it should be a 403

        # Test public object (should be accessible due to is_public=True in obj_filter)
        request = self.factory.get(f"/test-models/{self.public_obj.pk}/")
        request.user = self.regular_user
        response = view(request, pk=self.public_obj.pk)
        self.assertEqual(response.status_code, 200)

    def test_object_update_permissions(self):
        """Test update permissions at object level"""
        view = TestModelViewSet.as_view({"put": "update"})

        # Regular user has change permission on private_obj
        request = self.factory.put(
            f"/test-models/{self.private_obj.pk}/", {"name": "Updated Name"}
        )
        request.user = self.regular_user
        response = view(request, pk=self.private_obj.pk)
        self.assertEqual(response.status_code, 200)

        # Regular user doesn't have change permission on owned_obj
        request = self.factory.put(
            f"/test-models/{self.owned_obj.pk}/", {"name": "Updated Name"}
        )
        request.user = self.regular_user
        response = view(request, pk=self.owned_obj.pk)
        self.assertEqual(response.status_code, 404)

    def test_custom_action_permissions(self):
        """Test custom action with context-based permissions"""
        view = TestModelViewSet.as_view({"get": "custom_action"})

        print(self.owner_user.get_all_permissions(self.owned_obj))

        # Owner should have access to their object via owner_id filter
        request = self.factory.get(f"/test-models/{self.owned_obj.pk}/custom_action/")
        request.user = self.owner_user
        response = view(request, pk=self.owned_obj.pk)
        self.assertEqual(response.status_code, 200)

        # Regular user shouldn't have access to owned object
        request = self.factory.get(f"/test-models/{self.owned_obj.pk}/custom_action/")
        request.user = self.regular_user
        response = view(request, pk=self.owned_obj.pk)
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
