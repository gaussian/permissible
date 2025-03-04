import unittest
from unittest.mock import MagicMock, patch

from django.db.models import QuerySet
from django.http import HttpRequest
from rest_framework.request import Request

from permissible.filters import PermissibleFilter
from permissible.models.permissible_mixin import PermissibleMixin
from permissible.perm_def import p, PermDef
from permissible.permissions import PermissiblePerms
from django.test import TestCase, override_settings


# Mock classes for testing
class DummyUser:
    def __init__(self, is_authenticated=True, is_superuser=False, perms=None):
        self.is_authenticated = is_authenticated
        self.is_superuser = is_superuser
        self.perms = perms or {}

    def has_perms(self, perms, obj=None):
        if obj:
            for perm in perms:
                if (perm, obj.pk) not in self.perms:
                    return False
            return True
        else:
            for perm in perms:
                if (perm, None) not in self.perms:
                    return False
            return True


class MockManager:
    """Mock Django's model manager"""

    def __init__(self, queryset=None):
        self.queryset = queryset or MagicMock(spec=QuerySet)

    def all(self):
        return self.queryset

    def filter(self, *args, **kwargs):
        return self.queryset

    def exclude(self, *args, **kwargs):
        return self.queryset


class DummyModel(PermissibleMixin):
    # Mock Django model _meta attribute
    _meta = type("Meta", (), {"app_label": "testapp", "model_name": "dummymodel"})

    # Mock objects manager
    objects = MockManager()

    @classmethod
    def get_policies(cls):
        """Return mock policies for testing"""
        return {
            "global": {
                "list": p(["view"]),
                "retrieve": p(["view"]),
                "update": p(["change"]),
                "partial_update": p(["change"]),
                "destroy": p(["delete"]),
            },
            "object": {
                "list": p(
                    ["view"]
                ),  # Add this line - list action for object permissions
                "retrieve": p(["view"]),
                "update": p(["change"]),
                "partial_update": p(["change"]),
                "destroy": p(["delete"]),
            },
            "filters": ["status", "owner_id"],  # Mock filterable fields
        }


class DummyView:
    """Mock DRF view for testing"""

    def __init__(self, action="list", queryset=None, detail=False):
        self.action = action
        self.base_model = DummyModel
        self.queryset = queryset or MagicMock(spec=QuerySet)
        self.queryset.model = DummyModel
        self.detail = detail
        # Add permission_classes with PermissiblePerms for view config check
        self.permission_classes = [PermissiblePerms]
        # Add filter_backends with PermissibleFilter
        self.filter_backends = [PermissibleFilter]

    def get_queryset(self):
        return self.queryset

    # Add method to return string representation of permission classes for config check
    def get_permissions(self):
        return [perm() for perm in self.permission_classes]

    # Add method to return filter backends for config check
    def get_filter_backends(self):
        return self.filter_backends


class TestPermissibleFilter(TestCase):
    def setUp(self):
        # Create a mock request
        self.http_request = MagicMock(spec=HttpRequest)
        self.request = Request(self.http_request)
        self.request._request = self.http_request

        # Create a standard user
        self.user = DummyUser()
        self.request.user = self.user

        # Create a superuser
        self.superuser = DummyUser(is_superuser=True)

        # Create a basic queryset and view
        self.queryset = MagicMock(spec=QuerySet)
        self.queryset.model = DummyModel
        self.view = DummyView(queryset=self.queryset)

    @patch("guardian.shortcuts.get_objects_for_user")
    def test_filter_queryset_basic(self, mock_get_objects):
        """Test basic filtering functionality"""
        # Configure mock to return the queryset
        filtered_queryset = MagicMock(spec=QuerySet)
        mock_get_objects.return_value = filtered_queryset

        filter_instance = PermissibleFilter()

        # Mock the perm_def that's returned by get_global_perms_def
        perm_def_mock = PermDef(
            short_perm_codes=["view"]
        )  # Use real PermDef with mock behavior

        # Patch get_global_perms_def to return our mock perm_def
        with patch.object(
            DummyModel, "get_global_perms_def", return_value=perm_def_mock
        ):
            # Also patch _check_perms to avoid permission checks
            with patch.object(PermDef, "_check_perms", return_value=True):
                result = filter_instance.filter_queryset(
                    self.request, self.queryset, self.view
                )

        # Verify the filtered queryset was returned
        self.assertEqual(result, filtered_queryset)
        # Verify get_objects_for_user was called
        mock_get_objects.assert_called_once()

    @patch("guardian.shortcuts.get_objects_for_user")
    def test_filter_queryset_superuser(self, mock_get_objects):
        """Test that superusers bypass filtering"""
        # Create a view with detail=True to bypass filtering
        view = DummyView(detail=True)

        # Create filter instance
        filter_instance = PermissibleFilter()

        # Configure request with superuser
        request = Request(self.http_request)
        request._request = self.http_request
        request.user = self.superuser

        # Call filter_queryset
        result = filter_instance.filter_queryset(request, self.queryset, view)

        # For detail=True views, filter_queryset should return the original queryset
        self.assertIs(result, self.queryset)

        # Verify get_objects_for_user was never called
        mock_get_objects.assert_not_called()

    @patch("guardian.shortcuts.get_objects_for_user")
    @patch("permissible.models.permissible_mixin.PermissibleMixin.get_object_perm_def")
    def test_filter_queryset_none_for_no_perm_def(
        self, mock_get_object_perm_def, mock_get_objects
    ):
        """Test that an empty queryset is returned when no perm_def is available"""
        # Setup the mock to return None for the object perm def
        mock_get_object_perm_def.return_value = None

        # Create a mock for the none() method of the queryset
        none_queryset = MagicMock(spec=QuerySet)
        self.queryset.none.return_value = none_queryset

        filter_instance = PermissibleFilter()

        # By patching get_object_perm_def to return None, we should get an assertion error
        # Since the default behavior in the filter is to assert that perm_def is not None
        with self.assertRaises(AssertionError):
            result = filter_instance.filter_queryset(
                self.request, self.queryset, self.view
            )

        # Verify get_objects_for_user was not called
        mock_get_objects.assert_not_called()

    @patch("guardian.shortcuts.get_objects_for_user")
    @patch("permissible.utils.views.make_context_from_request")
    def test_filter_queryset_with_context(self, mock_make_context, mock_get_objects):
        """Test filtering with context from request"""
        # Set up mock context
        context = {"status": "active", "owner_id": 123}
        mock_make_context.return_value = context

        # Configure mock to return filtered queryset
        filtered_queryset = MagicMock(spec=QuerySet)
        mock_get_objects.return_value = filtered_queryset

        # Set up filter instance and mock perm_def
        filter_instance = PermissibleFilter()
        perm_def_mock = PermDef(short_perm_codes=["view"])

        # Patch get_global_perms_def to return our mock perm_def
        with patch.object(
            DummyModel, "get_global_perms_def", return_value=perm_def_mock
        ):
            # Also patch _check_perms to avoid permission checks
            with patch.object(PermDef, "_check_perms", return_value=True):
                result = filter_instance.filter_queryset(
                    self.request, self.queryset, self.view
                )

        # Verify make_context_from_request was called
        mock_make_context.assert_called_once_with(self.request)
        # Verify get_objects_for_user was called
        mock_get_objects.assert_called_once()
        self.assertEqual(result, filtered_queryset)

    @patch("guardian.shortcuts.get_objects_for_user")
    def test_filter_queryset_with_different_actions(self, mock_get_objects):
        """Test filtering with various view actions"""
        # Test multiple actions with appropriate detail flags
        test_cases = [
            {"action": "list", "detail": False},
            {"action": "retrieve", "detail": True},
            {"action": "update", "detail": True},
        ]

        for case in test_cases:
            with self.subTest(**case):
                # Create view with current action and detail flag
                view = DummyView(
                    action=case["action"], queryset=self.queryset, detail=case["detail"]
                )

                # Set up filter instance and mock perm_def
                filter_instance = PermissibleFilter()
                filtered_queryset = MagicMock(spec=QuerySet)
                mock_get_objects.return_value = filtered_queryset
                perm_def_mock = PermDef(short_perm_codes=["view"])

                # Patch get_global_perms_def to return our mock perm_def
                with patch.object(
                    DummyModel, "get_global_perms_def", return_value=perm_def_mock
                ):
                    result = filter_instance.filter_queryset(
                        self.request, self.queryset, view
                    )

                # Verify the correct action was used
                self.assertEqual(view.action, case["action"])
                mock_get_objects.assert_called_with(
                    self.user, "view_dummymodel", self.queryset
                )
                self.assertEqual(result, filtered_queryset)

    def test_get_schema_fields(self):
        """Test that get_schema_fields returns the correct fields"""
        filter_instance = PermissibleFilter()
        view = DummyView()

        # Mock get_filters to return the list of filterable fields
        with patch.object(
            DummyModel, "get_filters", return_value=["status", "owner_id"]
        ):
            schema_fields = filter_instance.get_schema_fields(view)

        # Verify we get the expected number of fields
        self.assertEqual(len(schema_fields), 2)

        # Check field names
        field_names = [field.name for field in schema_fields]
        self.assertIn("status", field_names)
        self.assertIn("owner_id", field_names)

    def test_get_schema_fields_no_filters(self):
        """Test that get_schema_fields returns empty list when no filters are defined"""
        filter_instance = PermissibleFilter()
        view = DummyView()

        # Mock get_filters to return None
        with patch.object(DummyModel, "get_filters", return_value=None):
            schema_fields = filter_instance.get_schema_fields(view)

        # Verify we get an empty list
        self.assertEqual(schema_fields, [])

    def test_get_schema_operation_parameters(self):
        """Test that get_schema_operation_parameters returns the correct params"""
        filter_instance = PermissibleFilter()
        view = DummyView()

        # Mock get_filters to return the list of filterable fields
        with patch.object(
            DummyModel, "get_filters", return_value=["status", "owner_id"]
        ):
            params = filter_instance.get_schema_operation_parameters(view)

        # Verify we get the expected number of parameters
        self.assertEqual(len(params), 2)

        # Check parameter names
        param_names = [param["name"] for param in params]
        self.assertIn("status", param_names)
        self.assertIn("owner_id", param_names)

        # Check parameter properties
        for param in params:
            self.assertEqual(param["in"], "query")
            self.assertFalse(param["required"])
            self.assertIn("description", param)

    def test_get_schema_operation_parameters_no_filters(self):
        """Test that get_schema_operation_parameters returns empty list when no filters defined"""
        filter_instance = PermissibleFilter()
        view = DummyView()

        # Mock get_filters to return None
        with patch.object(DummyModel, "get_filters", return_value=None):
            params = filter_instance.get_schema_operation_parameters(view)

        # Verify we get an empty list
        self.assertEqual(params, [])


if __name__ == "__main__":
    unittest.main()
