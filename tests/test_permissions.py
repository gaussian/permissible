import unittest
from unittest.mock import MagicMock, patch
from django.http import Http404
from rest_framework.exceptions import PermissionDenied

from permissible.permissions import PermissiblePerms
from permissible.utils.views import make_context_from_request
from permissible.models.permissible_mixin import PermissibleMixin
from permissible.perm_def import PermDef
from permissible.filters import PermissibleFilter  # Add this import


# Dummy classes for testing
class DummyUser:
    def __init__(self, is_authenticated=True, is_superuser=False):
        self.is_authenticated = is_authenticated
        self.is_superuser = is_superuser


class DummyObj:
    def __init__(self, pk=1, allowed=True, retrieve_allowed=True, _state=None):
        self.pk = pk
        self.allowed = allowed
        self.retrieve_allowed = retrieve_allowed
        self._state = _state or MagicMock()
        self._state.adding = False

    def has_object_permission(self, user, action, context=None):
        if action == "retrieve":
            return self.retrieve_allowed
        return self.allowed


class DummyModel(PermissibleMixin):
    # Class-level flag for global permission result
    global_permission = True

    # Mock Django model _meta attribute
    _meta = type("Meta", (), {"app_label": "testapp", "model_name": "dummymodel"})

    @classmethod
    def get_policies(cls):
        """Return mock policies for testing"""
        return {
            "global": {
                "create": PermDef(["add"]),
                "list": PermDef(["view"]),
                "retrieve": PermDef(["view"]),
                "update": PermDef(["change"]),
                "partial_update": PermDef(["change"]),
                "destroy": PermDef(["delete"]),
            },
            "object": {
                "retrieve": PermDef(["view"]),
                "update": PermDef(["change"]),
                "partial_update": PermDef(["change"]),
                "destroy": PermDef(["delete"]),
            },
        }

    @classmethod
    def has_global_permission(cls, user, action, context=None):
        """Override to use our test behavior but preserve superuser check"""
        # Preserve superuser bypass from PermissibleMixin
        if user.is_superuser:
            return True

        if not user.is_authenticated and action == "create":
            return False  # Unauthenticated users can't create
        return cls.global_permission

    @classmethod
    def make_objs_from_data(cls, data):
        # Data is expected to be a list of dicts with key 'allow'
        if not isinstance(data, list):
            data = [data]

        objs = []
        for item in data:
            # Create a dummy object with the specified permissions
            allowed = item.get("allow", True)
            retrieve_allowed = item.get("retrieve_allow", True)
            objs.append(DummyObj(allowed=allowed, retrieve_allowed=retrieve_allowed))
        return objs


class DummyQuerySet:
    # Return DummyModel as the model
    model = DummyModel


class DummyView:
    # Simulate a DRF view with required attributes
    def __init__(
        self,
        action="retrieve",
        detail=True,
        ignore=False,
        query_params=None,
        data=None,
        list_actions=None,
    ):
        self._ignore_model_permissions = ignore
        self.action = action
        self.detail = detail
        self.query_params = query_params or {}
        self.data = data or []
        self.LIST_ACTIONS = list_actions if list_actions is not None else ("list",)
        self.permission_classes = [PermissiblePerms]
        self.queryset = DummyQuerySet()
        self._permissible_filter = True  # Simulate config check
        # Use actual PermissibleFilter class instead of string
        self.filter_backends = [PermissibleFilter]

    def get_filter_backends(self):
        return self.filter_backends


class DummyRequest:
    def __init__(self, user, query_params=None, data=None):
        self.user = user
        self.query_params = query_params or {}
        self.data = data or {}


class TestPermissiblePerms(unittest.TestCase):

    def setUp(self):
        # Reset global permission to default True before each test
        DummyModel.global_permission = True

    def get_permission_instance(self, permission_class=PermissiblePerms):
        instance = permission_class()
        # Monkey-patch _queryset to return DummyQuerySet
        instance._queryset = lambda view: DummyQuerySet()
        return instance

    def test_ignore_model_permissions(self):
        # When view._ignore_model_permissions is True, has_permission should return True
        user = DummyUser(is_authenticated=False)
        view = DummyView(action="any", ignore=True)
        request = DummyRequest(user=user)
        perms = self.get_permission_instance()
        result = perms.has_permission(request, view)
        self.assertTrue(result)

    def test_global_permission_false(self):
        # Authenticated user but global permission check fails should return False.
        DummyModel.global_permission = False
        user = DummyUser(is_authenticated=True)
        view = DummyView(action="retrieve", detail=True)
        request = DummyRequest(user=user)
        perms = self.get_permission_instance()
        result = perms.has_permission(request, view)
        self.assertFalse(result)

    def test_superuser_global_permission(self):
        # Test that superuser can access content even when global permission is False
        DummyModel.global_permission = False
        user = DummyUser(is_authenticated=True, is_superuser=True)
        view = DummyView(action="retrieve", detail=True)
        request = DummyRequest(user=user)
        perms = self.get_permission_instance()
        result = perms.has_permission(request, view)

        # Even though global permission is False, superuser should be able to access
        self.assertTrue(result, "Superuser should bypass global permission checks")

    def test_create_action_all_objects_allowed(self):
        # For actions like create (non-detail), has_permission returns True if all dummy objs allow access
        user = DummyUser(is_authenticated=True)
        data = [{"allow": True}, {"allow": True}]
        view = DummyView(action="create", detail=False)
        request = DummyRequest(user=user, data=data)
        perms = self.get_permission_instance()
        result = perms.has_permission(request, view)
        self.assertTrue(result)

    def test_create_action_one_object_denied(self):
        # Test non-detail action where one of the dummy objects denies permission
        user = DummyUser(is_authenticated=True)
        data = [{"allow": True}, {"allow": False}]
        view = DummyView(action="create", detail=False)
        request = DummyRequest(user=user, data=data)
        perms = self.get_permission_instance()
        # Since one object returns False, overall result should be False
        result = perms.has_permission(request, view)
        self.assertFalse(result)

    def test_unauthenticated_denied_for_create(self):
        # Test that unauthenticated users are denied for create action
        user = DummyUser(is_authenticated=False)
        data = [{"allow": True}]
        view = DummyView(action="create", detail=False)
        request = DummyRequest(user=user, data=data)
        perms = self.get_permission_instance()
        result = perms.has_permission(request, view)
        self.assertFalse(result)

    def test_object_permission_granted(self):
        # Test that object permission check works properly when permission is granted
        user = DummyUser(is_authenticated=True)
        view = DummyView(action="update", detail=True)
        request = DummyRequest(user=user)
        perms = self.get_permission_instance()
        obj = DummyObj(allowed=True)

        result = perms.has_object_permission(request, view, obj)
        self.assertTrue(result)

    def test_object_permission_denied(self):
        # Test that object permission check works properly when permission is denied
        user = DummyUser(is_authenticated=True)
        view = DummyView(action="update", detail=True)
        request = DummyRequest(user=user)
        perms = self.get_permission_instance()
        obj = DummyObj(allowed=False)

        # Permission denied but user is authenticated
        result = perms.has_object_permission(request, view, obj)
        self.assertFalse(result)

    def test_object_permission_denied_unauthenticated(self):
        # Test that object permission denies unauthenticated users
        user = DummyUser(is_authenticated=False)
        view = DummyView(action="update", detail=True)
        request = DummyRequest(user=user)
        perms = self.get_permission_instance()
        obj = DummyObj(allowed=False)

        # Should return False for unauthenticated users
        result = perms.has_object_permission(request, view, obj)
        self.assertFalse(result)

    def test_retrieve_denied_raises_http404(self):
        """Test that denied retrieve permission raises Http404 when retrieve permission is denied"""
        user = DummyUser(is_authenticated=True)
        view = DummyView(action="retrieve", detail=True)
        request = DummyRequest(user=user)
        perms = self.get_permission_instance()

        # Create an object that will fail permission checks
        obj = DummyObj(allowed=False, retrieve_allowed=False)

        # The key issue: PermissiblePerms.has_object_permission needs to call
        # obj.has_object_permission and then handle the response correctly

        # Mock obj.has_object_permission to always return False for both retrieve and update
        with patch.object(obj, "has_object_permission", return_value=False):
            # This should raise Http404 because retrieve permission fails
            with self.assertRaises(Http404):
                perms.has_object_permission(request, view, obj)

    def test_update_denied_with_retrieve_allowed(self):
        # Test that update denied but retrieve allowed returns False (not Http404)
        user = DummyUser(is_authenticated=True)
        view = DummyView(action="update", detail=True)
        request = DummyRequest(user=user)
        perms = self.get_permission_instance()
        obj = DummyObj(allowed=False, retrieve_allowed=True)

        # Should return False (not raise Http404) when user can retrieve but not update
        result = perms.has_object_permission(request, view, obj)
        self.assertFalse(result)

    def test_update_denied_with_retrieve_denied_raises_http404(self):
        """Test that update denied and retrieve denied raises Http404"""
        user = DummyUser(is_authenticated=True)
        view = DummyView(action="update", detail=True)  # Note: action is "update"
        request = DummyRequest(user=user)
        perms = self.get_permission_instance()
        obj = DummyObj(allowed=False, retrieve_allowed=False)

        # Mock has_object_permission to simulate permissions failing for both update and retrieve
        original_has_object_permission = obj.has_object_permission

        def mock_has_object_permission(user, action, context=None):
            # Return False for any action
            return False

        with patch.object(
            obj, "has_object_permission", side_effect=mock_has_object_permission
        ):
            # Should raise Http404 because both update and retrieve permissions fail
            with self.assertRaises(Http404):
                perms.has_object_permission(request, view, obj)

    def test_adding_object_denied_returns_false(self):
        # Test that adding object (state.adding=True) with permission denied returns False
        user = DummyUser(is_authenticated=True)
        view = DummyView(action="create", detail=False)
        request = DummyRequest(user=user)
        perms = self.get_permission_instance()

        # Create an object that's being added (not yet saved)
        obj = DummyObj(allowed=False)
        obj._state.adding = True

        # Should return False instead of raising Http404
        result = perms.has_object_permission(request, view, obj)
        self.assertFalse(result)

    # Fix the patch path to target where make_context_from_request is imported in permissions.py
    @patch("permissible.permissions.make_context_from_request")
    def test_make_context_from_request_called(self, mock_make_context):
        # Test that make_context_from_request is called when checking permissions
        mock_make_context.return_value = {"test": "context"}

        user = DummyUser(is_authenticated=True)
        view = DummyView(action="retrieve", detail=True)
        request = DummyRequest(user=user)
        perms = self.get_permission_instance()

        # Call has_permission
        perms.has_permission(request, view)

        # Verify make_context_from_request was called
        mock_make_context.assert_called_once_with(request)

    def test_check_view_config_success(self):
        # Test that _check_view_config succeeds with properly configured view
        view = DummyView()
        perms = self.get_permission_instance()

        # Should not raise an exception
        perms._check_view_config(view, view.queryset)

    def test_check_view_config_failure(self):
        # Test that _check_view_config fails with incorrectly configured view
        view = DummyView()
        # Instead of just setting _permissible_filter=False,
        # completely remove the filter_backends attribute which will definitely fail the check
        view.filter_backends = []
        perms = self.get_permission_instance()

        # Should raise an exception
        with self.assertRaises(AssertionError):
            perms._check_view_config(view, view.queryset)

    def test_check_view_config_failure_missing_queryset_model(self):
        # Test that _check_view_config fails when queryset.model is missing
        view = DummyView()
        # Remove the model attribute
        old_model = view.queryset.model
        view.queryset.model = None
        perms = self.get_permission_instance()

        # Should raise an assertion error
        with self.assertRaises(AssertionError):
            perms._check_view_config(view, view.queryset)

        # Restore the model attribute
        view.queryset.model = old_model


if __name__ == "__main__":
    unittest.main()
