import unittest
from unittest.mock import MagicMock, patch

from django.apps import apps
from django.db.models.query import QuerySet

from permissible.perm_def import PermDef
from permissible.perm_def.short_perms import ShortPermsMixin
from permissible.perm_def.base import BasePermDefObj


# Dummy user class
class DummyUser:
    def __init__(self, id, perms_result=True, pk=1, is_superuser=False):
        self.id = id
        self.perms_result = perms_result
        self.pk = pk
        self.is_superuser = is_superuser

    def has_perms(self, perms, obj=None):
        return self.perms_result


# Dummy object mixin for permissions
class DummyShortPermsMixin:
    """Standalone mixin for tests to avoid MRO conflicts"""

    @classmethod
    def get_permission_codenames(cls, short_perm_codes, include_app_label):
        if short_perm_codes is None:
            return []

        app_label = "testapp" if include_app_label else ""
        prefix = f"{app_label}." if app_label else ""

        return [f"{prefix}{code}_dummy" for code in short_perm_codes]


# Add this class before DummyObj
class MockManager:
    """Mock Django's model manager using descriptor pattern"""

    def __get__(self, obj, objtype=None):
        manager = MagicMock()
        manager.all.return_value = manager
        manager.filter.return_value = manager
        manager.exclude.return_value = manager
        manager.values_list.return_value = [1, 2, 3]  # PKs
        return manager


# Dummy object simulating BasePermDefObj functionality
class DummyObj(DummyShortPermsMixin):
    _meta = type("Meta", (), {"app_label": "testapp", "model_name": "dummy"})
    # Replace the @property @classmethod with descriptor
    objects = MockManager()

    def __init__(self, pk, allowed=True, **kwargs):
        self.pk = pk
        self.allowed = allowed
        # Add any additional attributes provided in kwargs
        for key, val in kwargs.items():
            setattr(self, key, val)

    def get_unretrieved(self, path):
        """
        Implement get_unretrieved to handle obj_path functionality
        """
        parts = path.split(".")
        current = self
        for part in parts:
            if hasattr(current, part):
                current = getattr(current, part)
            else:
                return None
        return current

    @classmethod
    def get_unretrieved_class(cls, path):
        """
        Mock implementation of get_unretrieved_class for testing
        """
        # Return the same class for testing
        return cls

    @classmethod
    def resolve_chain(cls, path):
        """
        Mock implementation of resolve_chain for testing filter_queryset
        """
        return {"final_model_class": cls, "root_query_path": path.replace(".", "__")}


# Dummy object to be used as a related object
class DummyRelatedObj(DummyObj):
    def __init__(self, pk=456, **kwargs):
        super().__init__(pk, **kwargs)


class TestPermDef(unittest.TestCase):

    def test_check_global_success(self):
        # PermDef with empty short_perm_codes and global_condition_checker always True
        perm_def = PermDef(
            short_perm_codes=[], global_condition_checker=lambda u, c: True
        )
        user = DummyUser(id=1)
        self.assertTrue(
            perm_def.check_global(DummyObj, user, context={"extra": "value"})
        )

    def test_check_global_fail(self):
        # PermDef with null short_perm_codes - should fail
        perm_def = PermDef(short_perm_codes=None)
        user = DummyUser(id=1)
        self.assertFalse(
            perm_def.check_global(DummyObj, user, context={"extra": "value"})
        )

    def test_check_global_fail_condition(self):
        # PermDef with a global_condition_checker that always returns False
        perm_def = PermDef(
            short_perm_codes=[], global_condition_checker=lambda u, c: False
        )
        user = DummyUser(id=1)
        self.assertFalse(perm_def.check_global(DummyObj, user))

    def test_check_obj_success(self):
        # Basic object permission check with simple short_perm_codes
        perm_def = PermDef(short_perm_codes=["view"])
        dummy_obj = DummyObj(pk=123)
        user = DummyUser(id=1, perms_result=True)
        self.assertTrue(perm_def.check_obj(dummy_obj, user))

    def test_obj_path_string(self):
        # Test obj_path as a string path to an attribute
        perm_def = PermDef(short_perm_codes=["view"], obj_path="related_obj")
        related = DummyRelatedObj(pk=789)
        dummy_obj = DummyObj(pk=123, related_obj=related)
        user = DummyUser(id=1, perms_result=True)
        self.assertTrue(perm_def.check_obj(dummy_obj, user))

    def test_obj_path_nested(self):
        # Test obj_path with multiple levels
        perm_def = PermDef(short_perm_codes=["view"], obj_path="parent.grandparent")
        grandparent = DummyObj(pk=789)
        parent = DummyObj(pk=456, grandparent=grandparent)
        child = DummyObj(pk=123, parent=parent)
        user = DummyUser(id=1, perms_result=True)
        self.assertTrue(perm_def.check_obj(child, user))

    def test_obj_path_missing_attribute(self):
        # Test obj_path with a missing attribute - should fail
        perm_def = PermDef(short_perm_codes=["view"], obj_path="nonexistent")
        dummy_obj = DummyObj(pk=123)
        user = DummyUser(id=1, perms_result=True)
        self.assertFalse(perm_def.check_obj(dummy_obj, user))

    @patch("django.apps.apps.get_model")
    def test_context_obj_path(self, mock_get_model):
        # Test using _context to get object
        mock_model = MagicMock()
        mock_model.objects.get.return_value = DummyObj(pk=888)
        mock_get_model.return_value = mock_model

        perm_def = PermDef(
            short_perm_codes=["view"],
            obj_path="_context.obj_id",
            model_label="testapp.dummy",
        )
        context = {"obj_id": 888}
        user = DummyUser(id=1, perms_result=True)

        self.assertTrue(perm_def.check_obj(DummyObj(pk=123), user, context=context))
        mock_model.objects.get.assert_called_once_with(pk=888)

    def test_obj_filter_equal(self):
        # Test obj_filter with equality check
        perm_def = PermDef(
            short_perm_codes=["view"], obj_filter=("status", "==", "public")
        )

        # Object with matching status should pass
        public_obj = DummyObj(pk=123, status="public")
        user = DummyUser(id=1, perms_result=True)
        self.assertTrue(perm_def.check_obj(public_obj, user))

        # Object with non-matching status should fail
        private_obj = DummyObj(pk=456, status="private")
        self.assertFalse(perm_def.check_obj(private_obj, user))

    def test_obj_filter_not_equal(self):
        # Test obj_filter with inequality check
        perm_def = PermDef(
            short_perm_codes=["view"], obj_filter=("status", "!=", "private")
        )

        # Object with non-matching status should pass
        public_obj = DummyObj(pk=123, status="public")
        user = DummyUser(id=1, perms_result=True)
        self.assertTrue(perm_def.check_obj(public_obj, user))

        # Object with matching status should fail
        private_obj = DummyObj(pk=456, status="private")
        self.assertFalse(perm_def.check_obj(private_obj, user))

    def test_obj_filter_greater_than(self):
        # Test obj_filter with greater than check
        perm_def = PermDef(short_perm_codes=["view"], obj_filter=("value", ">", 50))

        # Object with value > 50 should pass
        high_value_obj = DummyObj(pk=123, value=100)
        user = DummyUser(id=1, perms_result=True)
        self.assertTrue(perm_def.check_obj(high_value_obj, user))

        # Object with value <= 50 should fail
        low_value_obj = DummyObj(pk=456, value=50)
        self.assertFalse(perm_def.check_obj(low_value_obj, user))

    def test_obj_filter_less_than(self):
        # Test obj_filter with less than check
        perm_def = PermDef(short_perm_codes=["view"], obj_filter=("value", "<", 50))

        # Object with value < 50 should pass
        low_value_obj = DummyObj(pk=123, value=20)
        user = DummyUser(id=1, perms_result=True)
        self.assertTrue(perm_def.check_obj(low_value_obj, user))

        # Object with value >= 50 should fail
        high_value_obj = DummyObj(pk=456, value=50)
        self.assertFalse(perm_def.check_obj(high_value_obj, user))

    def test_obj_filter_context_value(self):
        # Test obj_filter with value from context
        perm_def = PermDef(
            short_perm_codes=["view"],
            obj_filter=("owner_id", "==", "_context.request.user.id"),
        )

        user = DummyUser(id=42)
        context = {"user": user, "request": {"user": user}}

        # Object with matching owner_id should pass
        owned_obj = DummyObj(pk=123, owner_id=42)
        self.assertTrue(perm_def.check_obj(owned_obj, user, context))

        # Object with non-matching owner_id should fail
        other_obj = DummyObj(pk=456, owner_id=99)
        self.assertFalse(perm_def.check_obj(other_obj, user, context))

    # Change this test to patch the correct path
    @patch(
        "guardian.shortcuts.get_objects_for_user"
    )  # Changed from permissible.perm_def.perm_def.get_objects_for_user
    def test_filter_queryset_basic(self, mock_get_objects_for_user):
        # Test the basic filtering functionality
        # Setup mocks
        queryset = MagicMock(spec=QuerySet)
        model = DummyObj
        queryset.model = model

        # Configure the mock to return the same queryset
        mock_get_objects_for_user.return_value = queryset

        # Create PermDef and test
        perm_def = PermDef(short_perm_codes=["view"])
        user = DummyUser(id=1)

        result = perm_def.filter_queryset(queryset, user)

        # Verify get_objects_for_user was called correctly
        mock_get_objects_for_user.assert_called_once()
        self.assertEqual(result, queryset)

    # Change this test to patch the correct path
    @patch(
        "guardian.shortcuts.get_objects_for_user"
    )  # Changed from permissible.perm_def.perm_def.get_objects_for_user
    def test_filter_queryset_with_obj_path(self, mock_get_objects_for_user):
        # Test filtering with obj_path
        # Setup mocks
        queryset = MagicMock(spec=QuerySet)
        model = DummyObj
        queryset.model = model

        related_queryset = MagicMock(spec=QuerySet)
        related_queryset.values_list.return_value = [1, 2, 3]  # PKs
        mock_get_objects_for_user.return_value = related_queryset

        # Create filtered queryset mock
        filtered_queryset = MagicMock(spec=QuerySet)
        queryset.filter.return_value = filtered_queryset

        # Create PermDef with obj_path and test
        perm_def = PermDef(short_perm_codes=["view"], obj_path="related")
        user = DummyUser(id=1)

        result = perm_def.filter_queryset(queryset, user)

        # Verify the filter was applied correctly
        queryset.filter.assert_called_once()
        self.assertEqual(result, filtered_queryset)

    # Change this test to patch the correct path
    @patch(
        "guardian.shortcuts.get_objects_for_user"
    )  # Changed from permissible.perm_def.perm_def.get_objects_for_user
    def test_filter_queryset_with_obj_filter(self, mock_get_objects_for_user):
        # Test filtering with obj_filter
        # Setup mocks
        queryset = MagicMock(spec=QuerySet)
        model = DummyObj
        queryset.model = model

        filtered_by_status = MagicMock(spec=QuerySet)
        queryset.filter.return_value = filtered_by_status

        mock_get_objects_for_user.return_value = filtered_by_status

        # Create PermDef with obj_filter and test
        perm_def = PermDef(
            short_perm_codes=["view"], obj_filter=("status", "==", "public")
        )
        user = DummyUser(id=1)

        result = perm_def.filter_queryset(queryset, user)

        # Verify the filter was applied
        queryset.filter.assert_called_once_with(status="public")
        mock_get_objects_for_user.assert_called_once()
        self.assertEqual(result, filtered_by_status)

    def test_empty_short_perm_codes(self):
        # Test that empty short_perm_codes always passes
        perm_def = PermDef(short_perm_codes=[])
        user = DummyUser(id=1, perms_result=False)  # Even with perms_result=False
        dummy_obj = DummyObj(pk=123)

        self.assertTrue(perm_def.check_obj(dummy_obj, user))
        self.assertTrue(perm_def.check_global(DummyObj, user))

    def test_global_condition_checker(self):
        # Test that global_condition_checker works in both global and object permission checks
        context = {"allowed": True}

        perm_def = PermDef(
            short_perm_codes=["view"],
            global_condition_checker=lambda u, c: c.get("allowed", False),
        )
        user = DummyUser(id=1, perms_result=True)
        dummy_obj = DummyObj(pk=123)

        # With allowed=True in context
        self.assertTrue(perm_def.check_obj(dummy_obj, user, context))
        self.assertTrue(perm_def.check_global(DummyObj, user, context))

        # With allowed=False in context
        context["allowed"] = False
        self.assertFalse(perm_def.check_obj(dummy_obj, user, context))
        self.assertFalse(perm_def.check_global(DummyObj, user, context))

    @patch("django.apps.apps.get_model")
    def test_model_label_with_global(self, mock_get_model):
        # Test that model_label works with check_global
        mock_model = MagicMock()
        mock_get_model.return_value = mock_model

        perm_def = PermDef(short_perm_codes=["view"], model_label="testapp.otherdummy")
        user = DummyUser(id=1, perms_result=True)

        self.assertTrue(perm_def.check_global(DummyObj, user))
        mock_get_model.assert_called_once_with("testapp.otherdummy")

    def test_or_operator_overloading(self):
        # Test the | operator overloading
        perm_def1 = PermDef(short_perm_codes=["view"])
        perm_def2 = PermDef(short_perm_codes=["change"])

        # Combine with OR
        combined = perm_def1 | perm_def2

        # Check that it's a CompositePermDef
        from permissible.perm_def.composite import CompositePermDef

        self.assertIsInstance(combined, CompositePermDef)
        self.assertEqual(combined.operator, "or")
        self.assertEqual(combined.perm_defs, [perm_def1, perm_def2])

    def test_and_operator_overloading(self):
        # Test the & operator overloading
        perm_def1 = PermDef(short_perm_codes=["view"])
        perm_def2 = PermDef(short_perm_codes=["change"])

        # Combine with AND
        combined = perm_def1 & perm_def2

        # Check that it's a CompositePermDef
        from permissible.perm_def.composite import CompositePermDef

        self.assertIsInstance(combined, CompositePermDef)
        self.assertEqual(combined.operator, "and")
        self.assertEqual(combined.perm_defs, [perm_def1, perm_def2])

    def test_allow_blank_functionality(self):
        """Test the allow_blank parameter in PermDef."""
        # Create a user with permissions for testing
        user = DummyUser(id=1, perms_result=True)

        # Create a base object with no "related" field (None)
        base_obj = DummyObj(pk=123)

        # Create a base object with "related" field that has no PK
        obj_without_pk = DummyObj(pk=None)
        base_obj_with_related = DummyObj(pk=456, related=obj_without_pk)

        # Case 1: Default behavior (allow_blank=False)
        # Should fail when object is None
        perm_def = PermDef(short_perm_codes=["view"], obj_path="nonexistent")
        self.assertFalse(perm_def.check_obj(base_obj, user))

        # Should fail when object has no PK
        perm_def = PermDef(short_perm_codes=["view"], obj_path="related")
        self.assertFalse(perm_def.check_obj(base_obj_with_related, user))

        # Case 2: With allow_blank=True
        # Should proceed to _check_perms when object is None
        perm_def = PermDef(
            short_perm_codes=["view"], obj_path="nonexistent", allow_blank=True
        )
        self.assertTrue(perm_def.check_obj(base_obj, user))

        # Should proceed to _check_perms when object has no PK
        perm_def = PermDef(
            short_perm_codes=["view"], obj_path="related", allow_blank=True
        )
        self.assertTrue(perm_def.check_obj(base_obj_with_related, user))


if __name__ == "__main__":
    unittest.main()
