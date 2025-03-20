import unittest
from unittest.mock import MagicMock, patch
from django.db.models.query import QuerySet

from permissible.perm_def import PermDef
from permissible.perm_def.composite import CompositePermDef
from permissible.perm_def.short_perms import ShortPermsMixin


# Reuse dummy classes from test_perm_def for consistency
class DummyUser:
    def __init__(self, id, perms_result=True, pk=1):
        self.id = id
        self.perms_result = perms_result
        self.pk = pk

    def has_perms(self, perms, obj):
        return self.perms_result


# Mock manager class for queryset operations
class MockManager:
    def __get__(self, obj, objtype=None):
        manager = MagicMock()
        manager.all.return_value = manager
        manager.filter.return_value = manager
        manager.exclude.return_value = manager
        manager.values_list.return_value = [1, 2, 3]
        manager.none.return_value = MagicMock(spec=QuerySet)
        return manager


class DummyShortPermsMixin:
    @classmethod
    def get_permission_codenames(cls, short_perm_codes, include_app_label):
        if short_perm_codes is None:
            return []
        app_label = "testapp" if include_app_label else ""
        prefix = f"{app_label}." if app_label else ""
        return [f"{prefix}{code}_dummy" for code in short_perm_codes]


class DummyObj(DummyShortPermsMixin):
    _meta = type("Meta", (), {"app_label": "testapp", "model_name": "dummy"})
    objects = MockManager()

    def __init__(self, pk, allowed=True, **kwargs):
        self.pk = pk
        self.allowed = allowed
        for key, val in kwargs.items():
            setattr(self, key, val)

    def get_unretrieved(self, path):
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
        return cls

    @classmethod
    def resolve_chain(cls, path):
        return {"final_model_class": cls, "root_query_path": path.replace(".", "__")}


class TestCompositePermDef(unittest.TestCase):
    """Test cases for the CompositePermDef class and operator overloading."""

    def setUp(self):
        """Set up test fixtures."""
        self.dummy_obj = DummyObj(pk=123)
        self.user = DummyUser(id=1)
        self.context = {"test_key": "test_value"}

        # Create basic permission definitions for testing
        self.true_perm = PermDef(
            short_perm_codes=["view"], global_condition_checker=lambda u, c: True
        )
        self.false_perm = PermDef(
            short_perm_codes=["view"], global_condition_checker=lambda u, c: False
        )
        self.path_perm = PermDef(short_perm_codes=["view"], obj_path="related")
        self.filter_perm = PermDef(
            short_perm_codes=["view"], obj_filter=("status", "==", "public")
        )

    def test_composite_or_check_obj(self):
        """Test OR composite behavior for object checks."""
        # Create composite with OR operator
        composite = CompositePermDef([self.true_perm, self.false_perm], "or")

        # Should pass because at least one permission (true_perm) passes
        self.assertTrue(composite.check_obj(self.dummy_obj, self.user))

        # Create composite with only failing permissions
        all_false = CompositePermDef([self.false_perm, self.false_perm], "or")

        # Should fail because no permissions pass
        self.assertFalse(all_false.check_obj(self.dummy_obj, self.user))

    def test_composite_and_check_obj(self):
        """Test AND composite behavior for object checks."""
        # Create composite with AND operator
        composite = CompositePermDef([self.true_perm, self.false_perm], "and")

        # Should fail because not all permissions pass
        self.assertFalse(composite.check_obj(self.dummy_obj, self.user))

        # Create composite with all passing permissions
        all_true = CompositePermDef([self.true_perm, self.true_perm], "and")

        # Should pass because all permissions pass
        self.assertTrue(all_true.check_obj(self.dummy_obj, self.user))

    def test_composite_or_check_global(self):
        """Test OR composite behavior for global checks."""
        composite = CompositePermDef([self.true_perm, self.false_perm], "or")

        # Should pass because at least one permission passes
        self.assertTrue(composite.check_global(DummyObj, self.user))

        all_false = CompositePermDef([self.false_perm, self.false_perm], "or")

        # Should fail because no permissions pass
        self.assertFalse(all_false.check_global(DummyObj, self.user))

    def test_composite_and_check_global(self):
        """Test AND composite behavior for global checks."""
        composite = CompositePermDef([self.true_perm, self.false_perm], "and")

        # Should fail because not all permissions pass
        self.assertFalse(composite.check_global(DummyObj, self.user))

        all_true = CompositePermDef([self.true_perm, self.true_perm], "and")

        # Should pass because all permissions pass
        self.assertTrue(all_true.check_global(DummyObj, self.user))

    def test_or_operator_overloading(self):
        """Test the | operator for combining permissions with OR logic."""
        # Create combined permission using | operator
        combined = self.true_perm | self.false_perm

        # Check that the combined permission is a CompositePermDef with OR logic
        self.assertIsInstance(combined, CompositePermDef)
        self.assertEqual(combined.operator, "or")
        self.assertEqual(len(combined.perm_defs), 2)

        # Check that the combined permission works correctly
        self.assertTrue(combined.check_obj(self.dummy_obj, self.user))

    def test_and_operator_overloading(self):
        """Test the & operator for combining permissions with AND logic."""
        # Create combined permission using & operator
        combined = self.true_perm & self.false_perm

        # Check that the combined permission is a CompositePermDef with AND logic
        self.assertIsInstance(combined, CompositePermDef)
        self.assertEqual(combined.operator, "and")
        self.assertEqual(len(combined.perm_defs), 2)

        # Check that the combined permission works correctly
        self.assertFalse(combined.check_obj(self.dummy_obj, self.user))

    def test_or_operator_flattening(self):
        """Test that | operator flattens OR composites appropriately."""
        # Create an initial OR composite
        or_composite = self.true_perm | self.false_perm

        # Add another permission with |
        flattened = or_composite | self.true_perm

        # Should have all three permissions in a single OR composite
        self.assertIsInstance(flattened, CompositePermDef)
        self.assertEqual(flattened.operator, "or")
        self.assertEqual(len(flattened.perm_defs), 3)

        # The result should still pass the permission check
        self.assertTrue(flattened.check_obj(self.dummy_obj, self.user))

    def test_and_operator_flattening(self):
        """Test that & operator flattens AND composites appropriately."""
        # Create an initial AND composite
        and_composite = self.true_perm & self.true_perm

        # Add another permission with &
        flattened = and_composite & self.false_perm

        # Should have all three permissions in a single AND composite
        self.assertIsInstance(flattened, CompositePermDef)
        self.assertEqual(flattened.operator, "and")
        self.assertEqual(len(flattened.perm_defs), 3)

        # The result should fail the permission check (due to false_perm)
        self.assertFalse(flattened.check_obj(self.dummy_obj, self.user))

    def test_complex_composition(self):
        """Test complex compositions with multiple levels of operations."""
        # Create a more complex composition: (true & true) | (true & false)
        complex_perm = (self.true_perm & self.true_perm) | (
            self.true_perm & self.false_perm
        )

        # Should be an OR at the top level
        self.assertIsInstance(complex_perm, CompositePermDef)
        self.assertEqual(complex_perm.operator, "or")
        self.assertEqual(len(complex_perm.perm_defs), 2)

        # First element should be an AND composite
        self.assertIsInstance(complex_perm.perm_defs[0], CompositePermDef)
        self.assertEqual(complex_perm.perm_defs[0].operator, "and")

        # Second element should be an AND composite
        self.assertIsInstance(complex_perm.perm_defs[1], CompositePermDef)
        self.assertEqual(complex_perm.perm_defs[1].operator, "and")

        # The overall result should pass (because the first AND passes)
        self.assertTrue(complex_perm.check_obj(self.dummy_obj, self.user))

    def test_operator_with_non_perm_def(self):
        """Test that operators with non-PermDef objects return NotImplemented."""
        with self.assertRaises(TypeError):
            result = self.true_perm | "not a perm_def"

        with self.assertRaises(TypeError):
            result = self.true_perm & 42

    def test_invalid_operator(self):
        """Test that CompositePermDef raises ValueError for invalid operators."""
        with self.assertRaises(ValueError):
            CompositePermDef([self.true_perm, self.false_perm], "invalid_operator")

    @patch("guardian.shortcuts.get_objects_for_user")
    def test_composite_or_filter_queryset(self, mock_get_objects_for_user):
        # Let's simplify this test to focus on the core behavior
        queryset = MagicMock(spec=QuerySet)
        queryset.model = DummyObj

        # Create our result querysets
        result1 = MagicMock(spec=QuerySet)
        result2 = MagicMock(spec=QuerySet)
        final_result = MagicMock(spec=QuerySet)

        # Configure the mocks
        mock_get_objects_for_user.side_effect = [result1, result2]
        result1.union.return_value = final_result

        # Create the composite
        composite = CompositePermDef([self.true_perm, self.path_perm], "or")

        # Run the filter_queryset method
        result = composite.filter_queryset(queryset, self.user, self.context)

        # Verify the result - we just want to check if union was called
        self.assertEqual(result1.union.call_count, 1)
        self.assertEqual(result, final_result)

    @patch("guardian.shortcuts.get_objects_for_user")
    def test_composite_and_filter_queryset(self, mock_get_objects_for_user):
        # Set up test data
        queryset = MagicMock(spec=QuerySet)
        queryset.model = DummyObj

        # Create our result querysets
        result1 = MagicMock(spec=QuerySet)
        result2 = MagicMock(spec=QuerySet)
        final_result = MagicMock(spec=QuerySet)

        # Configure the mocks - use intersection instead of __and__
        mock_get_objects_for_user.side_effect = [result1, result2]
        result1.intersection.return_value = final_result

        # Create composite with AND operator
        composite = CompositePermDef([self.true_perm, self.path_perm], "and")

        # Test filtering
        result = composite.filter_queryset(queryset, self.user, self.context)

        # Verify behavior - check intersection was called instead of __and__
        self.assertEqual(result1.intersection.call_count, 1)
        self.assertEqual(result, final_result)

    @patch("guardian.shortcuts.get_objects_for_user")
    def test_composite_filter_with_condition_fail(self, mock_get_objects_for_user):
        # Create a test permission that will always return none() before calling get_objects_for_user
        # Using None as short_perm_codes ensures _pre_check_perms returns False immediately
        null_perm = PermDef(short_perm_codes=None)

        # Create composite with a failing permission
        composite = CompositePermDef([null_perm, self.path_perm], "and")

        queryset = MagicMock(spec=QuerySet)
        queryset.model = DummyObj
        none_qs = MagicMock(spec=QuerySet)
        queryset.none.return_value = none_qs

        # Test filtering
        result = composite.filter_queryset(queryset, self.user, self.context)

        # Should return empty queryset without calling get_objects_for_user
        # AND operations should short-circuit on the first failure
        mock_get_objects_for_user.assert_not_called()
        self.assertEqual(result, none_qs)

    @patch("guardian.shortcuts.get_objects_for_user")
    def test_composite_filter_with_obj_filter(self, mock_get_objects_for_user):
        # Set up test data
        queryset = MagicMock(spec=QuerySet)
        queryset.model = DummyObj

        # Create mock querysets with proper chaining
        filtered_by_status = MagicMock(spec=QuerySet)
        filtered_perms1 = MagicMock(spec=QuerySet)
        filtered_perms2 = MagicMock(spec=QuerySet)
        final_result = MagicMock(spec=QuerySet)

        # Configure mocks
        queryset.filter.return_value = filtered_by_status
        mock_get_objects_for_user.side_effect = [filtered_perms1, filtered_perms2]

        # Setup intersection chain - this is key for AND composites
        filtered_perms1.intersection.return_value = final_result

        # Create composite with obj_filter
        composite = CompositePermDef([self.filter_perm, self.true_perm], "and")

        # Test filtering
        result = composite.filter_queryset(queryset, self.user, self.context)

        # Verify the filter was applied
        queryset.filter.assert_called_with(status="public")
        mock_get_objects_for_user.assert_called()
        self.assertEqual(result, final_result)

    def test_empty_composite(self):
        # Test that an empty composite behaves correctly
        composite = CompositePermDef([], "or")
        queryset = MagicMock(spec=QuerySet)
        none_qs = MagicMock(spec=QuerySet)
        queryset.none.return_value = none_qs

        result = composite.filter_queryset(queryset, self.user, self.context)
        self.assertEqual(result, none_qs)


if __name__ == "__main__":
    unittest.main()
