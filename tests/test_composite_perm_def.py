import unittest
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


class DummyObj(ShortPermsMixin):
    _meta = type("Meta", (), {"app_label": "testapp", "model_name": "dummy"})

    def __init__(self, pk, allowed=True):
        self.pk = pk
        self.allowed = allowed

    # Example method for string-based condition checking
    def can_do(self, user, context):
        return True


class TestCompositePermDef(unittest.TestCase):
    """Test cases for the CompositePermDef class and operator overloading."""

    def setUp(self):
        """Set up test fixtures."""
        self.dummy_obj = DummyObj(pk=123)
        self.user = DummyUser(id=1)

        # Create basic permission definitions for testing
        self.true_perm = PermDef(["view"], condition_checker=lambda o, u, c: True)
        self.false_perm = PermDef(["view"], condition_checker=lambda o, u, c: False)

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


if __name__ == "__main__":
    unittest.main()
