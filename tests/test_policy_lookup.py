import unittest
from unittest.mock import patch, MagicMock

from django.db import models

from permissible.models.policy_lookup import PolicyLooupMixin
from permissible.perm_def import p


# Mock ACTION_POLICIES for testing
MOCK_ACTION_POLICIES = {
    "testapp.PolicyModel": {
        "global": {
            "list": p(["view"]),
            "retrieve": p(["view"]),
        },
        "object": {
            "retrieve": p(["view"]),
            "update": p(["change"]),
        },
    },
    "testapp.PolicyRelated": {
        "global": {
            "list": p(["view"]),
        },
        "object": {
            "retrieve": p(["view"], obj_path="policy_model"),
        },
    },
}


# Create a test model that uses PolicyLooupMixin
class PolicyModel(PolicyLooupMixin, models.Model):
    name = models.CharField(max_length=100)

    class Meta:
        app_label = "testapp"
        managed = False


class PolicyRelated(PolicyLooupMixin, models.Model):
    name = models.CharField(max_length=100)
    policy_model = models.ForeignKey(PolicyModel, on_delete=models.CASCADE)

    class Meta:
        app_label = "testapp"
        managed = False


class TestPolicyLookup(unittest.TestCase):
    """Test cases for PolicyLooupMixin."""

    def setUp(self):
        """Set up test data."""
        self.test_model = PolicyModel(id=1)
        self.related_model = PolicyRelated(id=2, policy_model=self.test_model)
        # Clear the cache before each test
        if hasattr(PolicyModel.get_policies, "cache_clear"):
            PolicyModel.get_policies.cache_clear()
        if hasattr(PolicyRelated.get_policies, "cache_clear"):
            PolicyRelated.get_policies.cache_clear()

    @patch("importlib.import_module")
    def test_get_app_policies_module_primary_location(self, mock_import_module):
        """Test that get_app_policies_module finds policies in primary location."""
        # Create mock module with ACTION_POLICIES
        mock_module = MagicMock()
        mock_module.ACTION_POLICIES = MOCK_ACTION_POLICIES
        mock_import_module.return_value = mock_module

        # Test that the function returns the mock module
        result = PolicyModel.get_app_policies_module()

        # Verify import was attempted with correct path
        mock_import_module.assert_called_once_with("testapp.policies")
        self.assertEqual(result, mock_module)

    @patch("importlib.import_module")
    def test_get_app_policies_module_secondary_location(self, mock_import_module):
        """Test that get_app_policies_module finds policies in secondary location."""

        # Make first import raise ImportError, second succeed
        def side_effect(path):
            if path == "testapp.policies":
                raise ImportError("Module not found")
            return MagicMock()

        mock_import_module.side_effect = side_effect

        # Test that the function retries with secondary path
        PolicyModel.get_app_policies_module()

        # Verify both imports were attempted
        mock_import_module.assert_any_call("testapp.policies")
        mock_import_module.assert_any_call("testapp.models.policies")

    @patch("importlib.import_module")
    def test_get_app_policies_module_not_found(self, mock_import_module):
        """Test that get_app_policies_module returns None when policies not found."""
        # Make all imports raise ImportError
        mock_import_module.side_effect = ImportError("Module not found")

        # Test that the function returns None when module not found
        result = PolicyModel.get_app_policies_module()
        self.assertIsNone(result)

    @patch("permissible.models.policy_lookup.PolicyLooupMixin.get_app_policies_module")
    def test_get_policies_success(self, mock_get_app_policies_module):
        """Test that get_policies returns the correct policies."""
        # Create mock module with ACTION_POLICIES
        mock_module = MagicMock()
        mock_module.ACTION_POLICIES = MOCK_ACTION_POLICIES
        mock_get_app_policies_module.return_value = mock_module

        # Test that the function returns the correct policies for TestModel
        result = PolicyModel.get_policies()

        # Verify we get the correct policies
        self.assertEqual(result, MOCK_ACTION_POLICIES["testapp.PolicyModel"])

    @patch("permissible.models.policy_lookup.PolicyLooupMixin.get_app_policies_module")
    def test_get_policies_different_models(self, mock_get_app_policies_module):
        """Test that get_policies returns different policies for different models."""
        # Create mock module with ACTION_POLICIES
        mock_module = MagicMock()
        mock_module.ACTION_POLICIES = MOCK_ACTION_POLICIES
        mock_get_app_policies_module.return_value = mock_module

        # Get policies for both models
        test_model_policies = PolicyModel.get_policies()
        related_model_policies = PolicyRelated.get_policies()

        # Verify we get different policies for different models
        self.assertNotEqual(test_model_policies, related_model_policies)
        self.assertEqual(
            test_model_policies, MOCK_ACTION_POLICIES["testapp.PolicyModel"]
        )
        self.assertEqual(
            related_model_policies, MOCK_ACTION_POLICIES["testapp.PolicyRelated"]
        )

    @patch("permissible.models.policy_lookup.PolicyLooupMixin.get_app_policies_module")
    def test_get_policies_no_module(self, mock_get_app_policies_module):
        """Test that get_policies returns empty dict when module not found."""
        # Clear cache again to be extra sure
        PolicyModel.get_policies.cache_clear()

        # Make get_app_policies_module return None and ensure no side effects
        mock_get_app_policies_module.return_value = None
        mock_get_app_policies_module.side_effect = None

        # Test that the function returns an empty dict
        result = PolicyModel.get_policies()
        self.assertEqual(result, {})

        # Verify our mock was called
        mock_get_app_policies_module.assert_called_once()

    @patch("permissible.models.policy_lookup.PolicyLooupMixin.get_app_policies_module")
    def test_get_policies_no_action_policies(self, mock_get_app_policies_module):
        """Test that get_policies returns empty dict when ACTION_POLICIES not found."""
        # Create mock module without ACTION_POLICIES
        mock_module = MagicMock()
        mock_module.ACTION_POLICIES = None
        mock_get_app_policies_module.return_value = mock_module

        # Test that the function returns an empty dict
        result = PolicyModel.get_policies()
        self.assertEqual(result, {})

    @patch("permissible.models.policy_lookup.PolicyLooupMixin.get_app_policies_module")
    def test_get_policies_model_not_in_action_policies(
        self, mock_get_app_policies_module
    ):
        """Test that get_policies returns empty dict when model not in ACTION_POLICIES."""
        # Create mock module with ACTION_POLICIES that doesn't include our model
        mock_module = MagicMock()
        mock_module.ACTION_POLICIES = {"other.model": {}}
        mock_get_app_policies_module.return_value = mock_module

        # Test that the function returns an empty dict
        result = PolicyModel.get_policies()
        self.assertEqual(result, {})

    def test_caching(self):
        """Test that lru_cache is working for get_policies."""
        with patch(
            "permissible.models.policy_lookup.PolicyLooupMixin.get_app_policies_module"
        ) as mock_get_app:
            # Create mock module with ACTION_POLICIES
            mock_module = MagicMock()
            mock_module.ACTION_POLICIES = MOCK_ACTION_POLICIES
            mock_get_app.return_value = mock_module

            # Call get_policies multiple times
            PolicyModel.get_policies()
            PolicyModel.get_policies()
            PolicyModel.get_policies()

            # Verify get_app_policies_module was only called once (due to caching)
            mock_get_app.assert_called_once()


if __name__ == "__main__":
    unittest.main()
