"""
Tests for the utility functions in permissible/utils.py
"""

import unittest
from unittest import mock

from django.http import QueryDict
from rest_framework.request import Request

from permissible.utils.views import make_context_from_request


class TestMakeContextFromRequest(unittest.TestCase):
    """Test suite for the make_context_from_request function."""

    def setUp(self):
        """Set up test fixtures."""
        # Create mock user
        self.user = mock.MagicMock()
        self.user.id = 1
        self.user.username = "testuser"

    def create_mock_request(self, data=None, query_params=None, user=None):
        """Helper to create a mock request with data and/or query_params."""
        request = mock.MagicMock(spec=Request)
        request.user = user if user is not None else self.user
        request.data = data
        request.query_params = query_params
        return request

    def test_none_request(self):
        """Test that function returns None when request is None."""
        self.assertIsNone(make_context_from_request(None))

    def test_empty_request(self):
        """Test that function returns minimal context with empty request."""
        empty_request = self.create_mock_request()

        context = make_context_from_request(empty_request)

        self.assertIsNotNone(context)
        self.assertEqual(context["request"], empty_request)
        self.assertEqual(context["user"], self.user)

    def test_request_with_dict_data(self):
        """Test that function correctly handles dict data."""
        data = {
            "name": "Test Project",
            "description": "A test project",
            "is_active": True,
        }
        request = self.create_mock_request(data=data)

        context = make_context_from_request(request)

        self.assertIsNotNone(context)
        self.assertEqual(context["name"], "Test Project")
        self.assertEqual(context["description"], "A test project")
        self.assertTrue(context["is_active"])
        self.assertEqual(context["request"], request)
        self.assertEqual(context["user"], self.user)

    def test_request_with_query_dict_data(self):
        """Test that function correctly handles QueryDict data."""
        query_dict = QueryDict(
            "name=Test+Project&description=A+test+project&is_active=true", mutable=True
        )
        request = self.create_mock_request(data=query_dict)

        context = make_context_from_request(request)

        self.assertIsNotNone(context)
        self.assertEqual(context["name"], "Test Project")
        self.assertEqual(context["description"], "A test project")
        self.assertEqual(context["is_active"], "true")  # QueryDict stores as string
        self.assertEqual(context["request"], request)

    def test_request_with_list_data(self):
        """Test that function correctly handles list data."""
        data = [{"id": 1, "name": "Item 1"}, {"id": 2, "name": "Item 2"}]
        request = self.create_mock_request(data=data)

        context = make_context_from_request(request)

        self.assertIsNotNone(context)
        self.assertEqual(context["data"], data)
        self.assertEqual(context["request"], request)

    def test_request_with_query_params(self):
        """Test that function correctly handles query parameters."""
        query_params = QueryDict("page=2&page_size=10&sort=name")
        request = self.create_mock_request(query_params=query_params)

        context = make_context_from_request(request)

        self.assertIsNotNone(context)
        self.assertEqual(context["page"], "2")
        self.assertEqual(context["page_size"], "10")
        self.assertEqual(context["sort"], "name")
        self.assertEqual(context["request"], request)

    def test_both_data_and_query_params(self):
        """Test that function correctly merges data and query params with data taking precedence."""
        data = {"name": "Test Project", "shared": True}
        query_params = QueryDict(
            "page=2&name=Old+Name"
        )  # 'name' should be overridden by data
        request = self.create_mock_request(data=data, query_params=query_params)

        context = make_context_from_request(request)

        self.assertIsNotNone(context)
        # Data should override query params
        self.assertEqual(context["name"], "Test Project")
        self.assertTrue(context["shared"])
        # Query params not in data should be included
        self.assertEqual(context["page"], "2")
        self.assertEqual(context["request"], request)

    def test_request_without_user(self):
        """Test that function handles requests without a user attribute."""
        # Create a more basic mock without automatically adding all attributes
        request = mock.Mock()
        # Only set the data attribute
        request.data = {"name": "Test Project"}
        request.query_params = {}

        # Delete the user attribute if it was automatically added
        if hasattr(request, "user"):
            delattr(request, "user")

        context = make_context_from_request(request)

        self.assertIsNotNone(context)
        self.assertEqual(context["name"], "Test Project")
        self.assertEqual(context["request"], request)
        # User key should not be in context
        self.assertNotIn("user", context)

    def test_complex_nested_data(self):
        """Test that function correctly handles complex nested data structures."""
        data = {
            "project": {
                "name": "Test Project",
                "owner": {"id": 1, "name": "Test User"},
                "tags": ["test", "project", "api"],
            },
            "settings": {"public": True, "notifications": False},
        }
        request = self.create_mock_request(data=data)

        context = make_context_from_request(request)

        self.assertIsNotNone(context)
        self.assertEqual(context["project"]["name"], "Test Project")
        self.assertEqual(context["project"]["owner"]["id"], 1)
        self.assertEqual(context["project"]["tags"], ["test", "project", "api"])
        self.assertTrue(context["settings"]["public"])
        self.assertFalse(context["settings"]["notifications"])


if __name__ == "__main__":
    unittest.main()
