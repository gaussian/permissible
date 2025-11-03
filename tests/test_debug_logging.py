"""
Test that debug logging is working correctly
"""

import logging
from io import StringIO
from django.contrib.auth import get_user_model
from django.db import models
from django.test import TestCase
from rest_framework.test import APIRequestFactory
from rest_framework.viewsets import ModelViewSet

from permissible.filters import PermissibleFilter
from permissible.permissions import PermissiblePerms
from permissible.perm_def import p, ALLOW_ALL
from permissible.models import PermissibleMixin


# Define a test model
class TestLoggingModel(PermissibleMixin, models.Model):
    name = models.CharField(max_length=100)

    class Meta:
        app_label = "permissible"

    @classmethod
    def get_policies(cls):
        return {
            "global": {
                "retrieve": ALLOW_ALL,
            },
            "object": {
                "retrieve": p(["view"]),
            },
        }


class TestLoggingViewSet(ModelViewSet):
    queryset = TestLoggingModel.objects.all()
    permission_classes = [PermissiblePerms]
    filter_backends = [PermissibleFilter]
    filterset_class = PermissibleFilter


class DebugLoggingTest(TestCase):
    """Test that debug logging works correctly"""

    def setUp(self):
        self.User = get_user_model()
        self.user = self.User.objects.create_user(username="testuser")
        self.factory = APIRequestFactory()

        # Create a test object
        self.obj = TestLoggingModel.objects.create(name="Test Object")

    def test_permission_denied_logs_debug_message(self):
        """Test that permission denied generates a debug log"""
        # Setup logging capture
        logger = logging.getLogger("permissible.permissions")
        log_stream = StringIO()
        handler = logging.StreamHandler(log_stream)
        handler.setLevel(logging.DEBUG)
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

        try:
            # Create a request that should fail permission check
            request = self.factory.get(f"/test/{self.obj.pk}/")
            request.user = self.user

            # Create view
            view = TestLoggingViewSet.as_view({"get": "retrieve"})
            view(request, pk=self.obj.pk)

            # Check that debug log was generated
            log_output = log_stream.getvalue()
            self.assertIn("Object permission denied", log_output)
            self.assertIn("testuser", log_output)
            self.assertIn("TestLoggingModel", log_output)
        finally:
            logger.removeHandler(handler)
            logger.setLevel(logging.WARNING)
