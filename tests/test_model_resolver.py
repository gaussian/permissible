"""
Tests for the LazyModelResolverMixin functionality.
"""

from unittest import mock

from django.db import models
from django.test import TestCase

from permissible.perm_def.model_resolver import LazyModelResolverMixin


# Mock models for testing
class Team(models.Model):
    name = models.CharField(max_length=100)

    class Meta:
        app_label = "test_app"


class Experiment(LazyModelResolverMixin, models.Model):
    name = models.CharField(max_length=100)
    team = models.ForeignKey(Team, on_delete=models.CASCADE)

    class Meta:
        app_label = "test_app"


class ChainerSession(LazyModelResolverMixin, models.Model):
    name = models.CharField(max_length=100)
    experiment = models.ForeignKey(Experiment, on_delete=models.CASCADE)

    class Meta:
        app_label = "test_app"


class Question(LazyModelResolverMixin, models.Model):
    text = models.CharField(max_length=200)
    chainer_session = models.ForeignKey(
        ChainerSession, on_delete=models.CASCADE, null=True
    )

    class Meta:
        app_label = "test_app"


class LazyModelResolverMixinTest(TestCase):
    """Tests for the LazyModelResolverMixin."""

    def setUp(self):
        """Set up test data."""
        # We don't actually need to create DB records for these tests
        # since we'll mock the database queries
        self.team = Team(id=1, name="Test Team")
        self.experiment = Experiment(id=10, name="Test Experiment", team_id=1)
        self.chainer_session = ChainerSession(
            id=100, name="Test Session", experiment_id=10
        )
        self.question = Question(id=1000, text="Test Question", chainer_session_id=100)
        self.question_no_session = Question(
            id=1001, text="Orphan Question", chainer_session_id=None
        )

    def test_get_unretrieved_class(self):
        """Test that get_unretrieved_class returns the correct model class."""
        # Single-level chain
        self.assertEqual(
            Question.get_unretrieved_class("chainer_session"), ChainerSession
        )

        # Multi-level chain
        self.assertEqual(
            Question.get_unretrieved_class("chainer_session.experiment"), Experiment
        )

        # Deep chain
        self.assertEqual(
            Question.get_unretrieved_class("chainer_session.experiment.team"), Team
        )

    def test_get_unretrieved_single_level(self):
        """Test get_unretrieved with a single-level chain."""
        # This should return an unretrieved ChainerSession with id=100
        # No DB query should be made
        unretrieved = self.question.get_unretrieved("chainer_session")

        self.assertIsInstance(unretrieved, ChainerSession)
        self.assertEqual(unretrieved.id, 100)

        # For a null foreign key, should return None
        self.assertIsNone(self.question_no_session.get_unretrieved("chainer_session"))

    @mock.patch("django.db.models.query.QuerySet.values_list")
    def test_get_unretrieved_multi_level(self, mock_values_list):
        """Test get_unretrieved with a multi-level chain."""
        # Mock the database query that would get the experiment_id
        mock_values_list.return_value = [10]  # The experiment_id

        # This should return an unretrieved Experiment with id=10
        unretrieved = self.question.get_unretrieved("chainer_session.experiment")

        self.assertIsInstance(unretrieved, Experiment)
        self.assertEqual(unretrieved.id, 10)

        # Check that the correct query was made
        mock_values_list.assert_called_once_with("experiment_id", flat=True)

    @mock.patch("django.db.models.query.QuerySet.values_list")
    def test_get_unretrieved_deep_chain(self, mock_values_list):
        """Test get_unretrieved with a deep chain."""
        # Mock the database query that would get the team_id
        mock_values_list.return_value = [1]  # The team_id

        # This should return an unretrieved Team with id=1
        unretrieved = self.question.get_unretrieved("chainer_session.experiment.team")

        self.assertIsInstance(unretrieved, Team)
        self.assertEqual(unretrieved.id, 1)

        # Check that the correct query was made
        mock_values_list.assert_called_once_with("experiment__team_id", flat=True)

    @mock.patch("django.db.models.query.QuerySet.values_list")
    def test_get_unretrieved_no_results(self, mock_values_list):
        """Test get_unretrieved when the query returns no results."""
        # Mock empty result set
        mock_values_list.return_value = []

        # This should return None
        unretrieved = self.question.get_unretrieved("chainer_session.experiment.team")

        self.assertIsNone(unretrieved)

    @mock.patch("django.db.models.query.QuerySet.values_list")
    def test_get_unretrieved_null_result(self, mock_values_list):
        """Test get_unretrieved when the query returns a null foreign key."""
        # Mock null foreign key
        mock_values_list.return_value = [None]

        # This should return None
        unretrieved = self.question.get_unretrieved("chainer_session.experiment.team")

        self.assertIsNone(unretrieved)

    @mock.patch("django.db.models.query.QuerySet.values_list")
    def test_get_unretrieved_multiple_results(self, mock_values_list):
        """Test get_unretrieved when the query unexpectedly returns multiple results."""
        # Mock multiple results (should never happen with proper foreign keys, but testing edge case)
        mock_values_list.return_value = [1, 2]

        # This should return None when there are multiple results
        unretrieved = self.question.get_unretrieved("chainer_session.experiment.team")

        self.assertIsNone(unretrieved)

    def test_get_unretrieved_invalid_attr(self):
        """Test get_unretrieved with an invalid attribute chain."""
        with self.assertRaises(AttributeError):
            self.question.get_unretrieved("nonexistent_field")
