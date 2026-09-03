import contextlib
import signal
import unittest
from unittest.mock import patch

from asgiref.sync import async_to_sync
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.db import connection, models
from django.test import TestCase
from django.test.utils import CaptureQueriesContext

from permissible.models.role_based.hierarchical import HierarchicalPermDomain
from permissible.models.role_based.core import PermDomainRole, PermDomainMember


@contextlib.contextmanager
def time_limit(seconds=5):
    """
    Stop the test with a TimeoutError instead of hanging the suite.

    A cycle regression makes the walks loop forever. Every cycle test runs
    inside this guard, so a regression fails the run rather than freezing it.
    """
    if not hasattr(signal, "SIGALRM"):
        yield
        return

    def handler(signum, frame):
        raise TimeoutError(f"call did not finish within {seconds}s")

    old_handler = signal.signal(signal.SIGALRM, handler)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)


# Define a dummy concrete model for HierarchicalPermDomain
class DummyHierarchicalDomain(HierarchicalPermDomain):
    name = models.CharField(max_length=100)
    groups = models.ManyToManyField(
        Group,
        through="DummyHierarchicalDomainRole",
        related_name="dummy_hierarchical_domains",
        blank=True,
    )
    users = models.ManyToManyField(
        get_user_model(),
        through="DummyHierarchicalDomainMember",
        related_name="dummy_hierarchical_domains",
        blank=True,
    )

    def __str__(self):
        return self.name

    class Meta:
        app_label = "tests"  # Ensure proper app_label for testing


# Define a dummy domain role model that links DummyHierarchicalDomain to roles
class DummyHierarchicalDomainRole(PermDomainRole):
    domain = models.ForeignKey(
        DummyHierarchicalDomain, on_delete=models.CASCADE, related_name="domain_roles"
    )

    # Use the standard role definitions from PermDomainRole
    ROLE_DEFINITIONS = {
        "mem": ("Member", []),
        "view": ("Viewer", ["view"]),
        "adm": ("Admin", ["view", "change", "delete"]),
    }

    # Define role field using the build_role_field utility from PermDomainRole
    role = models.CharField(
        choices=[(k, v[0]) for k, v in ROLE_DEFINITIONS.items()],
        max_length=4,
        default="mem",
    )

    class Meta:
        app_label = "tests"
        # Group and domain together must be unique
        unique_together = ("group", "domain")


class DummyHierarchicalDomainMember(PermDomainMember):
    """
    A concrete PermDomainMember. It joins HierarchicalPermDomain to a User.
    """

    dummydomain = models.ForeignKey(
        DummyHierarchicalDomain,
        on_delete=models.CASCADE,
        related_name="dummydomain_members",
    )

    class Meta:
        app_label = "tests"


class ActiveDomainManager(models.Manager):
    """A soft-delete style default manager: it hides rows marked deleted."""

    def get_queryset(self):
        return super().get_queryset().filter(is_deleted=False)


class DummySoftDeleteDomain(HierarchicalPermDomain):
    """
    A hierarchical domain whose DEFAULT manager hides soft-deleted rows.
    Used to pin what the ancestor walk does with a hidden ancestor.
    """

    name = models.CharField(max_length=100)
    is_deleted = models.BooleanField(default=False)

    # `objects` is declared first, so it is the `_default_manager`.
    objects = ActiveDomainManager()
    all_objects = models.Manager()

    groups = models.ManyToManyField(
        Group,
        through="DummySoftDeleteDomainRole",
        related_name="dummy_soft_delete_domains",
        blank=True,
    )
    users = models.ManyToManyField(
        get_user_model(),
        through="DummySoftDeleteDomainMember",
        related_name="dummy_soft_delete_domains",
        blank=True,
    )

    def __str__(self):
        return self.name

    class Meta:
        app_label = "tests"


class DummySoftDeleteDomainRole(PermDomainRole):
    domain = models.ForeignKey(
        DummySoftDeleteDomain, on_delete=models.CASCADE, related_name="domain_roles"
    )

    ROLE_DEFINITIONS = {
        "mem": ("Member", []),
        "view": ("Viewer", ["view"]),
        "adm": ("Admin", ["view", "change", "delete"]),
    }

    role = models.CharField(
        choices=[(k, v[0]) for k, v in ROLE_DEFINITIONS.items()],
        max_length=4,
        default="mem",
    )

    class Meta:
        app_label = "tests"
        unique_together = ("group", "domain")


class DummySoftDeleteDomainMember(PermDomainMember):
    dummydomain = models.ForeignKey(
        DummySoftDeleteDomain,
        on_delete=models.CASCADE,
        related_name="dummydomain_members",
    )

    class Meta:
        app_label = "tests"


def make_chain(length, model=DummyHierarchicalDomain):
    """Create a straight parent chain of `length` nodes, root first."""
    nodes = []
    parent = None
    for level in range(1, length + 1):
        parent = model.objects.create(name=f"Level{level}", parent=parent)
        nodes.append(parent)
    return nodes


class HierarchicalPermDomainTests(TestCase):
    def setUp(self):
        # Create a simple hierarchy:
        #         Root
        #           |
        #        Child1
        #          /  \
        #    Child2   Child3
        self.domain = DummyHierarchicalDomain.objects.create(name="Root")
        self.child1 = DummyHierarchicalDomain.objects.create(
            name="Child1", parent=self.domain
        )
        self.child2 = DummyHierarchicalDomain.objects.create(
            name="Child2", parent=self.child1
        )
        self.child3 = DummyHierarchicalDomain.objects.create(
            name="Child3", parent=self.child1
        )

    def test_get_permission_targets(self):
        """
        Test that get_permission_targets returns self and all descendants recursively.
        """
        targets = list(self.domain.get_permission_targets())
        target_names = {t.name for t in targets}
        expected_names = {"Root", "Child1", "Child2", "Child3"}
        self.assertEqual(target_names, expected_names)

    def test_get_permission_targets_child(self):
        """
        Test that get_permission_targets on an intermediate node returns self and its descendants.
        """
        targets = list(self.child1.get_permission_targets())
        target_names = {t.name for t in targets}
        expected_names = {"Child1", "Child2", "Child3"}
        self.assertEqual(target_names, expected_names)

    def test_get_ancestor_ids_from_id(self):
        """
        Test that get_ancestor_ids_from_id returns the ancestor IDs, nearest first.
        """
        # For child2, ancestors are child1 then domain, nearest first.
        ancestor_ids = DummyHierarchicalDomain.get_ancestor_ids_from_id(self.child1.pk)
        self.assertIn(self.child1.pk, ancestor_ids)
        # For child2, get ancestors via parent chain.
        ancestor_ids_child2 = DummyHierarchicalDomain.get_ancestor_ids_from_id(
            self.child2.parent.pk
        )
        expected = [self.child1.pk, self.domain.pk]
        self.assertEqual(ancestor_ids_child2, expected)

    def test_get_ancestor_ids_from_none(self):
        """
        Test that get_ancestor_ids_from_id returns an empty list for a None parent_id.
        """
        ancestor_ids = DummyHierarchicalDomain.get_ancestor_ids_from_id(None)
        self.assertEqual(ancestor_ids, [])

    @patch.object(DummyHierarchicalDomain, "reset_domain_roles")
    def test_save_parent_changed_calls_reset_on_ancestors(self, mock_reset):
        """
        Test that when a HierarchicalPermDomain instance has its parent changed,
        reset_domain_roles is called on ancestors that differ.
        """
        # Initially, child1.parent is domain.
        # Change child1's parent to None.
        self.child1.parent = None
        self.child1.save()

        # The reset_domain_roles on affected ancestors should have been called.
        # We expect at least one call: on the old ancestor (domain) or on child1 itself.
        self.assertTrue(mock_reset.called)

    def test_save_no_parent_change_does_not_call_reset(self):
        """
        Test that saving an instance without changing its parent does not trigger ancestor resets.
        """
        # Save child1 without changing the parent.
        with patch.object(DummyHierarchicalDomain, "reset_domain_roles") as mock_reset:
            self.child1.name = "Child1 Updated"
            self.child1.save()
            mock_reset.assert_not_called()


class AncestorWalkTests(TestCase):
    """Ordered, cycle-safe, capped ancestor traversal."""

    def test_get_ancestor_ids_nearest_first_depth_2(self):
        nodes = make_chain(2)
        self.assertEqual(nodes[1].get_ancestor_ids(), [nodes[0].pk])

    def test_get_ancestor_ids_nearest_first_depth_5(self):
        nodes = make_chain(5)
        expected = [n.pk for n in reversed(nodes[:-1])]
        self.assertEqual(nodes[-1].get_ancestor_ids(), expected)

    def test_get_ancestor_ids_nearest_first_at_max_depth(self):
        depth = DummyHierarchicalDomain.MAX_HIERARCHY_DEPTH
        nodes = make_chain(depth)
        expected = [n.pk for n in reversed(nodes[:-1])]
        self.assertEqual(len(expected), depth - 1)
        self.assertEqual(nodes[-1].get_ancestor_ids(), expected)

    def test_get_ancestor_ids_root_has_none(self):
        nodes = make_chain(2)
        self.assertEqual(nodes[0].get_ancestor_ids(), [])

    def test_get_ancestor_ids_stops_at_max_levels(self):
        """The cap truncates the result instead of walking the whole chain."""
        nodes = make_chain(5)
        self.assertEqual(
            nodes[-1].get_ancestor_ids(max_levels=2),
            [nodes[3].pk, nodes[2].pk],
        )

    def test_get_ancestor_ids_costs_one_query_per_level_and_no_rows(self):
        nodes = make_chain(5)
        deepest = nodes[-1]
        with CaptureQueriesContext(connection) as captured:
            ancestor_ids = deepest.get_ancestor_ids()

        self.assertEqual(len(ancestor_ids), 4)
        # One query per level walked.
        self.assertEqual(len(captured.captured_queries), 4)
        # Each query reads the parent_id column only - no model rows built.
        for query in captured.captured_queries:
            self.assertIn("parent_id", query["sql"])
            self.assertNotIn("name", query["sql"])

    def test_aget_ancestor_ids_nearest_first(self):
        nodes = make_chain(5)
        expected = [n.pk for n in reversed(nodes[:-1])]
        self.assertEqual(async_to_sync(nodes[-1].aget_ancestor_ids)(), expected)


class HierarchyCycleTests(TestCase):
    """
    A cycle forged behind save()'s back must never hang or recurse.

    `objects.filter(...).update(...)` bypasses save(), which is exactly how a
    cycle reaches the database in real life (data migration, fixture, raw SQL).
    """

    def setUp(self):
        self.node_a = DummyHierarchicalDomain.objects.create(name="A")
        self.node_b = DummyHierarchicalDomain.objects.create(
            name="B", parent=self.node_a
        )
        # Forge A -> B -> A, bypassing save().
        DummyHierarchicalDomain.objects.filter(pk=self.node_a.pk).update(
            parent_id=self.node_b.pk
        )
        self.node_a.refresh_from_db()
        self.node_b.refresh_from_db()

    def test_get_ancestor_ids_terminates_on_cycle(self):
        with time_limit(), CaptureQueriesContext(connection) as captured:
            ancestor_ids = self.node_b.get_ancestor_ids()

        self.assertEqual(ancestor_ids, [self.node_a.pk])
        self.assertLessEqual(len(captured.captured_queries), 2)

    def test_aget_ancestor_ids_terminates_on_cycle(self):
        """
        The async walk is a separate loop. A missing stop condition there hangs
        an ASGI worker, so it gets its own test.
        """
        with time_limit(), CaptureQueriesContext(connection) as captured:
            ancestor_ids = async_to_sync(self.node_b.aget_ancestor_ids)()

        self.assertEqual(ancestor_ids, [self.node_a.pk])
        self.assertLessEqual(len(captured.captured_queries), 2)

    def test_get_ancestor_ids_from_id_terminates_on_cycle(self):
        with time_limit(), CaptureQueriesContext(connection) as captured:
            ancestor_ids = DummyHierarchicalDomain.get_ancestor_ids_from_id(
                self.node_a.pk
            )

        self.assertEqual(ancestor_ids, [self.node_a.pk, self.node_b.pk])
        self.assertLessEqual(len(captured.captured_queries), 3)

    def test_get_descendant_depth_terminates_on_cycle(self):
        with time_limit(), CaptureQueriesContext(connection) as captured:
            depth = self.node_a.get_descendant_depth()

        self.assertEqual(depth, 1)
        self.assertLessEqual(
            len(captured.captured_queries), DummyHierarchicalDomain.MAX_HIERARCHY_DEPTH
        )

    def test_get_permission_targets_yields_each_node_once_on_cycle(self):
        with time_limit(), CaptureQueriesContext(connection) as captured:
            target_pks = [t.pk for t in self.node_a.get_permission_targets()]

        self.assertEqual(target_pks, [self.node_a.pk, self.node_b.pk])
        self.assertEqual(len(target_pks), len(set(target_pks)))
        self.assertLessEqual(len(captured.captured_queries), 3)

    def test_save_terminates_on_cycle(self):
        """
        save() used to inherit the hang from get_ancestor_ids_from_id.

        Attaching a new node under a chain that already contains a cycle must
        finish. The cycle is upstream and is logged, not blamed on this write.
        """
        node_c = DummyHierarchicalDomain.objects.create(name="C")
        node_c.parent = self.node_b
        with time_limit():
            node_c.save()

        node_c.refresh_from_db()
        self.assertEqual(node_c.parent_id, self.node_b.pk)


class HierarchyValidationTests(TestCase):
    """Cycle and depth rules, enforced on save() as well as clean()."""

    def test_chain_of_exactly_max_depth_saves(self):
        depth = DummyHierarchicalDomain.MAX_HIERARCHY_DEPTH
        nodes = make_chain(depth)
        self.assertEqual(len(nodes), depth)

    def test_one_level_past_max_depth_raises(self):
        depth = DummyHierarchicalDomain.MAX_HIERARCHY_DEPTH
        nodes = make_chain(depth)
        with self.assertRaises(ValidationError) as ctx:
            DummyHierarchicalDomain.objects.create(name="TooDeep", parent=nodes[-1])
        self.assertIn("parent", ctx.exception.message_dict)

    def test_reparenting_a_subtree_counts_its_own_depth(self):
        """
        Moving a two-level subtree under a chain of MAX_HIERARCHY_DEPTH - 1
        would make the tree one level too deep. Counting only the ancestors
        misses this.
        """
        depth = DummyHierarchicalDomain.MAX_HIERARCHY_DEPTH
        chain = make_chain(depth - 1)

        subtree_root = DummyHierarchicalDomain.objects.create(name="SubtreeRoot")
        DummyHierarchicalDomain.objects.create(name="SubtreeLeaf", parent=subtree_root)
        self.assertEqual(subtree_root.get_descendant_depth(), 1)

        subtree_root.parent = chain[-1]
        with self.assertRaises(ValidationError) as ctx:
            subtree_root.save()
        self.assertIn("parent", ctx.exception.message_dict)

    def test_self_parent_raises_validation_error(self):
        node = DummyHierarchicalDomain.objects.create(name="Solo")
        node.parent_id = node.pk
        with self.assertRaises(ValidationError) as ctx:
            node.save()
        self.assertIn("parent", ctx.exception.message_dict)

    def test_cycle_parent_raises_validation_error(self):
        root = DummyHierarchicalDomain.objects.create(name="Root")
        child = DummyHierarchicalDomain.objects.create(name="Child", parent=root)
        root.parent = child
        with self.assertRaises(ValidationError) as ctx:
            root.save()
        self.assertIn("parent", ctx.exception.message_dict)

    def test_clean_enforces_the_same_rules(self):
        depth = DummyHierarchicalDomain.MAX_HIERARCHY_DEPTH
        nodes = make_chain(depth)
        too_deep = DummyHierarchicalDomain(name="TooDeep", parent=nodes[-1])
        with self.assertRaises(ValidationError):
            too_deep.clean()

    def test_partial_save_runs_no_hierarchy_queries(self):
        """A save that cannot change `parent` must not pay for the walks."""
        nodes = make_chain(3)
        leaf = nodes[-1]
        leaf.name = "Renamed"

        with CaptureQueriesContext(connection) as captured:
            leaf.save(update_fields=["name"])

        # Exactly one query: the UPDATE. No ancestor walk, no descendant walk,
        # and no lookup of the previous parent_id.
        self.assertEqual(len(captured.captured_queries), 1)
        self.assertIn("UPDATE", captured.captured_queries[0]["sql"].upper())


class DescendantDepthTests(TestCase):
    def test_leaf_has_zero_depth(self):
        nodes = make_chain(3)
        self.assertEqual(nodes[-1].get_descendant_depth(), 0)

    def test_depth_counts_levels_below(self):
        nodes = make_chain(4)
        self.assertEqual(nodes[0].get_descendant_depth(), 3)
        self.assertEqual(nodes[1].get_descendant_depth(), 2)

    def test_unsaved_object_has_zero_depth(self):
        self.assertEqual(DummyHierarchicalDomain(name="New").get_descendant_depth(), 0)


class SoftDeleteDefaultManagerTests(TestCase):
    """
    The walk reads through `_default_manager`. A default manager that hides a
    row therefore ENDS the chain at that row: nothing above it is returned.
    """

    def test_hidden_ancestor_ends_the_chain(self):
        grandparent = DummySoftDeleteDomain.objects.create(name="Grandparent")
        parent = DummySoftDeleteDomain.objects.create(name="Parent", parent=grandparent)
        child = DummySoftDeleteDomain.objects.create(name="Child", parent=parent)

        # Sanity check: the whole chain is visible while nothing is deleted.
        self.assertEqual(child.get_ancestor_ids(), [parent.pk, grandparent.pk])

        # Hide the middle node from the default manager.
        DummySoftDeleteDomain.all_objects.filter(pk=parent.pk).update(is_deleted=True)

        # The hidden node is still named by child.parent_id, but the walk
        # cannot read through it, so the grandparent is not returned.
        self.assertEqual(child.get_ancestor_ids(), [parent.pk])
        self.assertEqual(
            DummySoftDeleteDomain.get_ancestor_ids_from_id(child.parent_id),
            [parent.pk],
        )


if __name__ == "__main__":
    unittest.main()
