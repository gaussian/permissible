"""
Integration tests for PermDomain with Django Guardian.
This tests RBAC functionality and automatic permission assignment.
"""

from contextlib import nullcontext

import pytest
from django.db import models
from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from guardian.shortcuts import get_perms

from permissible.models import (
    PermDomain,
    PermDomainRole,
    PermDomainMember,
    PermissibleMixin,
    build_role_field,
)
from permissible.exceptions import RoleEscalationDenied, RoleLockoutDenied
from permissible.perm_def import p
from permissible.policies import make_domain_member_policy


# Define domain models
class TestIntegrationTeamModel(PermDomain):
    """A concrete PermDomain for testing"""

    __test__ = False

    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)

    groups = models.ManyToManyField(
        Group, through="TestTeamRole", related_name="test_teams"
    )
    users = models.ManyToManyField(
        get_user_model(), through="TestTeamMember", related_name="test_teams"
    )

    class Meta:
        app_label = "tests"
        permissions = (
            ("view_on_testintegrationteammodel", "Can view content in test team"),
        )

    def __str__(self):
        return self.name


class TestTeamRole(PermDomainRole):
    """A concrete PermDomainRole for testing"""

    __test__ = False

    team = models.ForeignKey(
        TestIntegrationTeamModel, on_delete=models.CASCADE, related_name="team_roles"
    )

    # Custom role definitions
    ROLE_DEFINITIONS = {
        "mem": ("Member", ["view"]),
        "view": ("Viewer", ["view", "view_on"]),
        "con": (
            "Contributor",
            [
                "view",
                "view_on",
                "add_on",
                "change_on",
            ],
        ),
        "adm": (
            "Admin",
            [
                "view",
                "change",
                "view_on",
                "add_on",
                "change_on",
                "change_permission",
            ],
        ),
        "own": (
            "Owner",
            [
                "view",
                "change",
                "delete",
                "view_on",
                "add_on",
                "change_on",
                "change_permission",
            ],
        ),
    }

    # Required when overriding ROLE_DEFINITIONS
    role = build_role_field(ROLE_DEFINITIONS)

    class Meta:
        app_label = "tests"
        unique_together = ("team", "role")


class TestTeamMember(PermDomainMember):
    """A concrete PermDomainMember for testing"""

    __test__ = False

    team = models.ForeignKey(
        TestIntegrationTeamModel, on_delete=models.CASCADE, related_name="team_members"
    )

    class Meta:
        app_label = "tests"
        unique_together = ("team", "user")

    @classmethod
    def get_policies(cls):
        return {"object": make_domain_member_policy("team")}


# Test content model owned by a team
class TestContent(PermissibleMixin, models.Model):
    """Content model owned by a team to test domain-based permissions"""

    __test__ = False

    title = models.CharField(max_length=100)
    content = models.TextField()
    team = models.ForeignKey(
        TestIntegrationTeamModel, on_delete=models.CASCADE, related_name="contents"
    )

    class Meta:
        app_label = "tests"

    def __str__(self):
        return self.title

    @classmethod
    def get_policies(cls):
        """Define policies that use the team as domain"""
        return {
            "domains": ["team"],
            "global": {
                "create": p(["add"]),
                "retrieve": p(["view"]),
                "update": p(["change"]),
                "partial_update": p(["change"]),
                "destroy": p(["delete"]),
            },
            "object": {
                "retrieve": p(["view_on"], "team"),
                "update": p(["change_on"], "team"),
                "partial_update": p(["change_on"], "team"),
                "create": p(["add_on"], "team"),
                "destroy": p(["change_permission"], "team"),
            },
        }


@override_settings(
    AUTHENTICATION_BACKENDS=(
        "django.contrib.auth.backends.ModelBackend",
        "guardian.backends.ObjectPermissionBackend",
    )
)
class PermDomainIntegrationTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        # Create users
        User = get_user_model()
        cls.admin_user = User.objects.create_superuser(
            username="admin", password="admin"
        )
        cls.team_owner = User.objects.create_user(username="owner", password="owner")
        cls.team_admin = User.objects.create_user(
            username="admin_user", password="admin"
        )
        cls.team_contributor = User.objects.create_user(
            username="contributor", password="contributor"
        )
        cls.team_viewer = User.objects.create_user(username="viewer", password="viewer")
        cls.team_member = User.objects.create_user(username="member", password="member")
        cls.non_member = User.objects.create_user(
            username="non_member", password="non_member"
        )

        # Create teams
        cls.team1 = TestIntegrationTeamModel.objects.create(
            name="Team 1", description="First test team"
        )
        cls.team2 = TestIntegrationTeamModel.objects.create(
            name="Team 2", description="Second test team"
        )

        # Add users to teams with different roles
        # For Team 1
        cls.team1.assign_roles_to_user(cls.team_owner, roles=["own"])
        cls.team1.assign_roles_to_user(cls.team_admin, roles=["adm"])
        cls.team1.assign_roles_to_user(cls.team_contributor, roles=["con"])
        cls.team1.assign_roles_to_user(cls.team_viewer, roles=["view"])
        cls.team1.assign_roles_to_user(cls.team_member, roles=["mem"])

        # For Team 2 - making contributor an admin here
        cls.team2.assign_roles_to_user(cls.team_owner, roles=["own"])
        cls.team2.assign_roles_to_user(cls.team_contributor, roles=["adm"])

        # Create test content in teams
        cls.content1 = TestContent.objects.create(
            title="Content 1", content="Content for team 1", team=cls.team1
        )
        cls.content2 = TestContent.objects.create(
            title="Content 2", content="Content for team 2", team=cls.team2
        )

    def test_role_group_creation(self):
        """Test that groups are created for each role"""
        # Check that proper number of roles exists for team1
        role_count = TestTeamRole.objects.filter(team=self.team1).count()
        self.assertEqual(role_count, 5)  # mem, view, con, adm, own

        # Verify groups were created
        for role_choice, _ in TestTeamRole._meta.get_field("role").choices:
            role = TestTeamRole.objects.get(team=self.team1, role=role_choice)
            self.assertIsNotNone(role.group)
            self.assertTrue(Group.objects.filter(id=role.group_id).exists())

    def test_team_permissions(self):
        """Test that permissions are correctly assigned for team roles"""
        # Check owner permissions on team
        owner_perms = get_perms(self.team_owner, self.team1)
        self.assertIn("view_testintegrationteammodel", owner_perms)
        self.assertIn("change_testintegrationteammodel", owner_perms)
        self.assertIn("delete_testintegrationteammodel", owner_perms)

        # Check admin permissions on team
        admin_perms = get_perms(self.team_admin, self.team1)
        self.assertIn("view_testintegrationteammodel", admin_perms)
        self.assertIn("change_testintegrationteammodel", admin_perms)
        self.assertNotIn("delete_testintegrationteammodel", admin_perms)

        # Check member permissions on team
        member_perms = get_perms(self.team_member, self.team1)
        self.assertIn("view_testintegrationteammodel", member_perms)
        self.assertNotIn("change_testintegrationteammodel", member_perms)
        self.assertNotIn("view_on_testintegrationteammodel", member_perms)

    def test_content_object_permissions(self):
        """Test object permissions on content via team roles"""
        # Test owner permissions on content
        self.assertTrue(
            self.content1.has_object_permission(self.team_owner, "retrieve")
        )
        self.assertTrue(self.content1.has_object_permission(self.team_owner, "update"))
        self.assertTrue(self.content1.has_object_permission(self.team_owner, "destroy"))

        # Test admin permissions on content
        self.assertTrue(
            self.content1.has_object_permission(self.team_admin, "retrieve")
        )
        self.assertTrue(self.content1.has_object_permission(self.team_admin, "update"))
        self.assertTrue(self.content1.has_object_permission(self.team_admin, "destroy"))

        # Test contributor permissions on content
        self.assertTrue(
            self.content1.has_object_permission(self.team_contributor, "retrieve")
        )
        self.assertTrue(
            self.content1.has_object_permission(self.team_contributor, "update")
        )
        self.assertFalse(
            self.content1.has_object_permission(self.team_contributor, "destroy")
        )

        # Test viewer permissions on content
        self.assertTrue(
            self.content1.has_object_permission(self.team_viewer, "retrieve")
        )
        self.assertFalse(
            self.content1.has_object_permission(self.team_viewer, "update")
        )
        self.assertFalse(
            self.content1.has_object_permission(self.team_viewer, "destroy")
        )

        # Test member permissions on content (no access)
        self.assertFalse(
            self.content1.has_object_permission(self.team_member, "retrieve")
        )
        self.assertFalse(
            self.content1.has_object_permission(self.team_member, "update")
        )

        # Test non-member permissions on content


# --- Role-change guards: `assign_roles_to_user(by=)` / `remove_roles_from_user(by=)`


ROLES = {"owner": "own", "admin": "adm", "viewer": "view", "member": "mem"}


@pytest.fixture
def team(db):
    """A team with one user per role, plus `other` (no role) and `super`."""
    User = get_user_model()
    team = TestIntegrationTeamModel.objects.create(name="Team")
    users = {n: User.objects.create_user(username=n) for n in [*ROLES, "other"]}
    users["super"] = User.objects.create_superuser(username="super")
    for name, role in ROLES.items():
        team.assign_roles_to_user(users[name], [role])
    return team, users


def expect(allowed, exc):
    return nullcontext() if allowed else pytest.raises(exc)


@pytest.mark.parametrize(
    "actor, action, allowed",
    [
        ("admin", "destroy", True),
        ("admin", "roles", True),
        ("admin", "retrieve", False),  # self-only
        ("member", "destroy", False),
        ("member", "roles", False),
        ("member", "retrieve", True),
    ],
)
def test_member_policy(team, actor, action, allowed):
    domain, users = team
    row = TestTeamMember.objects.get(team=domain, user=users["member"])
    context = {"request": {"user": users[actor]}}
    assert row.has_object_permission(users[actor], action, context) is allowed


@pytest.mark.parametrize(
    "actor, role, allowed",
    [
        ("admin", "own", False),  # "own" carries "delete"; "adm" does not
        ("admin", "adm", True),
        ("admin", "con", True),
        ("owner", "own", True),
        ("viewer", "con", False),  # "con" carries "add_on"
        ("member", "mem", True),  # "mem" carries only "view", which member holds
        ("member", "view", False),  # "view" carries "view_on"
        ("super", "own", True),
    ],
)
def test_no_escalation(team, actor, role, allowed):
    domain, users = team
    by, target = users[actor], users["other"]
    with expect(allowed, RoleEscalationDenied):
        domain.assign_roles_to_user(target, [role], by=by)
    assert (target in domain.users.all()) is allowed
    with expect(allowed, RoleEscalationDenied):
        domain.remove_roles_from_user(target, [role], by=by)
    assert target not in domain.users.all()


def test_unknown_role_code_is_rejected(team):
    domain, users = team
    with pytest.raises(ValueError):
        domain.assign_roles_to_user(users["other"], ["nope"], by=users["owner"])


@pytest.mark.parametrize(
    "admin_state, owner_roles, target, roles, locked",
    [
        ("manager", ["own"], "owner", ["own"], False),  # a second manager remains
        ("gone", ["own"], "owner", ["own"], True),  # last manager
        ("gone", ["own"], "owner", None, True),  # None: every role
        ("inactive", ["own"], "owner", ["own"], True),  # inactive does not count
        ("gone", ["own", "adm"], "owner", ["adm"], False),  # a manager role stays
        ("gone", ["own"], "viewer", ["view"], False),  # target is not a manager
        ("gone", [], "viewer", ["view"], False),  # no manager before: 0 -> 0
    ],
)
def test_no_lockout(team, admin_state, owner_roles, target, roles, locked):
    domain, users = team
    if admin_state == "gone":
        domain.remove_roles_from_user(users["admin"], None)
    elif admin_state == "inactive":
        users["admin"].is_active = False
        users["admin"].save()
    domain.remove_roles_from_user(users["owner"], None)
    domain.assign_roles_to_user(users["owner"], owner_roles)
    # A superuser as `by` passes Rule A, and Rule B has no superuser bypass
    with expect(not locked, RoleLockoutDenied):
        domain.remove_roles_from_user(users[target], roles, by=users["super"])
    removed = set(domain.get_group_ids_for_roles(roles))
    held = set(users[target].groups.values_list("id", flat=True))
    assert bool(removed & held) is locked
