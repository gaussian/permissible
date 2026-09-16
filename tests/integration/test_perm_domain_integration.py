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
from rest_framework import serializers
from rest_framework.test import APIRequestFactory, force_authenticate
from rest_framework.viewsets import ModelViewSet

from permissible.filters import PermissibleFilter
from permissible.models import (
    MEMBER_ROLE,
    PermDomain,
    PermDomainRole,
    PermDomainMember,
    PermissibleMixin,
    build_role_field,
)
from permissible.exceptions import RoleEscalationDenied, RoleLockoutDenied
from permissible.perm_def import p, IS_AUTHENTICATED
from permissible.permissions import PermissiblePerms
from permissible.policies import make_domain_member_policy
from permissible.views import PermDomainMemberViewSetMixin


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
        return {
            "global": {a: IS_AUTHENTICATED for a in ("retrieve", "destroy", "roles")},
            "object": make_domain_member_policy("team"),
        }


class TestTeamMemberSerializer(serializers.ModelSerializer):
    __test__ = False

    class Meta:
        model = TestTeamMember
        fields = ["id", "team", "user"]


class TestTeamMemberViewSet(PermDomainMemberViewSetMixin, ModelViewSet):
    __test__ = False
    queryset = TestTeamMember.objects.all()
    serializer_class = TestTeamMemberSerializer
    permission_classes = [PermissiblePerms]
    filter_backends = [PermissibleFilter]


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


# --- `set_roles_for_user` / `get_roles_for_user` / `role_labels` / `MEMBER_ROLE`


def test_member_role_constant():
    assert MEMBER_ROLE == "mem"
    assert TestTeamRole._meta.get_field("role").default == MEMBER_ROLE
    assert TestTeamRole.role_labels() == {
        "mem": "Member",
        "view": "Viewer",
        "con": "Contributor",
        "adm": "Admin",
        "own": "Owner",
    }


def test_get_roles_for_user(team, django_assert_num_queries):
    domain, users = team
    other_team = TestIntegrationTeamModel.objects.create(name="Other")
    other_team.assign_roles_to_user(users["owner"], ["view"])
    domain.assign_roles_to_user(users["owner"], ["con"])
    with django_assert_num_queries(1):
        assert set(domain.get_roles_for_user(users["owner"])) == {"own", "con"}
    assert set(domain.get_roles_for_user(users["other"])) == set()


@pytest.mark.parametrize(
    "target, roles, held",
    [
        ("owner", ["view"], {"view", "mem"}),  # replaced; "mem" is always kept
        ("owner", ["own", "view"], {"own", "view", "mem"}),  # unchanged role stays
        ("owner", [], {"mem"}),
        ("other", ["con"], {"con", "mem"}),  # a new member
    ],
)
def test_set_roles_for_user(team, target, roles, held):
    domain, users = team
    old = TestTeamMember.objects.filter(team=domain, user=users[target]).first()
    domain.set_roles_for_user(users[target], roles)
    assert set(domain.get_roles_for_user(users[target])) == held
    # Add-then-remove: the row keeps its id
    row = TestTeamMember.objects.get(team=domain, user=users[target])
    assert old is None or row.pk == old.pk


def test_set_roles_for_user_rejects_unknown_role(team):
    domain, users = team
    with pytest.raises(ValueError):
        domain.set_roles_for_user(users["owner"], ["view", "nope"])
    assert set(domain.get_roles_for_user(users["owner"])) == {"own"}


@pytest.mark.parametrize(
    "actor, target, roles, exc",
    [
        ("owner", "member", ["adm"], None),
        ("admin", "member", ["adm"], None),
        ("admin", "owner", ["view"], RoleEscalationDenied),  # may not revoke "own"
        ("super", "owner", ["view"], RoleLockoutDenied),  # last manager (admin gone)
    ],
)
def test_set_roles_for_user_by(team, actor, target, roles, exc):
    domain, users = team
    if exc is RoleLockoutDenied:
        domain.remove_roles_from_user(users["admin"], None)
    before = set(domain.get_roles_for_user(users[target]))
    with expect(exc is None, exc):
        domain.set_roles_for_user(users[target], roles, by=users[actor])
    # One transaction: a denied removal rolls back the additions
    after = set(domain.get_roles_for_user(users[target]))
    assert after == ({*roles, "mem"} if exc is None else before)


# --- `PermDomainMemberViewSetMixin`


def call(team, actor, target, data=None):
    """`PUT {target's row}/roles/` with `data`, or `DELETE` it when `data` is None."""
    domain, users = team
    method, name = ("delete", "destroy") if data is None else ("put", "roles")
    request = getattr(APIRequestFactory(), method)("/", data, format="json")
    force_authenticate(request, users[actor])
    row = TestTeamMember.objects.get(team=domain, user=users[target])
    return TestTeamMemberViewSet.as_view({method: name})(request, pk=row.pk), row


@pytest.mark.parametrize(
    "actor, target, roles, status",
    [
        ("admin", "member", ["con"], 200),
        ("admin", "member", ["con", "nope"], 400),
        ("admin", "member", "con", 400),  # not a list
        ("admin", "member", None, 400),  # missing
        ("member", "member", ["con"], 403),  # no change_permission: the policy
        ("admin", "owner", ["view"], 403),  # escalation
        ("owner", "owner", ["view"], 409),  # lockout: add another manager first
    ],
)
def test_roles_action(team, actor, target, roles, status):
    domain, users = team
    if status == 409:
        domain.remove_roles_from_user(users["admin"], ["adm"])
    response, row = call(team, actor, target, {} if roles is None else {"roles": roles})
    assert response.status_code == status, response.data
    if status == 200:
        assert response.data["id"] == row.id
        assert set(domain.get_roles_for_user(users[target])) == {*roles, "mem"}
    else:
        assert users[target] in domain.users.all()
    if status == 400:
        assert list(response.data) == ["roles"]


@pytest.mark.parametrize(
    "actor, target, status",
    [
        ("admin", "viewer", 204),  # an admin need not be able to revoke "own"
        ("admin", "owner", 403),  # escalation
        ("member", "member", 403),  # no change_permission: the policy
        ("owner", "owner", 409),
    ],
)
def test_destroy(team, actor, target, status):
    domain, users = team
    if status == 409:
        domain.remove_roles_from_user(users["admin"], ["adm"])
    response, row = call(team, actor, target)
    assert response.status_code == status, response.data
    assert TestTeamMember.objects.filter(pk=row.pk).exists() is (status != 204)
    assert (users[target] in domain.users.all()) is (status != 204)
