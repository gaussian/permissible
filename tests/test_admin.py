"""
Tests for the admin mixins in `permissible.admin`.

Models here are registered under the `tests` app (see INSTALLED_APPS), so they
don't need to share the `permissible` app registry with other test modules.
"""

from unittest.mock import patch

from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import Group
from django.core.exceptions import ImproperlyConfigured
from django.db import models
from django.test import RequestFactory, TestCase
from django.urls import reverse

from permissible.admin import (
    PermDomainAdminMixin,
    PermissibleAdminMixin,
    UserPermDomainAdminMixin,
)
from permissible.models import PermDomain, PermDomainMember, PermDomainRole

User = get_user_model()


# Concrete models (module level, so they are registered before test DB setup)


class AdminTeam(PermDomain):
    name = models.CharField(max_length=100)

    groups = models.ManyToManyField(
        Group, through="AdminTeamRole", related_name="admin_teams"
    )
    users = models.ManyToManyField(
        get_user_model(), through="AdminTeamMember", related_name="admin_teams"
    )

    class Meta:
        app_label = "tests"

    def __str__(self):
        return self.name


class AdminTeamRole(PermDomainRole):
    team = models.ForeignKey(
        AdminTeam, on_delete=models.CASCADE, related_name="team_roles"
    )

    class Meta:
        app_label = "tests"
        unique_together = ("team", "role")


class AdminTeamMember(PermDomainMember):
    team = models.ForeignKey(
        AdminTeam, on_delete=models.CASCADE, related_name="team_members"
    )

    class Meta:
        app_label = "tests"
        unique_together = ("team", "user")


class AdminOrg(PermDomain):
    name = models.CharField(max_length=100)

    groups = models.ManyToManyField(
        Group, through="AdminOrgRole", related_name="admin_orgs"
    )
    users = models.ManyToManyField(
        get_user_model(), through="AdminOrgMember", related_name="admin_orgs"
    )

    class Meta:
        app_label = "tests"

    def __str__(self):
        return self.name


class AdminOrgRole(PermDomainRole):
    org = models.ForeignKey(
        AdminOrg, on_delete=models.CASCADE, related_name="org_roles"
    )

    class Meta:
        app_label = "tests"
        unique_together = ("org", "role")


class AdminOrgMember(PermDomainMember):
    org = models.ForeignKey(
        AdminOrg, on_delete=models.CASCADE, related_name="org_members"
    )

    class Meta:
        app_label = "tests"
        unique_together = ("org", "user")


# Admin classes


class AdminTeamAdmin(PermDomainAdminMixin, admin.ModelAdmin):
    pass


class AdminOrgAdmin(PermDomainAdminMixin, admin.ModelAdmin):
    pass


class PermissibleUserAdmin(UserPermDomainAdminMixin, UserAdmin):
    domain_class_dict = {"team": AdminTeam, "org": AdminOrg}
    readonly_fields = tuple(UserAdmin.readonly_fields) + ("permissible_groups_links",)
    fieldsets = tuple(UserAdmin.fieldsets) + (
        ("Permissible", {"fields": ("permissible_groups_links",)}),
    )


class EmptyDomainUserAdmin(UserPermDomainAdminMixin, admin.ModelAdmin):
    domain_class_dict = {}


class AdminTeamPermissibleAdmin(PermissibleAdminMixin, admin.ModelAdmin):
    pass


admin.site.register(AdminTeam, AdminTeamAdmin)
admin.site.register(AdminOrg, AdminOrgAdmin)
admin.site.unregister(User)
admin.site.register(User, PermissibleUserAdmin)


class AdminTestCaseBase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.superuser = User.objects.create_superuser(
            username="admin", email="admin@example.com", password="pw"
        )
        cls.staff_user = User.objects.create_user(
            username="staff", password="pw", is_staff=True
        )
        cls.plain_user = User.objects.create_user(username="plain", password="pw")
        cls.team = AdminTeam.objects.create(name="Team A")
        cls.org = AdminOrg.objects.create(name="Org A")


class PermDomainAdminMixinTest(AdminTestCaseBase):
    def setUp(self):
        self.client.force_login(self.superuser)
        self.team_admin = admin.site._registry[AdminTeam]

    def test_get_urls_registers_permissible_route(self):
        url = reverse("admin:tests_adminteam_permissible_change", args=[self.team.pk])
        self.assertEqual(url, f"/admin/tests/adminteam/{self.team.pk}/permissible/")

    def test_permissible_groups_link(self):
        html = self.team_admin.permissible_groups_link(self.team)
        self.assertIn(f"/admin/tests/adminteam/{self.team.pk}/permissible/", html)
        self.assertIn("Edit permissible groups", html)

    def test_change_page_renders_permissible_link(self):
        response = self.client.get(
            reverse("admin:tests_adminteam_change", args=[self.team.pk])
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Edit permissible groups")

    def test_permissible_view_get(self):
        response = self.client.get(
            reverse("admin:tests_adminteam_permissible_change", args=[self.team.pk])
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "admin/permissible_changeform.html")

    def test_permissible_view_post_redirects(self):
        url = reverse("admin:tests_adminteam_permissible_change", args=[self.team.pk])
        response = self.client.post(url, data={})
        self.assertRedirects(response, url)

    def test_permissible_view_requires_change_permission(self):
        self.client.force_login(self.staff_user)
        response = self.client.get(
            reverse("admin:tests_adminteam_permissible_change", args=[self.team.pk])
        )
        self.assertEqual(response.status_code, 404)

    def test_reset_domain_roles_action(self):
        expected_roles = len(AdminTeamRole.ROLE_DEFINITIONS)
        self.assertEqual(
            AdminTeamRole.objects.filter(team=self.team).count(), expected_roles
        )
        AdminTeamRole.objects.filter(team=self.team).delete()
        self.assertEqual(AdminTeamRole.objects.filter(team=self.team).count(), 0)

        self.team_admin.reset_domain_roles(
            request=None, queryset=AdminTeam.objects.filter(pk=self.team.pk)
        )
        self.assertEqual(
            AdminTeamRole.objects.filter(team=self.team).count(), expected_roles
        )


class UserPermDomainAdminMixinTest(AdminTestCaseBase):
    def setUp(self):
        self.client.force_login(self.superuser)
        self.user_admin = admin.site._registry[User]

    def test_get_urls_registers_route_per_domain_type(self):
        for perm_type in ("team", "org"):
            url = reverse(
                f"admin:auth_user_permissible_{perm_type}", args=[self.plain_user.pk]
            )
            self.assertEqual(
                url, f"/admin/auth/user/{self.plain_user.pk}/permissible/{perm_type}/"
            )

    def test_permissible_groups_links_joins_all_domain_types(self):
        # Regression test for Django 6.0: this called format_html() without
        # args, which raises TypeError on Django >= 6.0.
        html = self.user_admin.permissible_groups_links(self.plain_user)
        self.assertIn("Edit team permissions", html)
        self.assertIn("Edit org permissions", html)
        self.assertIn(" | ", html)

    def test_permissible_groups_links_empty_dict(self):
        empty_admin = EmptyDomainUserAdmin(User, admin.site)
        self.assertEqual(empty_admin.permissible_groups_links(self.plain_user), "None")

    def test_user_change_page_renders_links(self):
        response = self.client.get(
            reverse("admin:auth_user_change", args=[self.plain_user.pk])
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Edit team permissions")
        self.assertContains(response, "Edit org permissions")

    def test_user_permissible_view_requires_permissible_user_model(self):
        # The user-centric view checks change_permission on the target User,
        # which requires the User model to include PermissibleMixin. With
        # vanilla auth.User it raises a clear configuration error.
        url = reverse("admin:auth_user_permissible_team", args=[self.plain_user.pk])
        with self.assertRaisesMessage(ImproperlyConfigured, "PermissibleMixin"):
            self.client.get(url)
        with self.assertRaisesMessage(ImproperlyConfigured, "PermissibleMixin"):
            self.client.post(url, data={})


class PermissibleAdminMixinTest(AdminTestCaseBase):
    def setUp(self):
        self.model_admin = AdminTeamPermissibleAdmin(AdminTeam, admin.site)
        self.request = RequestFactory().get("/")
        self.request.user = self.superuser

    def test_has_change_permission_delegates_to_object(self):
        with patch.object(
            AdminTeam, "has_object_permission", return_value=True
        ) as mock_check:
            self.assertTrue(
                self.model_admin.has_change_permission(self.request, obj=self.team)
            )
        self.assertEqual(mock_check.call_count, 1)
        self.assertEqual(mock_check.call_args.kwargs["action"], "update")

    def test_has_delete_permission_delegates_to_object(self):
        with patch.object(
            AdminTeam, "has_object_permission", return_value=False
        ) as mock_check:
            self.assertFalse(
                self.model_admin.has_delete_permission(self.request, obj=self.team)
            )
        self.assertEqual(mock_check.call_args.kwargs["action"], "destroy")

    def test_has_view_permission_falls_back_to_update(self):
        with patch.object(
            AdminTeam,
            "has_object_permission",
            side_effect=lambda **kwargs: kwargs["action"] == "update",
        ):
            self.assertTrue(
                self.model_admin.has_view_permission(self.request, obj=self.team)
            )

    def test_has_add_permission_denied_globally(self):
        with patch.object(AdminTeam, "has_global_permission", return_value=False):
            self.assertFalse(self.model_admin.has_add_permission(self.request))
