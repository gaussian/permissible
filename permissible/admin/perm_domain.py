"""
Django admin customization for the permissible module.
Provides mixins for managing object-level permissions through
the Django admin interface. The main components are:

- BasePermissibleViewMixin: Shared view logic for permission management
- PermDomainAdminMixin: Adds object-centric permission management to PermDomainAdmin
- UserPermDomainAdminMixin: Adds user-centric permission management to UserAdmin

This module does not require django-guardian for object-level permissions, but
does benefit from it.
"""

from __future__ import annotations

from collections import OrderedDict
from itertools import chain
from typing import TYPE_CHECKING, Dict, Type

from django.contrib import admin
from django.contrib.auth import get_user_model
from django.http import Http404
from django.shortcuts import redirect
from django.template.response import TemplateResponse
from django.urls import path, reverse
from django.utils.html import format_html

from .forms import PermDomainForm, BaseRoleBasedForm, UserPermDomainForm

if TYPE_CHECKING:
    from permissible.models import PermDomain

User = get_user_model()


class BasePermissibleViewMixin:
    """
    Shared view logic for permission management views.

    Provides common utilities for:
    - Retrieving role mappings
    - Getting object permissions
    - Processing permission views
    - Building context data
    """

    def get_role_to_user_id(self, perm_domain_obj):
        """
        Build a mapping of roles to user IDs for a PermDomain object.

        This method:
        1. Gets all group joins (role assignments) for the object
        2. Maps each role to its assigned user IDs
        3. Orders roles according to ROLE_DEFINITIONS
        4. Ensures all base roles are present even if empty
        5. Preserves any custom roles not in base roles

        Returns:
            OrderedDict: {role_name: [user_id_str, ...], ...}
        """
        # First get all current role assignments
        role_to_user_ids = {
            perm_domain_role.role: [
                str(u)
                for u in perm_domain_role.group.user_set.values_list("pk", flat=True)
            ]
            for perm_domain_role in perm_domain_obj.get_role_joins().all()
        }

        # Get the predefined roles from the model
        base_roles = (
            perm_domain_obj.get_role_join_rel().related_model.ROLE_DEFINITIONS.keys()
        )

        # Create ordered mapping with base roles first
        role_to_user_ids_sorted = OrderedDict()
        # Add base roles in their defined order
        for role in base_roles:
            role_to_user_ids_sorted[role] = role_to_user_ids.get(role, [])
        # Add any custom roles that weren't in base_roles
        for role in role_to_user_ids.keys():
            if role not in base_roles:
                role_to_user_ids_sorted[role] = role_to_user_ids.get(role, [])

        return role_to_user_ids_sorted

    def get_users_to_perms_for_obj(self, obj):
        """
        Get user->perms mapping for a single object
        (use guardian shortcut to populate object permissions if can import)
        """
        try:
            from guardian.shortcuts import get_users_with_perms

            return get_users_with_perms(obj, attach_perms=True)
        except Exception:
            return {}

    def handle_permission_view(
        self, request, obj, form_class, template_name, context_extras=None
    ):
        """
        Common view handler for permission management views.

        Handles:
        - Permission checking
        - Form processing
        - Context building
        - Template rendering

        Args:
            request: The HTTP request
            obj: The object being modified (User or PermDomain)
            form_class: Form class to use (UserPermDomainForm or PermDomainForm)
            template_name: Template to render
            context_extras: Additional context data
        """
        if obj and not BaseRoleBasedForm.user_has_permission_change_perm(
            request.user, obj
        ):
            raise Http404("Lacking permission to change permissions")

        if request.method == "POST":
            form = form_class(request.POST)
            if form.is_valid():
                form.save(instance=obj, request=request)
            return redirect(request.path)
        else:
            form = form_class()

        context = {
            "form": form,
            "opts": self.model._meta,
            **self.admin_site.each_context(request),
            **(context_extras or {}),
        }

        return TemplateResponse(request, template_name, context)


class PermDomainAdminMixin(BasePermissibleViewMixin):
    """
    Mixin for PermDomain model admins that adds permission management capabilities.

    Allows managing multiple users' roles on a single PermDomain object through
    the Django admin interface. Also provides utilities for resetting permissions
    and managing permission groups.
    """

    actions = ("reset_domain_roles",)

    @admin.action(description="Create or reset group/role permissions")
    def reset_domain_roles(self, request, queryset):
        """Admin action to reset permission groups for selected objects"""
        for domain_obj in queryset:
            domain_obj: PermDomain
            domain_obj.reset_domain_roles()

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path(
                "<object_id>/permissible/",
                self.admin_site.admin_view(self.permissible_view),
                name=self.get_permissible_change_url_name(),
            )
        ]
        return custom_urls + urls

    def permissible_view(self, request, object_id):
        """
        View for managing all users' roles on a specific object.

        Shows a matrix of:
        - Rows: Users
        - Columns: Available roles
        - Cells: Checkboxes for role assignment
        """
        obj = self.model.objects.get(pk=object_id)

        # This is the mapping for role to user_id for any Users that are present
        # in the group joins for this object (i.e. have roles and are part of
        # PermDomainRole groups)
        role_to_user_id = self.get_role_to_user_id(obj)

        # This is the mapping of user object to permissions list for this object
        # but note that this is only for users that have permissions on the object
        users_to_perms = self.get_users_to_perms_for_obj(obj)

        # Add users that have roles but no permissions
        user_ids_from_roles = set(chain(*role_to_user_id.values()))
        user_ids_with_perms = set([str(u.pk) for u in users_to_perms.keys()])
        user_ids_missing_from_perms_dict = user_ids_from_roles - user_ids_with_perms
        users_to_perms.update(
            {
                User.objects.get(pk=user_id): []
                for user_id in user_ids_missing_from_perms_dict
            }
        )

        context_extras = {
            "title": f"Add users to permissible groups of {obj}",
            "role_to_user_id": role_to_user_id,
            "users_to_perms": users_to_perms,
        }

        return self.handle_permission_view(
            request,
            obj,
            lambda *args: PermDomainForm(self.model, *args),
            "admin/permissible_changeform.html",
            context_extras,
        )

    readonly_fields = ("permissible_groups_link",)

    def get_permissible_change_url_name(self):
        return "%s_%s_permissible_change" % (
            self.model._meta.app_label,
            self.model._meta.model_name,
        )

    def permissible_groups_link(self, obj):
        url = reverse("admin:" + self.get_permissible_change_url_name(), args=(obj.pk,))
        link_text = "Edit permissible groups"
        html_format_string = "<a href=' {url}'>{link_text}</a>"  # SPACE IS NEEDED!
        return format_html(html_format_string, url=url, link_text=link_text)


class UserPermDomainAdminMixin(BasePermissibleViewMixin):
    """
    Mixin for UserAdmin that adds permission management capabilities.

    Allows managing a user's roles across multiple PermDomain objects through
    the Django admin interface. Supports multiple types of PermDomain objects
    (e.g., Teams, Projects) through the domain_class_dict mapping.
    """

    # Dictionary mapping type names to PermDomain model classes
    # Example: {'team': TeamModel, 'project': ProjectModel}
    domain_class_dict: Dict[str, Type[PermDomain]] = {}

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = []
        for perm_type in self.domain_class_dict.keys():
            custom_urls.append(
                path(
                    f"<path:object_id>/permissible/{perm_type}/",
                    self.admin_site.admin_view(
                        lambda request, object_id, pt=perm_type: self.user_permissible_view(
                            request, object_id, pt
                        )
                    ),
                    name=f"{self.model._meta.app_label}_{self.model._meta.model_name}_permissible_{perm_type}",
                )
            )
        return custom_urls + urls

    def user_permissible_view(self, request, object_id, perm_domain_type):
        """
        View for managing a user's roles across all objects of a specific type.

        Shows a matrix of:
        - Rows: PermDomain objects
        - Columns: Available roles
        - Cells: Checkboxes for role assignment
        """
        user = self.model.objects.get(pk=object_id)
        try:
            perm_domain_class = self.domain_class_dict[perm_domain_type]
        except KeyError:
            raise Http404(f"Unknown PermDomain type: {perm_domain_type}")

        # Get all PermDomain objects of the specified type
        perm_domains = perm_domain_class.objects.filter(users=user)

        # Filter down to the PermDomain records that the request user has change_permission on
        perm_domains = [
            domain
            for domain in perm_domains
            if BaseRoleBasedForm.user_has_permission_change_perm(request.user, domain)
        ]

        domain_to_roles = {
            domain: {
                "roles": self.get_role_to_user_id(domain),
                "perms": self.get_users_to_perms_for_obj(domain).get(user, []),
            }
            for domain in perm_domains
        }

        context_extras = {
            "title": f"Edit {user}'s roles in {perm_domain_type}s",
            "domain_to_roles": domain_to_roles,
            "first_roles": (
                next(iter(domain_to_roles.values()))["roles"] if domain_to_roles else {}
            ),
            "user": user,
            "perm_domain_name": perm_domain_class._meta.verbose_name,
        }

        return self.handle_permission_view(
            request,
            user,
            lambda *args: UserPermDomainForm(perm_domain_class, *args),
            "admin/user_permissible_changeform.html",
            context_extras,
        )

    readonly_fields = ("permissible_groups_links",)

    def permissible_groups_links(self, obj):
        """Generate links for each configured PermDomain type"""
        links = []
        for perm_type in self.domain_class_dict.keys():
            url = reverse(
                f"admin:{self.model._meta.app_label}_{self.model._meta.model_name}_permissible_{perm_type}",
                args=[obj.pk],
            )
            links.append(
                format_html('<a href="{}">{}</a>', url, f"Edit {perm_type} permissions")
            )
        if not links:
            return "None"
        return format_html(" | ".join(links))
