"""
Django admin customization for the permissible module.
Provides mixins and form classes for managing object-level permissions through
the Django admin interface. The main components are:

- PermissibleFormBase: Base form for handling role changes
- UserPermRootForm: Form for managing a user's roles across multiple PermRoot objects
- PermRootForm: Form for managing multiple users' roles on a single PermRoot object
- BasePermissibleViewMixin: Shared view logic for permission management
- UserPermissibleAdminMixin: Adds user-centric permission management to UserAdmin
- PermRootAdminMixin: Adds permission management to PermRoot model admins

This module requires django-guardian for object-level permissions.
"""

from __future__ import annotations

from collections import OrderedDict
from itertools import chain
from typing import TYPE_CHECKING, Dict, Type

from django.contrib import admin
from django.contrib.admin.widgets import AutocompleteSelect
from django.contrib.auth import get_user_model
from django.contrib.auth.models import PermissionsMixin
from django.core.exceptions import ValidationError
from django import forms
from django.http import Http404
from django.shortcuts import redirect
from django.template.response import TemplateResponse
from django.urls import path, reverse
from django.utils.html import format_html


from .models import PermissibleMixin, PermRootGroup

if TYPE_CHECKING:
    from .models.perm_root import PermRoot

User = get_user_model()


class PermissibleAdminMixin(object):
    """
    Restricts viewing, editing, changing, and deleting on an object to those
    who have the necessary permissions for that object.

    Models that are to be protected in this way should use `PermissibleMixin`,
    and the necessary permissions should be configured using `global_action_perm_map`
    and `obj_action_perm_map` from that mixin.

    Requires use of an object-level permissions library/schema such as
    django-guardian.
    """

    def _has_permission(self, action: str, request, obj: PermissibleMixin):
        assert issubclass(
            self.model, PermissibleMixin
        ), "Must use `PermissibleMixin` on the model class"

        # Permission checks
        perm_check_kwargs = {
            "user": request.user,
            "action": action,
            "context": {"request": request},
        }
        if not obj:
            if not self.model.has_global_permission(**perm_check_kwargs):
                return False
            if action != "create":
                # Not sure how we'd reach here...
                return False
            # For "create" action, we must create a dummy object from request data
            # and use it to check permissions against
            obj = self.model.make_objs_from_data(request.data)[0]
        return obj.has_object_permission(**perm_check_kwargs)

    def has_add_permission(self, request, obj=None):
        return self._has_permission("create", request=request, obj=obj)

    def has_change_permission(self, request, obj=None):
        return self._has_permission("update", request=request, obj=obj)

    def has_delete_permission(self, request, obj=None):
        return self._has_permission("destroy", request=request, obj=obj)

    def has_view_permission(self, request, obj=None):
        return self._has_permission(
            "retrieve", request=request, obj=obj
        ) or self._has_permission("update", request=request, obj=obj)


class PermissibleObjectAssignMixin(object):
    pass


class PermissibleFormBase(forms.Form):
    """
    Base form for handling role changes in permissible objects.

    This form provides the foundation for both user-centric and object-centric
    permission management. It handles:
    - Role addition/removal through a checkbox
    - JSON-based role change tracking
    - Permission validation
    - Role processing for both individual and batch changes
    """

    # Checkbox for toggling between adding and removing roles
    add = forms.BooleanField(
        initial=True, required=False, label="Add groups (uncheck to remove)"
    )

    # Hidden field for tracking role changes made through UI interactions
    role_changes = forms.JSONField(
        widget=forms.HiddenInput, required=False, initial={"added": {}, "removed": {}}
    )

    def __init__(self, perm_root_class, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.perm_root_class = perm_root_class
        self.perm_root_group_class = perm_root_class.get_group_join_rel().related_model
        self.setup_fields()

    def setup_fields(self):
        """Override in subclasses to add additional fields"""
        role_choices = [
            (role_value, role_label)
            for role_value, (
                role_label,
                _,
            ) in self.perm_root_group_class.ROLE_DEFINITIONS.items()
        ]
        self.fields["roles"] = forms.MultipleChoiceField(
            choices=role_choices, required=False
        )

    def clean_role_changes(self):
        role_changes = self.cleaned_data.get("role_changes", {})
        if not role_changes:
            return {}

        for role_changes_dict in role_changes.values():
            for obj_id_to_role_bool_dict in role_changes_dict.values():
                for role in obj_id_to_role_bool_dict.keys():
                    if role not in self.perm_root_group_class.ROLE_DEFINITIONS:
                        raise ValidationError(f"Invalid role: {role}")
        return role_changes

    def process_role_changes(self, role_changes, user=None, obj=None, request=None):
        """Process role changes for either user->roots or root->users relationships."""
        if not (request and (user or obj)):
            return

        role_changes_added = role_changes.get("added", {})
        role_changes_removed = role_changes.get("removed", {})

        # Convert traditional form submission to role_changes format (overwrites role_changes)
        if self.cleaned_data.get("roles"):
            if obj and self.cleaned_data.get("user"):
                user_id = str(self.cleaned_data["user"].pk)
                roles = self.cleaned_data["roles"]
                if self.cleaned_data["add"]:
                    role_changes_added[user_id] = {role: True for role in roles}
                else:
                    role_changes_removed[user_id] = {role: True for role in roles}
            elif user and self.cleaned_data.get("perm_root_obj"):
                root_id = str(self.cleaned_data["perm_root_obj"].pk)
                roles = self.cleaned_data["roles"]
                if self.cleaned_data["add"]:
                    role_changes_added[root_id] = {role: True for role in roles}
                else:
                    role_changes_removed[root_id] = {role: True for role in roles}

        def process_roles(changes_dict, add_roles=True):
            """
            Process a batch of role changes (either additions or removals).

            This helper function handles both adding and removing roles by abstracting
            the common logic between the two operations. It:
            1. Processes each ID (either user or root) in the changes
            2. Validates permissions for each change
            3. Filters out invalid or unauthorized changes
            4. Applies the changes in bulk

            Args:
                changes_dict: Dictionary of {id: {role: bool}} mappings
                add_roles: True for adding roles, False for removing
            """
            for id_str, roles in changes_dict.items():
                # Handle both directions: user->roots and root->users
                # In user mode: id_str is a root_id, target_user is fixed
                # In root mode: id_str is a user_id, root_obj is fixed
                if user:
                    root_obj = self.perm_root_class.objects.get(pk=id_str)
                    target_user = user
                else:
                    root_obj = obj
                    target_user = User.objects.get(pk=id_str)

                # Skip if requesting user lacks permission
                if not self.user_has_permission_change_perm(request.user, root_obj):
                    continue

                # Filter roles that should be changed
                roles_to_change = [
                    role for role, should_change in roles.items() if should_change
                ]
                if not roles_to_change:
                    continue

                # Only superusers can modify admin/owner roles
                restricted_roles = ("adm", "own")
                if (
                    any(r in restricted_roles for r in roles_to_change)
                    and not request.user.is_superuser
                ):
                    continue

                # Apply the changes using the appropriate method
                method = (
                    root_obj.add_user_to_groups
                    if add_roles
                    else root_obj.remove_user_from_groups
                )
                method(user=target_user, roles=roles_to_change)

        # Use the same logic for both additions and removals
        process_roles(role_changes_added, add_roles=True)
        process_roles(role_changes_removed, add_roles=False)

    @staticmethod
    def user_has_permission_change_perm(user, obj):
        """
        Check if a user has permission to change permissions on an object.

        Uses django-guardian's permission system to verify the user has the
        specific 'change_permission' permission on the given object.
        """
        permission = obj.get_permission_codename("change_permission")
        return user.has_perm(permission, obj)


class PermRootForm(PermissibleFormBase):
    def setup_fields(self):
        super().setup_fields()
        self.fields["user"] = forms.ModelChoiceField(
            queryset=User.objects.all(),
            widget=AutocompleteSelect(
                self.perm_root_class._meta.get_field("users"), admin.site
            ),
            required=False,
        )

    def save(self, *args, **kwargs):
        self.process_role_changes(
            self.cleaned_data.get("role_changes", {}),
            obj=kwargs.get("instance"),
            request=kwargs.get("request"),
        )


class UserPermRootForm(PermissibleFormBase):
    def setup_fields(self):
        super().setup_fields()
        self.fields["perm_root_obj"] = forms.ModelChoiceField(
            queryset=self.perm_root_class.objects.all(),
            widget=AutocompleteSelect(
                self.perm_root_class.get_user_join_rel().field, admin.site
            ),
            required=False,
            label=f"Add {self.perm_root_class._meta.verbose_name} to user",
        )

    def save(self, *args, **kwargs):
        self.process_role_changes(
            self.cleaned_data.get("role_changes", {}),
            user=kwargs.get("instance"),
            request=kwargs.get("request"),
        )


class BasePermissibleViewMixin:
    """
    Shared view logic for permission management views.

    Provides common utilities for:
    - Retrieving role mappings
    - Getting object permissions
    - Processing permission views
    - Building context data
    """

    def get_role_to_user_id(self, perm_root_obj):
        """
        Build a mapping of roles to user IDs for a PermRoot object.

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
            perm_root_group.role: [
                str(u)
                for u in perm_root_group.group.user_set.values_list("pk", flat=True)
            ]
            for perm_root_group in perm_root_obj.get_group_joins().all()
        }

        # Get the predefined roles from the model
        base_roles = (
            perm_root_obj.get_group_join_rel().related_model.ROLE_DEFINITIONS.keys()
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

    def get_perms_for_obj(self, obj):
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
            obj: The object being modified (User or PermRoot)
            form_class: Form class to use (UserPermRootForm or PermRootForm)
            template_name: Template to render
            context_extras: Additional context data
        """
        if obj and not PermissibleFormBase.user_has_permission_change_perm(
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


class UserPermissibleAdminMixin(BasePermissibleViewMixin):
    """
    Mixin for UserAdmin that adds permission management capabilities.

    Allows managing a user's roles across multiple PermRoot objects through
    the Django admin interface. Supports multiple types of PermRoot objects
    (e.g., Teams, Projects) through the permissible_root_classes mapping.
    """

    # Dictionary mapping type names to PermRoot model classes
    # Example: {'team': TeamModel, 'project': ProjectModel}
    permissible_root_classes: Dict[str, Type[PermRoot]] = {}

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = []
        for perm_type in self.permissible_root_classes.keys():
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

    def user_permissible_view(self, request, object_id, perm_root_type):
        """
        View for managing a user's roles across all objects of a specific type.

        Shows a matrix of:
        - Rows: PermRoot objects
        - Columns: Available roles
        - Cells: Checkboxes for role assignment
        """
        user = self.model.objects.get(pk=object_id)
        try:
            perm_root_class = self.permissible_root_classes[perm_root_type]
        except KeyError:
            raise Http404(f"Unknown PermRoot type: {perm_root_type}")

        perm_roots = perm_root_class.objects.filter(users=user)
        root_to_roles = {
            root: {
                "roles": self.get_role_to_user_id(root),
                "perms": self.get_perms_for_obj(root).get(user, []),
            }
            for root in perm_roots
        }

        context_extras = {
            "title": f"Edit {user}'s roles in {perm_root_type}s",
            "root_to_roles": root_to_roles,
            "first_roles": (
                next(iter(root_to_roles.values()))["roles"] if root_to_roles else {}
            ),
            "user": user,
            "perm_root_name": perm_root_class._meta.verbose_name,
        }

        return self.handle_permission_view(
            request,
            user,
            lambda *args: UserPermRootForm(perm_root_class, *args),
            "admin/user_permissible_changeform.html",
            context_extras,
        )

    def permissible_groups_link(self, obj):
        """Generate links for each configured PermRoot type"""
        links = []
        for perm_type in self.permissible_root_classes.keys():
            url = reverse(
                f"admin:{self.model._meta.app_label}_{self.model._meta.model_name}_permissible_{perm_type}",
                args=[obj.pk],
            )
            links.append(
                format_html('<a href="{}">{}</a>', url, f"Edit {perm_type} permissions")
            )
        return format_html(" | ".join(links))


class PermRootAdminMixin(BasePermissibleViewMixin):
    """
    Mixin for PermRoot model admins that adds permission management capabilities.

    Allows managing multiple users' roles on a single PermRoot object through
    the Django admin interface. Also provides utilities for resetting permissions
    and managing permission groups.
    """

    actions = ("reset_perm_groups",)

    @admin.action(description="Create or reset group/role permissions")
    def reset_perm_groups(self, request, queryset):
        """Admin action to reset permission groups for selected objects"""
        for root_obj in queryset:
            root_obj: PermRoot
            root_obj.reset_perm_groups()

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
        role_to_user_id = self.get_role_to_user_id(obj)
        users_to_perms = self.get_perms_for_obj(obj)

        # Add users that have permissions but no roles
        user_ids = list(set(chain(*role_to_user_id.values())))
        leftover_user_ids = list(
            set([str(u.pk) for u in users_to_perms.keys()]).difference(set(user_ids))
        )
        users_to_perms.update(
            {User.objects.get(pk=user_id): [] for user_id in leftover_user_ids}
        )

        context_extras = {
            "title": f"Add users to permissible groups of {obj}",
            "role_to_user_id": role_to_user_id,
            "users_to_perms": users_to_perms,
        }

        return self.handle_permission_view(
            request,
            obj,
            lambda *args: PermRootForm(self.model, *args),
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
