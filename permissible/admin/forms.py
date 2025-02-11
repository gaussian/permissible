"""
Django admin customization for the permissible module.
Provides form classes for managing object-level permissions through
the Django admin interface. The main components are:

- PermissibleFormBase: Base form for handling role changes
- UserPermRootForm: Form for managing a user's roles across multiple PermRoot objects
- PermRootForm: Form for managing multiple users' roles on a single PermRoot object

This module does not require django-guardian for object-level permissions, but
does benefit from it.
"""

from __future__ import annotations

from django.contrib import admin
from django.contrib.admin.widgets import AutocompleteSelect
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django import forms

User = get_user_model()


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
