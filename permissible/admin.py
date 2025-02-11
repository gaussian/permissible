"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from __future__ import annotations

from collections import OrderedDict
from itertools import chain
from typing import TYPE_CHECKING, Dict, Type

from django.contrib import admin
from django.contrib.admin.widgets import AutocompleteSelect
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django import forms
from django.http import Http404
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
                # Not sure how we"d reach here...
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
    add = forms.BooleanField(
        initial=True, required=False, label="Add groups (uncheck to remove)"
    )
    role_changes = forms.JSONField(
        widget=forms.HiddenInput, required=False, initial={"added": {}, "removed": {}}
    )

    def __init__(self, perm_root_class, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.perm_root_group_class = perm_root_class.get_group_join_rel().related_model
        role_choices = (
            (role_value, role_label)
            for role_value, (
                role_label,
                _,
            ) in self.perm_root_group_class.ROLE_DEFINITIONS.items()
        )

        self.fields.update(
            dict(
                roles=forms.MultipleChoiceField(choices=role_choices, required=False),
            )
        )


class PermRootForm(PermissibleFormBase):
    def __init__(self, perm_root_class, *args, **kwargs):
        super().__init__(perm_root_class=perm_root_class, *args, **kwargs)

        # Get related field, to make an autocomplete widget
        users_field = perm_root_class._meta.get_field("users")

        self.fields.update(
            dict(
                user=forms.ModelChoiceField(
                    queryset=User.objects.all(),
                    widget=AutocompleteSelect(users_field, admin.site),
                    required=False,
                ),
            )
        )

    def clean_role_changes(self):
        role_changes = self.cleaned_data.get("role_changes", {})
        if not role_changes:
            return

        for role_changes_dict in role_changes.values():
            for user_id_to_role_bool_dict in role_changes_dict.values():
                for role in user_id_to_role_bool_dict.keys():
                    if role not in self.perm_root_group_class.ROLE_DEFINITIONS:
                        raise ValidationError(f"Invalid role: {role}")
        return role_changes

    def save(self, *args, **kwargs):
        role_changes = self.cleaned_data.get("role_changes", {})
        obj = kwargs.get("instance")
        if not obj:
            return

        role_changes_added = role_changes.get("added", {})
        role_changes_removed = role_changes.get("removed", {})

        # Convert traditional form submission to role_changes format (overwrites role_changes)
        if self.cleaned_data.get("user") and self.cleaned_data.get("roles"):
            user_id = str(self.cleaned_data["user"].pk)
            roles = self.cleaned_data["roles"]
            if self.cleaned_data["add"]:
                role_changes_added[user_id] = {role: True for role in roles}
            else:
                role_changes_removed[user_id] = {role: True for role in roles}

        # Process additions
        for user_id, roles in role_changes_added.items():
            user = User.objects.get(pk=user_id)
            roles_to_add = [role for role, should_add in roles.items() if should_add]

            # Superuser check for restricted roles
            if any(r in ("adm", "own") for r in roles_to_add):
                if not kwargs.get("request").user.is_superuser:
                    continue

            if roles_to_add:
                obj.add_user_to_groups(user=user, roles=roles_to_add)

        # Process removals
        for user_id, roles in role_changes_removed.items():
            user = User.objects.get(pk=user_id)
            roles_to_remove = [
                role for role, should_remove in roles.items() if should_remove
            ]

            # Superuser check for restricted roles
            if any(r in ("adm", "own") for r in roles_to_remove):
                if not kwargs.get("request").user.is_superuser:
                    continue

            if roles_to_remove:
                obj.remove_user_from_groups(user=user, roles=roles_to_remove)


class BasePermissibleViewMixin:
    """Shared logic between PermRoot-centric and User-centric views"""

    def get_role_choices(self, perm_root_group_class):
        return [
            (role_value, role_label)
            for role_value, (
                role_label,
                _,
            ) in perm_root_group_class.ROLE_DEFINITIONS.items()
        ]

    def get_role_to_user_id(self, perm_root_obj):
        """Get role->user_ids mapping for a single PermRoot"""
        role_to_user_ids = {
            perm_root_group.role: [
                str(u)
                for u in perm_root_group.group.user_set.values_list("pk", flat=True)
            ]
            for perm_root_group in perm_root_obj.get_group_joins().all()
        }

        base_roles = (
            perm_root_obj.get_group_join_rel().related_model.ROLE_DEFINITIONS.keys()
        )
        role_to_user_ids_sorted = OrderedDict()
        for role in base_roles:
            role_to_user_ids_sorted[role] = role_to_user_ids.get(role, [])
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


class UserPermRootForm(PermissibleFormBase):
    """Form that handles role changes for multiple PermRoots"""

    def __init__(self, perm_root_class, *args, **kwargs):
        super().__init__(perm_root_class=perm_root_class, *args, **kwargs)

        # Get related field, to make an autocomplete widget
        # Get the ManyToManyField from your perm_root_class (e.g. Team)
        perm_root_field = perm_root_class._meta.get_field("users")
        # Get the name Django uses for the reverse accessor on the User model.
        # Using get_accessor_name() will return (eg) "teams" (the related_name, if provided)
        reverse_field_name = perm_root_field.remote_field.get_accessor_name()
        # Now retrieve the field instance from the User model
        perm_root_obj_field = User._meta.get_field(reverse_field_name)

        self.fields.update(
            dict(
                perm_root_obj=forms.ModelChoiceField(
                    queryset=perm_root_class.objects.all(),
                    widget=AutocompleteSelect(perm_root_obj_field, admin.site),
                    required=False,
                ),
            )
        )


class UserPermissibleAdminMixin(BasePermissibleViewMixin):
    """Mixin for UserAdmin to show/edit user's roles across all PermRoots of a type"""

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

    def save_role_changes(self, request, user, perm_root_class, role_changes):
        """Handle the role changes for a specific user across multiple PermRoots"""
        role_changes_added = role_changes.get("added", {})
        role_changes_removed = role_changes.get("removed", {})

        for root_id, roles in role_changes_added.items():
            root_obj = perm_root_class.objects.get(pk=root_id)
            roles_to_add = [role for role, should_add in roles.items() if should_add]

            # Superuser check for restricted roles
            if any(r in ("adm", "own") for r in roles_to_add):
                if not request.user.is_superuser:
                    continue

            if roles_to_add:
                root_obj.add_user_to_groups(user=user, roles=roles_to_add)

        for root_id, roles in role_changes_removed.items():
            root_obj = perm_root_class.objects.get(pk=root_id)
            roles_to_remove = [
                role for role, should_remove in roles.items() if should_remove
            ]

            # Superuser check for restricted roles
            if any(r in ("adm", "own") for r in roles_to_remove):
                if not request.user.is_superuser:
                    continue

            if roles_to_remove:
                root_obj.remove_user_from_groups(user=user, roles=roles_to_remove)

    def user_permissible_view(self, request, object_id, perm_root_type):
        user = self.model.objects.get(pk=object_id)

        try:
            perm_root_class = self.permissible_root_classes[perm_root_type]
        except KeyError:
            raise Http404(f"Unknown PermRoot type: {perm_root_type}")

        if request.method == "POST":
            form = UserPermRootForm(perm_root_class, request.POST)
            if form.is_valid():
                role_changes = form.cleaned_data.get("role_changes", {})
                self.save_role_changes(request, user, perm_root_class, role_changes)
        else:
            form = UserPermRootForm(perm_root_class)

        # Get all PermRoots of this type
        perm_roots = perm_root_class.objects.all()

        # Build data structure for template
        root_to_roles = {}
        for root in perm_roots:
            root_to_roles[root] = {
                "roles": self.get_role_to_user_id(root),
                "perms": self.get_perms_for_obj(root).get(user, []),
            }

        # Get the roles from the first root for the column headers
        first_roles = (
            next(iter(root_to_roles.values()))["roles"] if root_to_roles else {}
        )

        context = {
            "title": f"Edit {user}'s roles in {perm_root_type}s",
            "form": form,
            "root_to_roles": root_to_roles,
            "first_roles": first_roles,
            "opts": self.model._meta,
            "user": user,
            **self.admin_site.each_context(request),
        }

        return TemplateResponse(
            request, "admin/user_permissible_changeform.html", context
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
    @admin.action(description="Create or reset group/role permissions")
    def reset_perm_groups(self, request, queryset):
        for root_obj in queryset:
            root_obj: PermRoot
            root_obj.reset_perm_groups()

    actions = (reset_perm_groups,)

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
        obj = self.model.objects.get(pk=object_id)

        if not self.has_change_permission(request=request, obj=obj):
            raise Http404("Lacking permission")

        if request.method == "POST":
            form = PermRootForm(self.model, request.POST)
            if form.is_valid():
                form.save(instance=obj, request=request)
        else:
            form = PermRootForm(self.model)

        role_to_user_id = self.get_role_to_user_id(obj)

        # Get object permissions for each user
        users_to_perms = self.get_perms_for_obj(obj)

        # Some users may be in PermGroups that do not have any permissions (eg in
        # the `mem` group but not any others), so we need to include them
        # (or guardian.shortcuts.get_users_with_perms have have failed to import!)
        user_ids = list(set(chain(*role_to_user_id.values())))
        leftover_user_ids = list(
            set([str(u.pk) for u in users_to_perms.keys()]).difference(set(user_ids))
        )
        users_to_perms.update(
            {User.objects.get(pk=user_id): [] for user_id in leftover_user_ids}
        )

        context = {
            "title": f"Add users to permissible groups of {obj}",
            "form": form,
            "role_to_user_id": role_to_user_id,
            "users_to_perms": users_to_perms,  # Pass user permissions to the template
            "opts": self.model._meta,
            # Include common variables for rendering the admin template.
            **self.admin_site.each_context(request),
        }

        return TemplateResponse(request, "admin/permissible_changeform.html", context)

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
