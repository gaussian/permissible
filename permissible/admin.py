"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from collections import OrderedDict
from itertools import chain
from typing import TYPE_CHECKING

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


class PermRootForm(forms.Form):
    add = forms.BooleanField(
        initial=True, required=False, label="Add groups (uncheck to remove)"
    )
    role_changes = forms.JSONField(
        widget=forms.HiddenInput, required=False, initial={"added": {}, "removed": {}}
    )
    # role_changes = forms.CharField(widget=forms.HiddenInput, required=False)

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

        # Get related field, to make an autocomplete widget
        users_field = perm_root_class._meta.get_field("users")

        self.fields.update(
            dict(
                user=forms.ModelChoiceField(
                    queryset=User.objects.all(),
                    widget=AutocompleteSelect(users_field, admin.site),
                    required=False,
                ),
                roles=forms.MultipleChoiceField(choices=role_choices, required=False),
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


class PermRootAdminMixin(object):
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

        role_to_user_ids = {
            perm_root_group.role: [
                str(u)
                for u in perm_root_group.group.user_set.values_list("pk", flat=True)
            ]
            for perm_root_group in obj.get_group_joins().all()
        }

        base_roles = PermRootGroup.ROLE_DEFINITIONS.keys()
        role_to_user_ids_sorted = OrderedDict()
        for role in base_roles:
            role_to_user_ids_sorted[role] = role_to_user_ids.get(role, [])
        for role in role_to_user_ids.keys():
            if role not in base_roles:
                role_to_user_ids_sorted[role] = role_to_user_ids.get(role, [])

        # Get object permissions for each user (use guardian shortcut to populate object permissions if can import)
        try:
            from guardian.shortcuts import get_users_with_perms

            users_to_perms = get_users_with_perms(obj, attach_perms=True)
        except Exception as e:
            users_to_perms = {}

        # Some users may be in PermGroups that do not have any permissions (eg in
        # the `mem` group but not any others), so we need to include them
        # (or guardian.shortcuts.get_users_with_perms have have failed to import!)
        user_ids = list(set(chain(*role_to_user_ids_sorted.values())))
        leftover_user_ids = list(
            set([str(u.pk) for u in users_to_perms.keys()]).difference(set(user_ids))
        )
        users_to_perms.update(
            {User.objects.get(pk=user_id): [] for user_id in leftover_user_ids}
        )

        context = {
            "title": f"Add users to permissible groups of {obj}",
            "form": form,
            "role_to_users": role_to_user_ids_sorted,
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
