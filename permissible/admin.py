"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from collections import OrderedDict
from itertools import chain

from django.contrib import admin
from django.contrib.admin.widgets import AutocompleteSelect
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django import forms
from django.http import Http404
from django.template.response import TemplateResponse
from django.urls import path, reverse
from django.utils.html import format_html

from .models import PermissibleMixin

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
        assert issubclass(self.model, PermissibleMixin), \
            "Must use `PermissibleMixin` on the model class"

        # Permission checks
        perm_check_kwargs = {
            "user": request.user,
            "action": action,
            "context": {"request": request}
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
        return self._has_permission("retrieve", request=request, obj=obj) or \
               self._has_permission("update", request=request, obj=obj)


class PermissibleObjectAssignMixin(object):
    pass


class PermRootForm(forms.Form):
    add = forms.BooleanField(initial=True, required=False, label="Add groups (uncheck to remove)")

    def __init__(self, perm_root_class, *args, **kwargs):
        super().__init__(*args, **kwargs)

        perm_root_group_class = perm_root_class.get_group_join_rel().related_model
        role_choices = ((role_value, role_label)
                        for role_value, (role_label, _) in perm_root_group_class.ROLE_DEFINITIONS.items())

        # Get related field, to make an autocomplete widget
        users_field = perm_root_class._meta.get_field("users")

        self.fields.update(dict(
            user=forms.ModelChoiceField(queryset=User.objects.all(),
                                        widget=AutocompleteSelect(users_field, admin.site)),
            roles=forms.MultipleChoiceField(choices=role_choices)
        ))


class PermRootAdminMixin(object):
    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path("<object_id>/permissible/", self.admin_site.admin_view(self.permissible_view), name=self.get_permissible_change_url_name())
        ]
        return custom_urls + urls

    def permissible_view(self, request, object_id):
        obj = self.model.objects.get(pk=object_id)

        if not self.has_change_permission(request=request, obj=obj):
            raise Http404("Lacking permission")

        if request.method == "POST":
            form = PermRootForm(self.model, request.POST)
            if form.is_valid():
                roles = form.cleaned_data["roles"] or []
                if not request.user.is_superuser and any(r in roles for r in ("adm", "own")):
                    raise ValidationError(f"Bad roles, must be superuser: {roles}")
                user = form.cleaned_data["user"]
                if form.cleaned_data["add"]:
                    obj.add_user_to_groups(user=user, roles=roles)
                else:
                    obj.remove_user_from_groups(user=user, roles=roles)
        else:
            form = PermRootForm(self.model)

        unordered_role_to_users = {perm_root_group.role: [
            str(u) for u in perm_root_group.group.user_set.values_list(User.USERNAME_FIELD, flat=True)
        ] for perm_root_group in obj.get_group_joins().all()}

        base_roles = ("own", "adm", "con", "view", "mem")
        role_to_users = OrderedDict()
        for role in base_roles:
            role_to_users[role] = unordered_role_to_users.get(role, [])
        for role in unordered_role_to_users.keys():
            if role not in base_roles:
                role_to_users[role] = unordered_role_to_users.get(role, [])

        users = list(set(chain(*role_to_users.values())))

        context = {
            "title": f"Add users to permissible groups of {obj}",
            "form": form,
            "role_to_users": role_to_users,
            "users": users,
            "opts": self.model._meta,
            # Include common variables for rendering the admin template.
            **self.admin_site.each_context(request),
        }
        return TemplateResponse(request, "admin/permissible_changeform.html", context)

    readonly_fields = (
        "permissible_groups_link",
    )

    def get_permissible_change_url_name(self):
        return "%s_%s_permissible_change" % (self.model._meta.app_label, self.model._meta.model_name)

    def permissible_groups_link(self, obj):
        url = reverse("admin:" + self.get_permissible_change_url_name(), args=(obj.pk,))
        link_text = "Edit permissible groups"
        html_format_string = "<a href=' {url}'>{link_text}</a>"     # SPACE IS NEEDED!
        return format_html(html_format_string, url=url, text=link_text)
