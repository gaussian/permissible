"""
Neutron (a Visor module)
Author: Kut Akdogan
(c) 2016- Gaussian Holdings, LLC.

This codebase is confidential and proprietary.
No license for use, viewing, or reproduction without explicit written permission.
"""

from django.contrib.auth import get_user_model
from django import forms
from django.contrib.auth.models import Group
from django.template.response import TemplateResponse
from django.urls import path, reverse

from neutron.admin.forms import get_autocomplete_widget_for_model
from neutron.admin.utils import get_url_as_link
from neutron.permissible.models import PermissibleMixin

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

        self.fields.update(dict(
            user=forms.ModelChoiceField(queryset=User.objects.all(),
                                        widget=get_autocomplete_widget_for_model(User)),
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

        # TODO: allow this for users that have appropriate permissions, perhaps by setting self.has_permission() (see self.admin_site.admin_view())
        if request.method == "POST" and request.user.is_superuser:
            form = PermRootForm(self.model, request.POST)
            if form.is_valid():
                roles = form.cleaned_data["roles"]
                group_ids = obj.get_group_joins().filter(
                    role__in=roles
                ).values_list("group_id", flat=True)
                groups = Group.objects.filter(id__in=group_ids)
                user = form.cleaned_data["user"]
                if form.cleaned_data["add"]:
                    user.groups.add(*list(groups))
                else:
                    user.groups.remove(*list(groups))
        else:
            form = PermRootForm(self.model)

        role_to_users = {perm_root_group.role: [
            str(u) for u in perm_root_group.group.user_set.values_list(User.USERNAME_FIELD, flat=True)
        ] for perm_root_group in obj.get_group_joins().all()}

        context = {
            "title": "Add users to permissible groups",
            "form": form,
            "role_to_users": role_to_users,
            "opts": self.model._meta,
            # Include common variables for rendering the admin template.
            **self.admin_site.each_context(request),
        }
        return TemplateResponse(request, "admin/permissible_changeform.html", context)

    readonly_fields = (
        "permissible_link",
    )

    def get_permissible_change_url_name(self):
        return "%s_%s_permissible_change" % (self.model._meta.app_label, self.model._meta.model_name)

    def permissible_link(self, obj):
        url_for_link = reverse("admin:" + self.get_permissible_change_url_name(), args=(obj.pk,))
        return get_url_as_link(url_for_link, str(obj), check_for_http=False, new_window=False)
