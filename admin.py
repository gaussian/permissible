"""
Neutron (a Visor module)
Author: Kut Akdogan
(c) 2016- Gaussian Holdings, LLC.

This codebase is confidential and proprietary.
No license for use, viewing, or reproduction without explicit written permission.
"""

from neutron.permissible.models import PermissibleMixin


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
        return self._has_permission("retrieve", request=request, obj=obj) or \
               self._has_permission("update", request=request, obj=obj)


class PermissibleObjectAssignMixin(object):
    pass


class PermissibleGroupRootMixin(object):
    def set_default_group_permissions(self, request, queryset):
        for group_root_obj in queryset:
            group_root_obj.set_permissions_for_group()
    set_default_group_permissions.short_description = "Set default permissions of associated Group"

    actions = [
        set_default_group_permissions
    ]
