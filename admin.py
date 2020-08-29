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
        if action == "create":
            return self.model.has_global_and_create_permission(user=request.user, action=action, obj_dict=request.data)
        elif not obj:
            return self.model.has_global_permission(user=request.user, action=action)
        else:
            return obj.has_object_permission(user=request.user, action=action)

    def has_add_permission(self, request, obj=None):
        return self._has_permission("create", request=request, obj=obj)

    def has_change_permission(self, request, obj=None):
        return self._has_permission("update", request=request, obj=obj)

    def has_delete_permission(self, request, obj=None):
        return self._has_permission("delete", request=request, obj=obj)

    def has_view_permission(self, request, obj=None):
        return self._has_permission("retrieve", request=request, obj=obj) or \
               self._has_permission("update", request=request, obj=obj)
