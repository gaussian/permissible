"""
Django admin customization for the permissible module.
Provides mixins for managing object-level permissions through
the Django admin interface. The main components are:

- PermDomainAdminMixin: Adds permission management to PermDomain model admins

This module does not require django-guardian for object-level permissions, but
does benefit from it.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model

from permissible.models import PermissibleMixin

User = get_user_model()


class PermissibleAdminMixin(object):
    """
    Restricts viewing, editing, changing, and deleting on an object to those
    who have the necessary permissions for that object.

    Models that are to be protected in this way should use `PermissibleMixin`,
    and the necessary permissions should be configured using
    `policies.ACTION_POLICIES[<model_label>]`.

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
    # TODO: Implement this mixin
    pass
