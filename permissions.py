"""
Neutron (a Visor module)
Author: Kut Akdogan
(c) 2016- Gaussian Holdings, LLC.

This codebase is confidential and proprietary.
No license for use, viewing, or reproduction without explicit written permission.
"""

from django.http import Http404
from rest_framework import permissions
from rest_framework.permissions import SAFE_METHODS


class PermissiblePerms(permissions.DjangoObjectPermissions):
    """
    Restricts DRF access to on an object using advanced configuration.

    Models that are to be protected in this way should use `PermissibleMixin`, and
    the necessary permissions should be configured using `global_action_perm_map`
    and `obj_action_perm_map` from that mixin.

    Requires use of an object-level permissions library/schema such as
    django-guardian.

    NOTE: much is copied from `permissions.DjangoObjectPermissions`.
    """

    # This is not used, unlike in `permissions.DjangoObjectPermissions`, because
    # we instead define a perms map in the model class (`action_perm_map`), via the
    # `PermissibleMixin` class
    perms_map = {}

    def has_permission(self, request, view):
        # Workaround to ensure DjangoModelPermissions are not applied
        # to the root view when using DefaultRouter.
        if getattr(view, '_ignore_model_permissions', False):
            return True

        if not request.user or (
           not request.user.is_authenticated and self.authenticated_users_only):
            return False

        model_class = self._queryset(view).model
        perm_check_kwargs = {
            "user": request.user,
            "action": view.action,
            "context": {"request": request}
        }
        if not model_class.has_global_permission(**perm_check_kwargs):
            return False
        if not view.detail and view.action != "list":
            # For actions that have no instance (i.e. detail=False, e.g. "create"),
            # we must create a dummy object from request data and pass it into
            # `has_object_permission`, as this function will normally not be called
            # NOTE: multiple objects are allowed, hence the list of objects checked
            return all(self.has_object_permission(
                request=request,
                view=view,
                obj=o
            ) for o in model_class.make_objs_from_data(request.data))
        return True

    def has_object_permission(self, request, view, obj):
        # authentication checks have already executed via has_permission
        queryset = self._queryset(view)
        model_cls = queryset.model
        user = request.user
        context = {"request": request}

        if not obj.has_object_permission(user=user, action=view.action, context=context):
            # If user is not authenticated (if self.authenticated_users_only = False),
            # then return False to raise a 403 (instead of 404 per the logic below)
            if not user.is_authenticated:
                return False

            # If the user does not have permissions we need to determine if
            # they have read permissions to see 403, or not, and simply see
            # a 404 response
            # NOTE: object MUST EXIST for a 404 to be thrown (might not be the case,
            # e.g. if we're checking during "create" action)

            if obj._state.adding:
                return False

            if request.method in SAFE_METHODS:
                # Read permissions already checked and failed, no need
                # to make another lookup.
                raise Http404

            if not obj.has_object_permission(user=user, action="retrieve", context=context):
                raise Http404

            # Has read permissions.
            return False

        return True


class PermissiblePermsUnauthAllowed(PermissiblePerms):
    """
    Same as `PermissiblePerms`, but allowing unauthenticated users to have their
    permissions checked. This does NOT give unauthenticated users immediate
    access - they still need to pass the permission checks - but it does
    not automatically deny all unauthenticated users (like `PermissiblePerms`
    does).

    Models that are to be protected in this way should use `PermissibleMixin`, and
    the necessary permissions should be configured using `global_action_perm_map`
    and `obj_action_perm_map` from that mixin.

    Requires use of an object-level permissions library/schema such as
    django-guardian.

    NOTE: much is copied from `permissions.DjangoObjectPermissions`.
    """
    authenticated_users_only = False
