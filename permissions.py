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

        queryset = self._queryset(view)
        return queryset.model.has_global_and_create_permission(
            user=request.user,
            action=request.action,
            obj_dict=request.data
        )

    def has_object_permission(self, request, view, obj):
        # authentication checks have already executed via has_permission
        queryset = self._queryset(view)
        model_cls = queryset.model
        user = request.user

        if obj.has_object_permission(user=user, action=request.action):
            # If the user does not have permissions we need to determine if
            # they have read permissions to see 403, or not, and simply see
            # a 404 response.

            if request.method in SAFE_METHODS:
                # Read permissions already checked and failed, no need
                # to make another lookup.
                raise Http404

            if not obj.has_object_permissions(user=user, action="retrieve"):
                raise Http404

            # Has read permissions.
            return False

        return True
