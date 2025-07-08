"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Type

from django.http import Http404
from rest_framework import permissions

from permissible.utils.views import make_context_from_request
from permissible.views import CheckViewConfigMixin

if TYPE_CHECKING:
    from permissible.models import PermissibleMixin


class PermissiblePerms(CheckViewConfigMixin, permissions.DjangoModelPermissions):
    """
    Restricts DRF access to on an object using advanced configuration.

    Models that are to be protected in this way should use `PermissibleMixin`, and
    the necessary permissions should be configured using
    `policies.ACTION_POLICIES[<model_label>]`.

    Must pass global AND object permissions.

    Requires use of an object-level permissions library/schema such as
    django-guardian.

    NOTE: much is copied from `permissions.DjangoObjectPermissions`.
    """

    def has_permission(self, request, view):
        """
        Global permissions check (i.e. not object specific). Runs for all
        actions.

        Return `True` if permission is granted, `False` otherwise.

        All permissions checks (including this) must pass for permission to
        be granted.
        """

        # We require PermissibleFilter to be used on the view
        queryset = self._queryset(view)
        self._check_view_config(view, queryset)

        assert getattr(
            request, "user", None
        ), "User object must be available in request for PermissiblePerms"

        # Workaround to ensure DjangoModelPermissions are not applied
        # to the root view when using DefaultRouter.
        if getattr(view, "_ignore_model_permissions", False):
            return True

        model_class: Type[PermissibleMixin] = queryset.model
        perm_check_kwargs = {
            "user": request.user,
            "action": view.action,
            "context": make_context_from_request(request),
        }

        # Check if user has permission to do this action on this model type
        if not model_class.has_global_permission(**perm_check_kwargs):
            return False

        # Global permission check suceeeded - but now do additional checks for
        # certain non-detail actions (i.e. actions that do not have an instance,
        # and so will not call `has_object_permission` below).
        # We only do this for "create" actions (or similar, where there there is
        # request.data). We do NOT do it for "list" actions, as these are
        # expected to be filtered by the filter backend.

        if not self.is_detail_view(view) and request.data:
            # We must create a dummy object from request data and pass it into
            # `has_object_permission`, as this function will normally not be called
            # NOTE: multiple objects are allowed, hence the list of objects checked
            return all(
                self.has_object_permission(request=request, view=view, obj=o)
                for o in model_class.make_objs_from_data(request.data)
            )

        return True

    def has_object_permission(self, request, view, obj: PermissibleMixin):
        """
        Object-specific permissions check. Runs for any actions where the
        primary key is present (e.g. "retrieve", "update", "destroy").

        Return `True` if permission is granted, `False` otherwise.

        All permissions checks (including this AND `has_permission` above)
        must pass for permission to be granted.
        """

        assert getattr(
            request, "user", None
        ), "User object must be available in request for PermissiblePerms"

        queryset = self._queryset(view)
        model_cls = queryset.model
        user = request.user
        context = make_context_from_request(request)

        # Check if user has permission to do this action on this object
        if not obj.has_object_permission(
            user=user, action=view.action, context=context
        ):
            # PERMISSION CHECK FAILED

            # If user is not authenticated, then return False to raise a 403
            # (instead of 404 per the logic below)
            if not user.is_authenticated:
                return False

            # If the user does not have permissions we need to determine if
            # they have read permissions to see 403, or not, and simply see
            # a 404 response
            # NOTE: object MUST EXIST for a 404 to be thrown (might not be the case,
            # e.g. if we're checking during "create" action)

            if obj._state.adding:
                return False

            if view.action in ("retrieve",):
                # Read permissions already checked and failed, no need
                # to make another lookup.
                raise Http404

            if not obj.has_object_permission(
                user=user, action="retrieve", context=context
            ):
                raise Http404

            # Has read permissions.
            return False

        return True
