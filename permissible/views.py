"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from django.conf import settings
from rest_framework.permissions import IsAuthenticated

from permissible.models.permissible_mixin import PermissibleMixin


class NoPermissionsIfListMixin:
    def get_permissions(self):
        # For certain actions, don't bother checking for permissions, as
        # we filter down the objects that are returned (listing/searching),
        # or check permissions some other way
        list_actions = getattr(self, "LIST_ACTIONS", ("list",))
        if self.action in list_actions:
            return [IsAuthenticated()]
        return super().get_permissions()


class CheckViewConfigMixin:
    @staticmethod
    def is_detail_view(view):
        if view.detail is not None:
            return view.detail
        return view.kwargs.get("pk", None) is not None

    def _check_view_config(self, view):
        from .filters import PermissibleFilter
        from .permissions import PermissiblePerms

        assert hasattr(
            view, "base_model"
        ), f"View must have a `base_model` attribute pointing to the model class ({view})"

        assert issubclass(
            view.base_model, PermissibleMixin
        ), f"Model class must be a subclass of `PermissibleMixin` ({view.base_model})"

        # Check that view has permission_classes with PermissiblePerms, OR
        # if permission_classes is empty then check the default permission_classes
        permission_classes = getattr(view, "permission_classes", [])
        if permission_classes:
            assert any(
                [
                    issubclass(permission, PermissiblePerms)
                    for permission in permission_classes
                ]
            ), f"View ({view}) must have a permission class of PermissiblePerms"
        else:
            default_permission_classes = getattr(
                settings, "REST_FRAMEWORK", dict()
            ).get("DEFAULT_PERMISSION_CLASSES", [])
            assert (
                "permissible.permissions.PermissiblePerms" in default_permission_classes
            ), f"View ({view}) must have a permission class of PermissiblePerms"

        # Check that view has filter_backends with PermissibleFilter
        filter_backends = getattr(view, "filter_backends", [])
        if filter_backends:
            assert any(
                [issubclass(backend, PermissibleFilter) for backend in filter_backends]
            ), f"View ({view}) must have a filter backend of PermissibleFilter"
        else:
            default_filter_backends = getattr(settings, "REST_FRAMEWORK", dict()).get(
                "DEFAULT_FILTER_BACKENDS", []
            )
            assert (
                "permissible.filters.PermissibleFilter" in default_filter_backends
            ), f"View ({view}) must have a filter backend of PermissibleFilter"
