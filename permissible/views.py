"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from django.conf import settings

from permissible.models.permissible_mixin import PermissibleMixin


class CheckViewConfigMixin:
    @staticmethod
    def is_detail_view(view):
        if view.detail is not None:
            return view.detail
        return view.kwargs.get("pk", None) is not None

    def _check_view_config(self, view, queryset):
        from .filters import PermissibleFilter
        from .permissions import PermissiblePerms

        assert queryset.model and issubclass(
            queryset.model, PermissibleMixin
        ), f"Model class must be a subclass of `PermissibleMixin` ({queryset.model})"

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
