"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from django.conf import settings
from rest_framework import serializers, status
from rest_framework.decorators import action
from rest_framework.exceptions import APIException, ValidationError
from rest_framework.fields import empty
from rest_framework.response import Response

from permissible.exceptions import RoleLockoutDenied
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

        assert queryset.model and issubclass(queryset.model, PermissibleMixin), (
            f"Model class must be a subclass of `PermissibleMixin` ({queryset.model})"
        )

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
            assert "permissible.filters.PermissibleFilter" in default_filter_backends, (
                f"View ({view}) must have a filter backend of PermissibleFilter"
            )


class PermDomainMemberViewSetMixin:
    """
    For a `PermDomainMember` viewset. Gate with `make_domain_member_policy`
    ("roles", "destroy") and a global policy that also has "roles".

    - `PUT {id}/roles/` `{"roles": [code]}`: 400 (keyed "roles") for a code not
      in `ROLE_DEFINITIONS`; `set_roles_for_user(by=request.user)`; returns the row.
    - `DELETE {id}/`: `remove_roles_from_user(<held roles>, by=request.user)`,
      then the row. Held, not None: `by` need not be able to revoke every role.
    - `RoleLockoutDenied` -> 409 ("add another manager first"); escalation stays 403.
    """

    @action(detail=True, methods=["put"])
    def roles(self, request, *args, **kwargs):
        member = self.get_object()
        domain = member.get_domain()
        labels = domain.get_role_join_rel().related_model.role_labels()
        field = serializers.ListField(
            child=serializers.ChoiceField(choices=labels.items())
        )
        try:
            roles = field.run_validation(request.data.get("roles", empty))
        except ValidationError as exc:
            raise ValidationError({"roles": exc.detail})
        domain.set_roles_for_user(member.user, roles, by=request.user)
        return Response(self.get_serializer(member).data)

    def perform_destroy(self, instance):
        domain = instance.get_domain()
        held = set(domain.get_roles_for_user(instance.user))
        domain.remove_roles_from_user(instance.user, held, by=self.request.user)
        super().perform_destroy(instance)

    def handle_exception(self, exc):
        if isinstance(exc, RoleLockoutDenied):
            exc = APIException(str(exc), code="lockout")
            exc.status_code = status.HTTP_409_CONFLICT
        return super().handle_exception(exc)
