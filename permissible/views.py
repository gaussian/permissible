"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from rest_framework import serializers, status
from rest_framework.decorators import action
from rest_framework.exceptions import APIException, ValidationError
from rest_framework.fields import empty
from rest_framework.response import Response

from permissible.exceptions import RoleGrantRefused, RoleLockoutDenied


class PermDomainMemberViewSetMixin:
    """
    For a `PermDomainMember` viewset. Gate with `make_domain_member_policy`
    ("roles", "destroy") and a global policy that also has "roles".

    - `PUT {id}/roles/` `{"roles": [code]}`: 400 (keyed "roles") for a code not
      in `ROLE_DEFINITIONS`; `set_roles_for_user(by=request.user)`; returns the row.
    - `DELETE {id}/`: `remove_roles_from_user(None, by=request.user)` (guarded
      on the held roles only), then the row.
    - `RoleLockoutDenied` -> 409 ("add another manager first"); escalation stays 403.
    - `RoleGrantRefused` -> 409 `{"code": exc.code, "detail": str(exc)}`.
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
        domain.remove_roles_from_user(instance.user, None, by=self.request.user)
        super().perform_destroy(instance)

    def handle_exception(self, exc):
        if isinstance(exc, RoleGrantRefused):
            exc = APIException({"code": exc.code, "detail": str(exc)})
            exc.status_code = status.HTTP_409_CONFLICT
        elif isinstance(exc, RoleLockoutDenied):
            exc = APIException(str(exc), code="lockout")
            exc.status_code = status.HTTP_409_CONFLICT
        return super().handle_exception(exc)
