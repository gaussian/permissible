"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from rest_framework import serializers, status
from rest_framework.decorators import action
from rest_framework.exceptions import APIException, MethodNotAllowed, ValidationError
from rest_framework.fields import empty
from rest_framework.response import Response

from permissible.exceptions import RoleGrantRefused, RoleLockoutDenied


class PermDomainMemberViewSetMixin:
    """
    For a `PermDomainMember` viewset, which should not expose create/destroy: a
    row exists while its user holds a role. Gate with `make_domain_member_policy`
    ("roles") and a global policy that also has "roles".

    - `PUT {id}/roles/` `{"roles": [code]}`: 400 (keyed "roles") for a code not
      in `ROLE_DEFINITIONS`; `set_roles_for_user(by=request.user)`; returns the row.
    - `DELETE {id}/roles/`: `remove_roles_from_user(None, by=request.user)`
      (guarded on the held roles only), then deletes the row; 204.
    - `DELETE {id}/` -> 405 pointing at `DELETE {id}/roles/`.
    - `RoleLockoutDenied` -> 409 ("add another manager first"); escalation stays 403.
    - `RoleGrantRefused` -> 409 `{"code": exc.code, "detail": str(exc), **exc.fields}`.
    """

    @action(detail=True, methods=["put", "delete"])
    def roles(self, request, *args, **kwargs):
        """Set the member's roles (PUT), or strip them all (DELETE), which also
        ends the membership: the row exists only while it holds a role."""
        member = self.get_object()
        domain = member.get_domain()
        if request.method == "DELETE":
            domain.remove_roles_from_user(member.user, None, by=request.user)
            member.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
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

    # Not `http_method_not_allowed`: permission checks in `initial()` deny an
    # unmapped method (`action is None`) with 403 before that could run.
    def initial(self, request, *args, **kwargs):
        if self.action is None and request.method == "DELETE" and kwargs:
            raise MethodNotAllowed(
                "DELETE",
                detail=f"Use DELETE {request.path.rstrip('/')}/roles/ to remove "
                "a member: it strips their roles, which ends the membership.",
            )
        super().initial(request, *args, **kwargs)

    def handle_exception(self, exc):
        if isinstance(exc, RoleGrantRefused):
            exc = APIException({"code": exc.code, "detail": str(exc), **exc.fields})
            exc.status_code = status.HTTP_409_CONFLICT
        elif isinstance(exc, RoleLockoutDenied):
            exc = APIException(str(exc), code="lockout")
            exc.status_code = status.HTTP_409_CONFLICT
        return super().handle_exception(exc)
