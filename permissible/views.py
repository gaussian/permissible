"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from django.http import Http404
from rest_framework import serializers, status
from rest_framework.decorators import action
from rest_framework.exceptions import APIException, MethodNotAllowed, ValidationError
from rest_framework.fields import empty
from rest_framework.generics import get_object_or_404
from rest_framework.response import Response

from permissible.exceptions import RoleGrantRefused, RoleLockoutDenied


class PermDomainViewSetMixin:
    """For a `PermDomain` viewset; its policies need a "user_roles" entry."""

    @action(
        detail=True,
        methods=["put", "delete"],
        url_path=r"users/(?P<user_id>[^/.]+)/roles",
    )
    def user_roles(self, request, user_id, *args, **kwargs):
        """
        `PUT` `{"roles": [code]}` sets an existing member's roles (400 keyed "roles"
        on an unknown code). `DELETE` strips them all, which also ends the
        membership: the row exists only while it holds a role; 204. A non-member
        gets 404. Escalation 403; lockout 409; `RoleGrantRefused` 409 `{"code",
        "detail", **fields}`.
        """
        domain = self.get_object()
        try:  # one 404 body, whether `user_id` is malformed, unknown or not a member
            member = get_object_or_404(domain.get_user_joins(), user_id=user_id)
        except Http404:
            raise Http404
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
        return Response({"roles": sorted(domain.get_roles_for_user(member.user))})

    def handle_exception(self, exc):
        if isinstance(exc, RoleGrantRefused):
            exc = APIException({"code": exc.code, "detail": str(exc), **exc.fields})
            exc.status_code = status.HTTP_409_CONFLICT
        elif isinstance(exc, RoleLockoutDenied):
            exc = APIException(str(exc), code="lockout")
            exc.status_code = status.HTTP_409_CONFLICT
        return super().handle_exception(exc)


class PermDomainMemberViewSetMixin:
    """For a `PermDomainMember` viewset: list/retrieve/update only."""

    # Not `http_method_not_allowed`: permission checks in `initial()` deny an
    # unmapped method (`action is None`) with 403 before that could run.
    def initial(self, request, *args, **kwargs):
        if self.action is None and request.method == "DELETE" and kwargs:
            domain = self.get_queryset().model.get_domain_field().name
            raise MethodNotAllowed(
                "DELETE",
                detail=f"Use DELETE {{{domain}_id}}/users/{{user_id}}/roles/ on the "
                f"{domain} to remove a member: it strips their roles, which ends "
                "the membership.",
            )
        super().initial(request, *args, **kwargs)
