"""
Neutron (a Visor module)
Author: Kut Akdogan
(c) 2016- Gaussian Holdings, LLC.

This codebase is confidential and proprietary.
No license for use, viewing, or reproduction without explicit written permission.
"""

from rest_framework.serializers import Serializer
from rest_framework_guardian.serializers import ObjectPermissionsAssignmentMixin


class PermissibleObjectAssignMixin(ObjectPermissionsAssignmentMixin):
    """
    A serializer mixin to assign all possible object permissions for an object
    to the creating user.

    NOTE: object-level permissions (for the request's instance) are created,
          and NOT global permissions (that wouldn't make sense).
    NOTE: no add permission is created for this object, as that doesn't make
          sense either.
    """
    def get_permissions_map(self, created):
        """
        Return a map where keys are permissions and values are list of users
        and/or groups.
        """
        if created:
            model_class = self.instance.__class__
            django_short_perm_codes = ["view", "change", "delete"]
            permissions = [model_class.get_permission_codename(pc) for pc in django_short_perm_codes]
            extra_perms = [perm for perm, _ in model_class._meta.permissions]
            return {perm: self.context["request"].user
                    for perm in permissions + extra_perms}


class PermissibleRootObjectAssignMixin(Serializer):
    """
    A serializer mixin to add the user who creates a `PermRoot` object to
    all the associated groups.

    NOTE: no permissions are assigned - user is simply added to groups
    """

    def save(self, **kwargs):
        created = self.instance is not None

        result = super().save(**kwargs)

        if created:
            self.context["request"].user.groups.add(*list(self.instance.groups))

        return result
