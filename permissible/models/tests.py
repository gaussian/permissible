"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from django.conf import settings
from django.db import models

from ..models import (
    PermDomain,
    PermRole,
    PermDomainMember,
    PermissibleMixin,
    PermissibleDefaultPerms,
    PermissibleDefaultChildPerms,
)


class TestPermDomain(PermDomain, models.Model):
    groups = models.ManyToManyField("auth.Group", through="TestPermRole")
    users = models.ManyToManyField(
        settings.AUTH_USER_MODEL, through="TestPermDomainMember"
    )

    class Meta:
        permissions = (
            ("add_on_testpermissiblefromroot", "Can add objects on this"),
            ("change_on_testpermissiblefromroot", "Can change objects on this"),
        )
        app_label = "permissible"


class TestPermRole(PermRole, models.Model):
    root = models.ForeignKey("permissible.TestPermDomain", on_delete=models.CASCADE)


class TestPermDomainMember(PermDomainMember, models.Model):
    root = models.ForeignKey(TestPermDomain, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)


class TestPermissibleFromSelf(PermissibleDefaultPerms, PermissibleMixin, models.Model):
    class Meta:
        permissions = (
            ("add_on_testpermissiblefromself", "Can add objects on this"),
            ("change_on_testpermissiblefromself", "Can change objects on this"),
        )


class TestPermissibleFromRoot(
    PermissibleDefaultChildPerms, PermissibleMixin, models.Model
):
    root = models.ForeignKey("TestPermDomain", on_delete=models.CASCADE)

    def get_root_perm_object(self, context=None) -> object:
        return self.root
