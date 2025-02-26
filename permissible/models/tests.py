"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from django.conf import settings
from django.db import models

from ..models import (
    PermDomain,
    PermDomainRole,
    PermDomainMember,
    PermissibleMixin,
    PermissibleDefaultPerms,
    PermissibleDefaultChildPerms,
)


class TestPermDomain(PermDomain, models.Model):
    groups = models.ManyToManyField("auth.Group", through="TestPermDomainRole")
    users = models.ManyToManyField(
        settings.AUTH_USER_MODEL, through="TestPermDomainMember"
    )

    class Meta:
        permissions = (
            ("add_on_testpermissiblefromdomain", "Can add objects on this"),
            ("change_on_testpermissiblefromdomain", "Can change objects on this"),
        )
        app_label = "permissible"


class TestPermDomainRole(PermDomainRole, models.Model):
    domain = models.ForeignKey("permissible.TestPermDomain", on_delete=models.CASCADE)


class TestPermDomainMember(PermDomainMember, models.Model):
    domain = models.ForeignKey(TestPermDomain, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)


class TestPermissibleFromSelf(PermissibleDefaultPerms, PermissibleMixin, models.Model):
    class Meta:
        permissions = (
            ("add_on_testpermissiblefromself", "Can add objects on this"),
            ("change_on_testpermissiblefromself", "Can change objects on this"),
        )


class TestPermissibleFromDomain(
    PermissibleDefaultChildPerms, PermissibleMixin, models.Model
):
    domain = models.ForeignKey("TestPermDomain", on_delete=models.CASCADE)

    def get_root_perm_object(self, context=None) -> object:
        return self.domain
