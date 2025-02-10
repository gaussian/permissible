"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from django.conf import settings
from django.db import models

from ..models import (
    PermRoot,
    PermRootGroup,
    PermRootUser,
    PermissibleMixin,
    PermissibleDefaultPerms,
    PermissibleDefaultChildPerms,
)


class TestPermRoot(PermRoot, models.Model):
    groups = models.ManyToManyField("auth.Group", through="TestPermRootGroup")
    users = models.ManyToManyField(settings.AUTH_USER_MODEL, through="TestPermRootUser")

    class Meta:
        permissions = (
            ("add_on_testpermissiblefromroot", "Can add objects on this"),
            ("change_on_testpermissiblefromroot", "Can change objects on this"),
        )
        app_label = "permissible"


class TestPermRootGroup(PermRootGroup, models.Model):
    root = models.ForeignKey("permissible.TestPermRoot", on_delete=models.CASCADE)


class TestPermRootUser(PermRootUser, models.Model):
    root = models.ForeignKey(TestPermRoot, on_delete=models.CASCADE)
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
    root = models.ForeignKey("TestPermRoot", on_delete=models.CASCADE)

    def get_root_perm_object(self, context=None) -> object:
        return self.root
