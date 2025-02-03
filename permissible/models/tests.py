"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from django.conf import settings
from django.db import models

from ..models import PermRoot, PermRootGroup, PermRootUser, PermissibleMixin, PermissibleSelfOnlyMixin, \
    PermissibleRootOnlyMixin


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


class TestPermissibleFromSelf(PermissibleSelfOnlyMixin, PermissibleMixin, models.Model):
    class Meta:
        permissions = (
            ("add_on_testpermissiblefromself", "Can add objects on this"),
            ("change_on_testpermissiblefromself", "Can change objects on this"),
        )


class TestPermissibleFromRoot(PermissibleRootOnlyMixin, PermissibleMixin, models.Model):
    root = models.ForeignKey("TestPermRoot", on_delete=models.CASCADE)

    def get_permissions_root_obj(self, context=None) -> object:
        return self.root
