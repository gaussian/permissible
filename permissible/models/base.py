"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from django.db import models

from .permissible_mixin import PermissibleMixin
from .metaclasses import AbstractModelMetaclass, ExtraPermModelMetaclass


class PermRootModelMetaclass(ExtraPermModelMetaclass, AbstractModelMetaclass):
    permission_definitions = (
        ("add_on_{}", "Can add related records onto {}"),
        ("change_on_{}", "Can change related records on {}"),
        ("change_permission_{}", "Can change permissions of {}"),
    )


class BasePermRoot(PermissibleMixin, models.Model, metaclass=PermRootModelMetaclass):
    """
    A model that acts as the root for a permission hierarchy. This model is primarily
    used as a base class for PermRoot (which has considerable functionality), but
    can also be used directly as a way to add root object permissions without
    the associated PermRootGroup and PermRootUser models and functionality.
    """
    class Meta:
        abstract = True
