"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from abc import ABCMeta
from typing import Iterable, Tuple

from django.db import models


class AbstractModelMetaclass(ABCMeta, models.base.ModelBase):
    pass


class ExtraPermModelMetaclass(models.base.ModelBase):
    """
    Metaclass to allow model to automatically create extra permissions.
    """

    permission_definitions = ()  # type: Iterable[Tuple[str, str]]

    def __new__(mcs, name, bases, attrs):
        new_class = super().__new__(mcs, name, bases, attrs)

        # Skip permission addition for abstract classes.
        if new_class._meta.abstract:
            return new_class

        new_class._meta.permissions = new_class._meta.permissions or tuple()
        new_class._meta.permissions += tuple(
            (
                codename.format(new_class._meta.model_name),
                description.format(new_class._meta.verbose_name),
            )
            for codename, description in mcs.permission_definitions
        )
        new_class._meta.original_attrs["permissions"] = new_class._meta.permissions

        return new_class
