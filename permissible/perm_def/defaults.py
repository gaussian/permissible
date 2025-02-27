"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from .perm_def import PermDef


ALLOW_ALL = PermDef([])
DENY_ALL = PermDef(None)

IS_AUTHENTICATED = PermDef(None, condition_checker=lambda o, u, c: bool(u.pk))
IS_PUBLIC = PermDef(None, condition_checker=lambda o, u, c: o.is_public)
