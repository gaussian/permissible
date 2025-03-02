"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from .perm_def import p


ALLOW_ALL = p([])
DENY_ALL = p(None)

IS_AUTHENTICATED = p([], condition_checker=lambda o, u, c: bool(u.pk))
IS_PUBLIC = p([], condition_checker=lambda o, u, c: o.is_public)
