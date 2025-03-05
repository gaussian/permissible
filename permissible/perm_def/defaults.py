"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from .perm_def import p


ALLOW_ALL = p([])
DENY_ALL = p(None)

IS_AUTHENTICATED = p([], global_condition_checker=lambda u, c: bool(u.pk))
IS_PUBLIC = p([], obj_filter=("is_public", "==", True))
