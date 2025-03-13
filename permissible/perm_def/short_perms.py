"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""


class ShortPermsMixin(object):
    @classmethod
    def get_permission_codename(
        cls,
        short_permission: str,
        include_app_label: bool,
    ):
        app_label_prefix = f"{cls._meta.app_label}." if include_app_label else ""
        return f"{app_label_prefix}{short_permission}_{cls._meta.model_name}"

    @classmethod
    def get_permission_codenames(
        cls,
        short_permissions: list[str],
        include_app_label: bool,
    ):
        return [
            cls.get_permission_codename(sp, include_app_label)
            for sp in short_permissions
        ]
