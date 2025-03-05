"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

import importlib
from functools import lru_cache


class PolicyLooupMixin:
    @classmethod
    def get_app_policies_module(cls):
        """
        Dynamically find and import the policies module from the app
        where the model is defined using the model's app_label.

        Uses lru_cache for performance optimization.
        """
        # Get the app_label directly from the model's _meta
        app_label = cls._meta.app_label

        # Try to import the policies module from the app
        try:
            return importlib.import_module(f"{app_label}.policies")
        except ImportError:
            # Try alternative location
            try:
                return importlib.import_module(f"{app_label}.models.policies")
            except ImportError:
                return None

    @classmethod
    @lru_cache(maxsize=None)
    def get_policies(cls) -> dict:
        """
        Return the policies for this model from the app's ACTION_POLICIES.
        """
        # Get policies module
        module = cls.get_app_policies_module()
        if not module:
            return {}

        # Get ACTION_POLICIES
        policies = getattr(module, "ACTION_POLICIES", None)
        if not policies:
            return {}

        # Get the full model name for lookup
        full_model_name = f"{cls._meta.app_label}.{cls.__name__}"

        # Return empty dict if model not in policies

        return policies.get(
            full_model_name, {}
        ).copy()  # Return a copy to avoid cache issues
