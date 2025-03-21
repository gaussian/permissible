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

        # Get the actual module path of the class (works better for third-party libraries)
        module_path = cls.__module__
        module_parts = module_path.split(".")
        base_module = module_parts[0]  # Top-level package name

        # Lookup paths to try in order of preference
        paths_to_try = [
            f"{app_label}.policies",  # Django app_label based
            f"{app_label}.models.policies",  # Alternative app_label location
            # f"{base_module}.policies",          # Top-level package policies
            f"{'.'.join(module_parts[:-1])}.policies",  # Adjacent to model module
        ]

        # Try each path
        for path in paths_to_try:
            try:
                return importlib.import_module(path)
            except ImportError:
                continue

        # If all attempts fail, log the issue
        print(
            f"No policies module found for {app_label} ({cls}) - tried: {paths_to_try}"
        )
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
            print(f"No ACTION_POLICIES found in {module}")
            return {}

        # Get the full model name for lookup
        full_model_name = f"{cls._meta.app_label}.{cls.__name__}"

        # Return empty dict if model not in policies

        return policies.get(
            full_model_name, {}
        ).copy()  # Return a copy to avoid cache issues
