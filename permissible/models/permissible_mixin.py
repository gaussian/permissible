"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from __future__ import annotations

from typing import Type, Optional

from django.contrib.auth.models import PermissionsMixin

from permissible.perm_def import BasePermDefObj, BasePermDef

from .policy_lookup import PolicyLooupMixin


class PermissibleMixin(PolicyLooupMixin, BasePermDefObj):
    """
    Model mixin that allows a model to check permissions, in accordance with
    simple dictionaries (defined in policies.py inside ACTION_POLICIES) that
    configure which permissions are required for each action.

    This mixin allows us to define permission requirements in our Models
    (similarly to how django-rules does it in Model.Meta). Given that different
    view engines (e.g. DRF vs Django's admin) have different implementations for
    checking permissions, this mixin allows us to centralize the permissions
    configuration and keep the code clear and simple.

    This mixin may be leveraged for DRF views by using `PermissiblePerms` in
    your viewsets, or in the Django admin by using `PermissibleAdminMixin`
    in your admin classes.

    Configuration occurs using "global" and "object" dictionaries in the
    ACTION_POLICIES dictionary in the policies.py file for the app. These
    configure permissions for global (i.e. non-object) and object-level
    permissions. Each dictionary maps each action (e.g. "retrieve" or "list") to
    a list of `PermDef` objects which define what it takes to pass the permissions
    check. See `PermDef`.

    Note that permission definitions must be explicitly defined for each action
    in the model's ACTION_POLICIES. If no definition is found, an assertion will
    fail.

    Example ACTION_POLICIES:
    ```
    ACTION_POLICIES = {
        "myapp.MyModel": {
            "global": {
                "list": ALLOW_ALL,
                "retrieve": IS_AUTHENTICATED,
            },
            "object": {
                "retrieve": IS_AUTHENTICATED,
            },
        },
    }
    ```

    This mixin is compatible with django-guardian and others.

    Note that on its own, this model will automatically not do anything. It must
    be used in one of the ways above or in a custom way that calls the functions
    below.

    PermDef checking can be done in two modes: "ANY" or "ALL"
    ANY: only one of the PermDefs must pass for the permission to be granted
    ALL: all of the PermDefs must pass for the permission to be granted
    """

    @classmethod
    def get_domain_attr_paths(cls):
        """
        Return the domain attribute path for this instance, if any, by
        looking at the policy configuration.
        """
        return cls.get_policies().get("domains", None)

    @classmethod
    def get_global_perms_def(cls, action: str) -> Optional[BasePermDef]:
        # Try to get the global action perm map from the policies.py file for this app
        return cls.get_policies().get("global", {}).get(action, None)

    @classmethod
    def get_object_perm_def(cls, action: str) -> Optional[BasePermDef]:
        # Try to get the object action perm map from the policies.py file for this app
        return cls.get_policies().get("object", {}).get(action, None)

    @classmethod
    def has_global_permission(cls, user: PermissionsMixin, action: str, context=None):
        """
        Check if the provided user can access this action for this model, by checking
        the `policies.ACTION_POLICIES[<model_label>]["global"]`.
        In that dictionary, every action has a list of PermDef objects,
        only ONE of which must be satisfied to result in permission success.

        In order for a PermDef to be satisfied, the user must have all of global
        permissions (either directly or through one of its groups) defined by
        `PermDef.short_perm_codes`.

        Permissions are
        If the given action does not exist in the global PermDef, then permission
        FAILS automatically.

        NOTE: the class for which the global permissions are checked is `cls`.

        :param user:
        :param action:
        :param context:
        :return:
        """

        # Superusers override
        if user and user.is_superuser:
            return True

        # Get the PermDef for this action (global permissions)
        # (use "retrieve" if no permission is defined for "list")
        perm_def = cls.get_global_perms_def(action)
        if not perm_def and action == "list":
            perm_def = cls.get_global_perms_def("retrieve")

        # Deny if no EXPLICIT permission check is defined
        assert (
            perm_def is not None
        ), f"No global permission defined for {cls} action '{action}' in `policies.ACTION_POLICIES`"

        # Check permissions on the class
        return perm_def.check_global(
            obj_class=cls,
            user=user,
            context=context or {},
        )

    def has_object_permission(self, user: PermissionsMixin, action: str, context=None):
        """
        Check if the provided user can access this action for this object, by checking
        the `policies.ACTION_POLICIES[<model_label>]["object"]`.
        This check is done in ADDITION to the global check  above, usually.
        In that dictionary, every action has a list of PermDef objects.
        Whether ANY or ALL of them must be satisfied is determined by the `perm_def_mode`.

        In order for a PermDef to be satisfied, the following must BOTH be true:
        1. The user must have all of OBJECT permissions (either directly or through
           one of its groups) defined by `PermDef.short_perm_codes`, where the OBJECT
           to check permissions of is found using `PermDef.obj_getter`, or `self`
           (if the getter does not exist on the PermDef
        2. The object (either `self` or the object found from `PermDef.obj_getter`)
           must cause `PermDef.condition_checker` to return True (or
           `PermDef.condition_checker` must not be set)

        If the given action does not exist in the object-level PermDef, then permission
        FAILS automatically.

        NOTE: the object for which the object permissions are checked is `self`.

        :param user:
        :param action:
        :param context:
        :return:
        """

        # Superusers override
        if user and user.is_superuser:
            return True

        # Get the PermDef for this action (object permissions)
        perm_def = self.get_object_perm_def(action)
        assert (
            perm_def is not None
        ), f"No object permission for {self.__class__.__name__} (action '{action}') in `policies.ACTION_POLICIES`"

        # Check permissions on the object
        return perm_def.check_obj(
            obj=self,
            user=user,
            context=context or {},
        )

    def get_domains(self, type: Optional[Type] = None):
        """
        Return the domain object associated with this instance, if any, by
        looking at the policy configuration.

        If no domain paths are found, return None. Otherwise, return the
        list of domain objects (which may be empty).
        """
        domain_attr_paths = self.get_domain_attr_paths()
        if not domain_attr_paths:
            return None

        # Get the domain objects using the path provided
        domains = [self.get_unretrieved(path) for path in domain_attr_paths]

        # If domains are missing, they are not included in the returned list
        domains = [d for d in domains if d]

        # Filter down to a specific type if requested
        if type:
            domains = [d for d in domains if isinstance(d, type)]

        return domains

    @classmethod
    def get_domain_classes(cls, type: Optional[Type] = None):
        """
        Return the domain class associated with this class, if any, by
        looking at the policy configuration.

        If no domain paths are found, return None. Otherwise, return the
        list of domain classes (which may be empty).
        """
        domain_attr_paths = cls.get_domain_attr_paths()
        if not domain_attr_paths:
            return None

        # Get the domain classes using the path provided
        domain_classes = [cls.get_unretrieved_class(path) for path in domain_attr_paths]

        # If domains are missing, they are not included in the returned list
        domain_classes = [d for d in domain_classes if d]

        # Filter down to a specific type if requested
        if type:
            domain_classes = [d for d in domain_classes if isinstance(d, type)]

        return domain_classes
