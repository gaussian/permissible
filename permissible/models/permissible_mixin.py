"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from __future__ import annotations

from collections import defaultdict
from itertools import chain
from typing import TYPE_CHECKING, List, Literal, Type, Optional

from django.contrib.auth.models import PermissionsMixin

from permissible.perm_def import (
    ShortPermsMixin,
    LazyModelResolverMixin,
    PermDef,
    CompositePermDef,
)

from .policy_lookup import PolicyLooupMixin


class PermissibleMixin(PolicyLooupMixin, ShortPermsMixin, LazyModelResolverMixin):
    """
    Model mixin that allows a model to check permissions, in accordance with
    simple dictionaries (`global_action_perm_map` and `obj_action_perm_map`)
    that configure which permissions are required for each action.

    This mixin allows us to define permission requirements in our Models
    (similarly to how django-rules does it in Model.Meta). Given that different
    view engines (e.g. DRF vs Django's admin) have different implementations for
    checking permissions, this mixin allows us to centralize the permissions
    configuration and keep the code clear and simple.

    This mixin may be leveraged for DRF views by using `PermissiblePerms` in
    your viewsets, or in the Django admin by using `PermissibleAdminMixin`
    in your admin classes.

    Configuration occurs using `global_action_perm_map` and `obj_action_perm_map`,
    which configure permissions for global (i.e. non-object) and object-level
    permissions. Each dictionary maps each action (e.g. "retrieve" or "list") to
    a list of `PermDef` objects which define what it takes to pass the permissions
    check. See `PermDef`.

    This mixin is compatible with django-guardian and others.

    Note that on its own, this model will automatically not do anything. It must
    be used in one of the ways above or in a custom way that calls the functions
    below.

    PermDef checking can be done in two modes: "ANY" or "ALL"
    ANY: only one of the PermDefs must pass for the permission to be granted
    ALL: all of the PermDefs must pass for the permission to be granted
    """

    # See description above
    global_action_perm_map: dict[str, PermDef | CompositePermDef] = {}
    obj_action_perm_map: dict[str, PermDef | CompositePermDef] = {}

    @classmethod
    def get_global_perm_map(cls):
        # Try to get the global action perm map from the policies.py file for this app
        global_action_perm_map = cls.get_policies().get("global", None)
        if global_action_perm_map is None:
            global_action_perm_map = cls.global_action_perm_map
        return global_action_perm_map

    @classmethod
    def get_object_perm_map(cls):
        # Try to get the object action perm map from the policies.py file for this app
        obj_action_perm_map = cls.get_policies().get("object", None)
        if obj_action_perm_map is None:
            obj_action_perm_map = cls.obj_action_perm_map
        return obj_action_perm_map

    @classmethod
    def has_global_permission(cls, user: PermissionsMixin, action: str, context=None):
        """
        Check if the provided user can access this action for this model, by checking
        the `global_action_perm_map`.

        In the `global_action_perm_map`, every action has a list of PermDef objects,
        only ONE of which must be satisfied to result in permission success.

        In order for a PermDef to be satisfied, the user must have all of global
        permissions (either directly or through one of its groups) defined by
        `PermDef.short_perm_codes`.

        If the given action does not exist in the `global_action_perm_map`, then
        permission is granted automatically.

        NOTE: the class for which the global permissions are checked is, by default,
        `cls`. If you want to check permissions on a related object, you must
        override `get_root_perm_class` to return the class you want to check.

        :param user:
        :param action:
        :param context:
        :return:
        """
        # Superusers override
        if user and user.is_superuser:
            return True

        perm_def = cls.get_global_perm_map.get(action, None)
        if perm_def is None:
            return True

        # Get the root class for permissions checks
        # (it might not be `cls`!)
        root_perm_class = cls.get_room_perm_class(context=context)
        assert root_perm_class, "No root permissions class found"

        # Check permissions on the ROOT class
        return perm_def.check_global(
            obj_class=root_perm_class,
            user=user,
            context=context,
        )

    def has_object_permission(self, user: PermissionsMixin, action: str, context=None):
        """
        Check if the provided user can access this action for this object, by checking
        the `obj_action_perm_map`. This check is done in ADDITION to the global check
        above, usually.

        In the `obj_action_perm_map`, every action has a list of PermDef objects.
        Whether ANY or ALL of them must be satisfied is determined by the `perm_def_mode`.

        In order for a PermDef to be satisfied, the following must BOTH be true:
        1. The user must have all of OBJECT permissions (either directly or through
           one of its groups) defined by `PermDef.short_perm_codes`, where the OBJECT
           to check permissions of is found using `PermDef.obj_getter`, or `self`
           (if the getter does not exist on the PermDef
        2. The object (either `self` or the object found from `PermDef.obj_getter`)
           must cause `PermDef.condition_checker` to return True (or
           `PermDef.condition_checker` must not be set)

        If the given action does not exist in the `obj_action_perm_map`, then
        permission is granted automatically.

        NOTE: the object for which the object permissions are checked is, by default,
        `self`. If you want to check permissions on a related object, you must
        override `get_root_perm_object` to return the object you want to check.

        :param user:
        :param action:
        :param context:
        :return:
        """

        # Try to get the global action perm map from the policies.py file for this app
        obj_action_perm_map = self.get_object_perm_map()

        if not obj_action_perm_map and not self.get_global_perm_map():
            raise NotImplementedError(
                f"No permissions maps in `PermissibleMixin` or policies in policies.py, did you mean to define `obj_action_perm_map` on your model ({self.__class__})?"
            )

        # Superusers override
        if user and user.is_superuser:
            return True

        context = context or dict()

        perm_def = self.obj_action_perm_map.get(action, None)
        if perm_def is None:
            return True

        # Get the root object for permissions checks
        # (it might not be `self`!)
        room_perm_object = self.get_root_perm_object(context=context)

        # If no object to check (but there are perm_defs required), then
        # we can't check permissions, so fail
        if not room_perm_object:
            return False

        # Check permissions on the ROOT object
        return perm_def.check_obj(
            obj=room_perm_object,
            user=user,
            context=context,
        )

    def get_root_perm_object(self, context=None) -> Optional[PermissibleMixin]:
        """
        Retrieve the "root permissions object" for this object, which is the object
        against which permissions are checked.

        Clearly, by default, this is the object itself, but by overriding this, you
        can customize the root object used for permission checks.

        For instance, you might allow permissions on a Team to confer permissions to
        records owned by that Team, such as projects, documents, etc.
        """
        return self

    @classmethod
    def get_room_perm_class(cls, context=None) -> Type[PermissibleMixin]:
        """
        Get the class of the root permissions object for this object.
        """
        return cls

    @classmethod
    def get_root_perm_object_from_data(cls, data):
        """
        Look at the data provided to find the "permissions root" object,
        and return it if it exists.

        Note that sometimes, get_root_perm_object() returns a User,
        which is NOT a PermDomain object.
        """
        try:
            data_as_obj = cls.make_objs_from_data(data)[0]
            root_obj = data_as_obj.get_root_perm_object()
            return root_obj
        except (IndexError, AttributeError):
            pass

        return None

    @staticmethod
    def merge_action_perm_maps(*perm_maps):
        """
        Convenience function to merge two perm_maps (either "global_" or "obj_").

        Note that this essentially does a "union" of the permissions, and if any
        of the perm_maps allow a permission, then it is allowed. So this is
        necessarily more permissive than any of the individual perm_maps.

        :param perm_maps:
        :return:
        """
        result = defaultdict(list)
        keys = set(chain(*[pm.keys() for pm in perm_maps]))
        for key in keys:
            for perm_map in perm_maps:
                result[key] += perm_map.get(key, [])
        return result
