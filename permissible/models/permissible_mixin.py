"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from __future__ import annotations

from collections import defaultdict
from itertools import chain
from typing import TYPE_CHECKING, Dict, List, Literal, Type, Union, Optional

from django.contrib.auth.models import PermissionsMixin


from .unretrieved_model_mixin import UnRetrievedModelMixin
from permissible.perm_def import ShortPermsMixin, PermDef


class PermissibleMixin(ShortPermsMixin, UnRetrievedModelMixin):
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
    global_action_perm_map: dict[str, list[PermDef]] = {}
    obj_action_perm_map: dict[str, list[PermDef]] = {}

    # PermDef checking can be done in two modes: "ANY" or "ALL"
    PermDefModeType = Literal["ANY", "ALL"]
    perm_def_mode: PermDefModeType = "ANY"

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

        perm_defs = cls.global_action_perm_map.get(action, None)
        if perm_defs is None:
            return True

        # Get the root class for permissions checks
        # (it might not be `cls`!)
        root_perm_class = cls.get_room_perm_class(context=context)
        assert root_perm_class, "No root permissions class found"

        # Check permissions on the ROOT class
        for perm_def in perm_defs:
            check_passes = perm_def.check_global(
                obj_class=root_perm_class,
                user=user,
                context=context,
            )
            if cls.perm_def_mode == "ALL" and not check_passes:
                return False
            elif cls.perm_def_mode == "ANY" and check_passes:
                return True

        # If we reach here, and we're in "ALL" mode, then all checks passed
        if cls.perm_def_mode == "ALL":
            return True

        # If we reach here, and we're in "ANY" mode, then no checks passed
        return False

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
        if not self.global_action_perm_map and not self.obj_action_perm_map:
            raise NotImplementedError(
                "No permissions maps in `PermissibleMixin`, did you mean to define "
                "`obj_action_perm_map` on your model?"
            )

        # Superusers override
        if user and user.is_superuser:
            return True

        context = context or dict()

        perm_defs = self.obj_action_perm_map.get(action, None)
        if perm_defs is None:
            return True

        # Get the root object for permissions checks
        # (it might not be `self`!)
        room_perm_object = self.get_root_perm_object(context=context)

        # If no object to check (but there are perm_defs required), then
        # we can't check permissions, so fail
        if not room_perm_object:
            return False

        # Check permissions on the ROOT object
        return room_perm_object.check_perm_defs(
            mode=self.perm_def_mode,
            user=user,
            perm_defs=perm_defs,
            context=context,
        )

    def check_perm_defs(
        self,
        mode: PermissibleMixin.PermDefModeType,
        user: PermissionsMixin,
        perm_defs: List[PermDef],
        context=None,
    ):
        """
        Check if the provided user can access this action for this object, by checking
        the provided list of `PermDef` objects.

        Override this function if you want to customize the permission check, eg like
        in HierarchicalPermissibleMixin.
        """
        return PermissibleMixin.check_perm_defs_on_obj(
            mode=mode,
            obj=self,
            user=user,
            perm_defs=perm_defs,
            context=context,
        )

    @staticmethod
    def check_perm_defs_on_obj(
        mode: PermissibleMixin.PermDefModeType,
        obj: PermissibleMixin,
        user: PermissionsMixin,
        perm_defs: list[PermDef],
        context=None,
    ):
        """
        Check if the provided user can access this action for this object, by checking
        the provided list of `PermDef` objects.

        Only ONE of the provided `PermDef` objects must be satisfied to result in
        permission success.
        """
        for perm_def in perm_defs:
            check_passes = perm_def.check_obj(
                obj=obj,
                user=user,
                context=context,
            )

            if mode == "ALL" and not check_passes:
                return False
            elif mode == "ANY" and check_passes:
                return True

        # If we reach here, and we're in "ALL" mode, then all checks passed
        if mode == "ALL":
            return True

        # If we reach here, and we're in "ANY" mode, then no checks passed
        return False

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
        which is NOT a PermRoot object.
        """
        try:
            # from .perm_root import PermRoot
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


# class HierarchicalPermissibleMixin(PermissibleMixin, models.Model):
#     """
#     This is the same as PermissibleMixin, but additionally will check permissions
#     all the way up a hierarchy of parent objects, following the parent field.

#     In other words, the permissions check passes if ANY object in the hierarchy,
#     including the original object, passes the permissions check. This makes sense
#     because it's a hierarchy - parent object permissions should confer permissions
#     to the children.
#     """

#     parent = models.ForeignKey(
#         "self",
#         related_name="children",
#         on_delete=models.SET_NULL,
#         null=True,
#         blank=True,
#     )

#     class Meta:
#         abstract = True

#     def check_perm_defs(
#         self,
#         mode: PermissibleMixin.PermDefModeType,
#         user: PermissionsMixin,
#         perm_defs: List[PermDef],
#         context=None,
#     ):
#         # Start with the original object
#         obj_to_check = self

#         # Iterate over objects, checking permissions and proceeding to parent,
#         # until we reach the top (or until we pass the check, in which case we
#         # would have returned True)
#         while obj_to_check is not None:

#             # Check permission on the current object, and return True if it passes
#             if PermissibleMixin.check_perm_defs_on_obj(
#                 mode=mode,
#                 obj=obj_to_check,
#                 user=user,
#                 perm_defs=perm_defs,
#                 context=context,
#             ):
#                 return True

#             # If we don't pass, proceed to the parent object (but get unretrieved)
#             obj_to_check = obj_to_check.get_unretrieved("parent")

#         # If we reach here, no object in the hierarchy passed the check
#         return False
