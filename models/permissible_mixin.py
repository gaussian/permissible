"""
Neutron (a Visor module)
Author: Kut Akdogan
(c) 2016- Gaussian Holdings, LLC.

This codebase is confidential and proprietary.
No license for use, viewing, or reproduction without explicit written permission.
"""

from collections import defaultdict
from itertools import chain
from typing import Dict, List

from django.contrib.auth.models import PermissionsMixin


class PermDef:
    """
    A simple data structure to hold instructions for permissions configuration.

    Examples:
        PermDef(["change"], obj_getter=PermissibleMixin.get_permissions_root_obj
        PermDef(["view"], obj_getter=lambda o: o.project.team)
        PermDef([], condition_checker=lambda o, u: o.is_public)
        PermDef(["view", "change"], condition_checker=lambda o, u: not o.is_public and u.is_superuser)
    """

    def __init__(self, short_perm_codes, obj_getter=None, condition_checker=None):
        """
        Initialize.
        :param short_perm_codes: A list of short permission codes, e.g. ["view", "change"]
        :param obj_getter: A function that takes an initial object and returns its root
        object, e.g. a "survey" might be the root of "survey question" objects
        :param condition_checker: A function that takes an object and the user, and
        returns a boolean, which is AND'd with the result of user.has_perms to return
        whether permission is successful
        """
        self.short_perm_codes = short_perm_codes
        self.obj_getter = obj_getter
        self.condition_checker = condition_checker


class PermissibleMixin(object):
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
    """

    # See description above
    global_action_perm_map = {}     # type: Dict[str, List[PermDef]]
    obj_action_perm_map = {}        # type: Dict[str, List[PermDef]]

    @classmethod
    def get_permission_codename(cls, short_permission):
        return f"{cls._meta.app_label}.{short_permission}_{cls._meta.model_name}"

    @classmethod
    def get_permission_codenames(cls, short_permissions):
        return [cls.get_permission_codename(sp) for sp in short_permissions]

    @classmethod
    def has_global_and_create_permission(cls, user: PermissionsMixin, action: str, obj_dict=None):
        if not cls.has_global_permission(user, action):
            return False
        if action == "create":
            return cls.has_create_permission(user, obj_dict)
        return True

    @classmethod
    def has_global_permission(cls, user: PermissionsMixin, action: str):
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


        :param user:
        :param action:
        :return:
        """
        perm_defs = cls.global_action_perm_map.get(action, None)
        if perm_defs is None:
            return True

        for perm_def in perm_defs:
            perms = cls.get_permission_codenames(perm_def.short_perm_codes)
            if user.has_perms(perms):
                return True

        return False

    @classmethod
    def has_create_permission(cls, user: PermissionsMixin, obj_dict=None):
        """
        Specifically for the "create" action, check if the provided user can do this,
        the `obj_action_perm_map`. This is like `has_object_permissions` except
        we have to create the object instance as we don't have it - we only have a
        dict representing the object we want to create.

        :param user:
        :param obj_dict:
        :return:
        """

        # Create temporary object (not for saving, just for permission checking)
        obj = cls(**obj_dict)

        # Run object permissions as usual
        return obj.has_object_permission(user, "create")

    def has_object_permission(self, user: PermissionsMixin, action: str):
        """
        Check if the provided user can access this action for this object, by checking
        the `obj_action_perm_map`. This check is done in ADDITION to the global check
        above, usually.

        In the `obj_action_perm_map`, every action has a list of PermDef objects, only
        ONE of which must be satisfied to result in permission success.

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

        :param user:
        :param action:
        :return:
        """
        if not self.global_action_perm_map and not self.obj_action_perm_map:
            raise NotImplementedError("No permissions maps in `PermissibleMixin`, did you mean to define "
                                      "`obj_action_perm_map` on your model?")

        perm_defs = self.obj_action_perm_map.get(action, None)
        if perm_defs is None:
            return True

        for perm_def in perm_defs:
            if perm_def.obj_getter:
                obj = perm_def.obj_getter(self)
            else:
                obj = self
            if perm_def.condition_checker:
                obj_check_passes = perm_def.condition_checker(obj, user)
            else:
                obj_check_passes = True
            if perm_def.short_perm_codes is None:
                has_perms = True
            else:
                perms = obj.get_permission_codenames(perm_def.short_perm_codes)
                has_perms = user.has_perms(perms, obj)
            if has_perms and obj_check_passes:
                return True

        return False

    def get_permissions_root_obj(self) -> object:
        """
        Convenience function to retrieve a root object against which permissions
        can be checked.

        For instance, if a "survey" is the root for "survey question", then
        allow creation of "survey questions" if the "change" permission exists
        for the "survey".

        The use of this function is optional, though derived classes make use of this.
        """
        raise NotImplementedError

    def get_unretrieved(self, attr_name):
        field = getattr(self.__class__, attr_name).field
        model_class = field.related_model
        pk = getattr(self, field.attname)
        return model_class(pk=pk)

    def get_unretrieved_nested(self, attr_name, attr_name_nested):
        field = getattr(self.__class__, attr_name).field
        model_class = field.related_model
        field_name = field.attname
        nested_field = getattr(self.__class__, attr_name_nested).field
        nested_model_class = nested_field.related_model
        nested_pk = getattr(self, nested_field.attname)
        pk = nested_model_class.objects.filter(pk=nested_pk).values_list(field_name, flat=True)[0]
        return model_class(pk=pk)

    @staticmethod
    def merge_action_perm_maps(*perm_maps):
        """
        Convenience function to merge two perm_maps (either "global_" or "obj_")

        :param perm_maps:
        :return:
        """
        result = defaultdict(list)
        keys = set(chain(*[pm.keys() for pm in perm_maps]))
        for key in keys:
            for perm_map in perm_maps:
                result[key] += perm_map.get(key, [])
        return result


class PermissibleSelfOnlyMixin(object):
    """
    A default configuration of permissions that ONLY checks for object-level
    permissions on the object that we are trying to access.

    Note that no global checks are done.
    Note that no "list" permission checks are done (inaccessible objects
    should be filtered out instead, using
    `rest_framework_guardian.ObjectPermissionsFilter`).
    Note that no "create" permission checks are done (cannot check object
    permissions on an object that hasn't been created yet).
    """

    obj_action_perm_map = {
        "retrieve": [PermDef(["view"])],
        "update": [PermDef(["change"])],
        "partial_update": [PermDef(["change"])],
        "delete": [PermDef(["delete"])],
    }

    def get_permissions_root_obj(self) -> object:
        return self


class PermissibleRootOnlyMixin(PermissibleMixin):
    """
    A default configuration of permissions that ONLY checks for object-level
    permissions on the ROOT of the object that we are trying to access.

    Note that having "change" permission on the root object confers "create"
    permission on the original (child) object.

    Note that no global checks are done.
    Note that no "list" permission checks are done (permissions checks should
    instead be done on the root object, in the "list" action, via
    `permissible.PermissibleRootPermissionsFilter`).
    """

    obj_action_perm_map = {
        "create": [PermDef(["add_on"], obj_getter=PermissibleMixin.get_permissions_root_obj)],
        "retrieve": [PermDef(["view"], obj_getter=PermissibleMixin.get_permissions_root_obj)],
        "update": [PermDef(["change_on"], obj_getter=PermissibleMixin.get_permissions_root_obj)],
        "partial_update": [PermDef(["change_on"], obj_getter=PermissibleMixin.get_permissions_root_obj)],
        "delete": [PermDef(["change_on"], obj_getter=PermissibleMixin.get_permissions_root_obj)],
    }


class PermissibleSelfOrRootMixin(PermissibleMixin):
    """
    A default configuration of permissions that checks for object-level
    permissions on BOTH the ROOT of the object that we are trying to access,
    AND the object that we are trying to access, itself.

    Note that no global checks are done.
    """

    obj_action_perm_map = PermissibleMixin.merge_action_perm_maps(
        PermissibleSelfOnlyMixin.obj_action_perm_map, PermissibleRootOnlyMixin.obj_action_perm_map
    )
