"""
Neutron (a Visor module)
Author: Kut Akdogan
(c) 2016- Gaussian Holdings, LLC.

This codebase is confidential and proprietary.
No license for use, viewing, or reproduction without explicit written permission.
"""

from collections import defaultdict
from itertools import chain
from typing import Dict, List, Union, Optional

from django.contrib.auth.models import PermissionsMixin
from django.db.models.fields.related import RelatedField, ManyToManyField
from django.db.models.fields.reverse_related import ForeignObjectRel

from ..perm_def import ShortPermsMixin, PermDef, DENY_ALL, IS_AUTHENTICATED


class PermissibleMixin(ShortPermsMixin):
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

        for perm_def in perm_defs:
            if perm_def.check_global(user=user, context=context):
                return True

        return False

    def has_object_permission(self, user: PermissionsMixin, action: str, context=None):
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
        :param context:
        :return:
        """
        if not self.global_action_perm_map and not self.obj_action_perm_map:
            raise NotImplementedError("No permissions maps in `PermissibleMixin`, did you mean to define "
                                      "`obj_action_perm_map` on your model?")

        # Superusers override
        if user and user.is_superuser:
            return True

        context = context or dict()

        perm_defs = self.obj_action_perm_map.get(action, None)
        if perm_defs is None:
            return True

        for perm_def in perm_defs:
            if perm_def.check_obj(obj=self, user=user, context=context):
                return True

        return False

    def get_permissions_root_obj(self, context=None) -> object:
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

    @classmethod
    def make_objs_from_data(cls, obj_dict_or_list: Union[Dict, List[Dict]]
                            ) -> Union[object, List[object]]:
        """
        Turn data (usually request.data) into a model object (or a list of model
        objects). Allows multiple objects to be built.

        Helpful for non-detail, non-list actions (in particular, the "create"
        action), to allow us to check if the provided user can do the action via
        `obj_action_perm_map`.

        :param obj_dict_or_list: Model data, in dictionary form (or list of
        dictionaries).
        :return: models.Model object (or list of such objects)
        """
        if isinstance(obj_dict_or_list, list):
            return [cls._make_obj_from_data(obj_dict=d) for d in obj_dict_or_list]
        return [cls._make_obj_from_data(obj_dict=obj_dict_or_list)]

    @classmethod
    def _make_obj_from_data(cls, obj_dict: Dict) -> object:
        valid_fields = [f for f in cls._meta.get_fields()
                        if not isinstance(f, (ForeignObjectRel, ManyToManyField))]
        valid_dict_key_to_field_name = {f.name: f.attname for f in valid_fields}
        valid_dict_key_to_field_name.update({f.attname: f.attname for f in valid_fields})
        obj_dict = {valid_dict_key_to_field_name[f]: v
                    for f, v in obj_dict.items()
                    if f in valid_dict_key_to_field_name}
        return cls(**obj_dict)

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


class PermissibleAuthenticatedListingMixin(object):
    global_action_perm_map = {
        "list": [IS_AUTHENTICATED]
    }


class PermissibleDenyDefaultMixin(PermissibleAuthenticatedListingMixin, PermissibleMixin):
    """
    A default configuration of permissions that denies all standard DRF actions
    on objects, and denies object listing to unauthenticated users.

    Note that no global checks are done.
    Note that no "list" permission checks are done (permissions checks should
    instead be done on the root object, in the "list" action, via
    `permissible.PermissibleRootFilter`).
    """

    obj_action_perm_map = {
        "create": DENY_ALL,
        "retrieve": DENY_ALL,
        "update": DENY_ALL,
        "partial_update": DENY_ALL,
        "destroy": DENY_ALL,
    }

    def get_permissions_root_obj(self, context=None) -> object:
        return None


class PermissibleSelfOnlyMixin(PermissibleAuthenticatedListingMixin, PermissibleMixin):
    """
    A default configuration of permissions that ONLY checks for object-level
    permissions on the object that we are trying to access.

    Note that no global checks are done.
    Note that no "list" permission checks are done (inaccessible objects
    should be filtered out instead, using
    `permissible.filters.PermissibleFilter`).
    No "create" permission, this should be overriden if needed.
    """

    obj_action_perm_map = {
        "create": DENY_ALL,
        "retrieve": [PermDef(["view"])],
        "update": [PermDef(["change"])],
        "partial_update": [PermDef(["change"])],
        "destroy": [PermDef(["delete"])],
    }

    def get_permissions_root_obj(self, context=None) -> object:
        return self


class PermissibleRootOnlyMixin(PermissibleAuthenticatedListingMixin, PermissibleMixin):
    """
    A default configuration of permissions that ONLY checks for object-level
    permissions on the ROOT of the object that we are trying to access.

    Note that having "change" permission on the root object confers "create"
    permission on the original (child) object.

    Note that no global checks are done.
    Note that no "list" permission checks are done (permissions checks should
    instead be done on the root object, in the "list" action, via
    `permissible.PermissibleRootFilter`).
    """

    obj_action_perm_map = {
        "create": [PermDef(["add_on"], obj_getter="get_permissions_root_obj")],
        "retrieve": [PermDef(["view"], obj_getter="get_permissions_root_obj")],
        "update": [PermDef(["change_on"], obj_getter="get_permissions_root_obj")],
        "partial_update": [PermDef(["change_on"], obj_getter="get_permissions_root_obj")],
        "destroy": [PermDef(["change_on"], obj_getter="get_permissions_root_obj")],
    }


class PermissibleSelfOrRootMixin(PermissibleAuthenticatedListingMixin, PermissibleMixin):
    """
    A default configuration of permissions that checks for object-level
    permissions on BOTH the ROOT of the object that we are trying to access,
    AND the object that we are trying to access, itself.

    Note that no global checks are done.
    """

    obj_action_perm_map = PermissibleMixin.merge_action_perm_maps(
        PermissibleSelfOnlyMixin.obj_action_perm_map, PermissibleRootOnlyMixin.obj_action_perm_map
    )
