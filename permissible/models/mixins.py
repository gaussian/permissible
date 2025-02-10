from typing import Optional, Type
from .permissible_mixin import PermissibleMixin
from permissible.perm_def import ALLOW_ALL, DENY_ALL, IS_AUTHENTICATED, PermDef


class PermissibleRejectGlobalPermissionsMixin(PermissibleMixin):
    @classmethod
    def get_room_perm_class(cls, context=None) -> PermissibleMixin:
        raise AssertionError(
            "No global permissions allowed, make sure `global_action_perm_map` is empty"
        )


class PermissibleCreateIfAuthPerms(PermissibleMixin):
    global_action_perm_map = {"list": [IS_AUTHENTICATED]}


class PermissibleDenyPerms(PermissibleCreateIfAuthPerms):
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


class PermissibleDefaultPerms(PermissibleCreateIfAuthPerms):
    """
    A default configuration of permissions that ONLY checks for object-level
    permissions on the object that we are trying to access.

    Note that no global checks are done.
    Note that no "list" permission checks are done (inaccessible objects
    should be filtered out instead).
    No "create" permission, this should be overridden if needed.
    """

    obj_action_perm_map = {
        "create": DENY_ALL,
        "retrieve": [PermDef(["view"])],
        "update": [PermDef(["change"])],
        "partial_update": [PermDef(["change"])],
        "destroy": [PermDef(["delete"])],
    }


class PermissibleDefaultWithGlobalCreatePerms(PermissibleDefaultPerms):
    """
    A default configuration of permissions that ONLY checks for object-level
    permissions on the object that we are trying to access, and additionally
    requires (for creation) that global "add" permission exists for this user.

    Note that no "list" permission checks are done (inaccessible objects
    should be filtered out instead).
    """

    global_action_perm_map = {
        "create": PermDef(["add"]),
    }

    obj_action_perm_map = {
        **PermissibleDefaultPerms.obj_action_perm_map,
        "create": ALLOW_ALL,
    }


class PermissibleDefaultChildPerms(PermissibleCreateIfAuthPerms):
    """
    A default configuration of permissions that ONLY checks for object-level
    permissions on the root of the object that we are trying to access.
    The permissions themselves relate to the root object, not the child object,
    and so the perm_codes are "add_on" and so forth.

    Note that having "change" permission on the root object confers "create"
    permission on the original (child) object.

    Note that the permissions root object/class functions REQUIRE implementation
    in the child class now, unlike other mixins.

    Note also that no global checks are done.
    """

    obj_action_perm_map = {
        "create": [PermDef(["add_on"])],
        "list": [PermDef(["view"])],
        "retrieve": [PermDef(["view"])],
        "update": [PermDef(["change_on"])],
        "partial_update": [PermDef(["change_on"])],
        "destroy": [PermDef(["change_on"])],
    }

    def get_root_perm_object(self, context=None) -> Optional[PermissibleMixin]:
        raise NotImplementedError(
            "Must implement get_root_perm_object to get parent object for permissions"
        )

    @classmethod
    def get_root_perm_class(cls, context=None) -> Type[PermissibleMixin]:
        raise NotImplementedError(
            "Must implement get_root_perm_object to get parent object for permissions"
        )


class PermissibleSimpleChildPerms(PermissibleDefaultChildPerms):
    """
    An alternative configuration of permissions that ONLY checks for object-level
    permissions on the root of the object that we are trying to access.
    The permissions themselves relate to the root object, not the child object,
    and so the perm_codes are "add_on" and so forth.

    Note that having "change" permission on the root object confers "create"
    permission on the original (child) object.

    Note that no global checks are done.

    Note that this class is very similar to `PermissibleDefaultChildPerms`, except it
    doesn't require the "add_on_XXX" and "change_on_XXX" permissions.
    """

    obj_action_perm_map = {
        "create": [PermDef(["change"], obj_getter="get_permissions_root_obj")],
        "list": [PermDef(["view"], obj_getter="get_permissions_root_obj")],
        "retrieve": [PermDef(["view"], obj_getter="get_permissions_root_obj")],
        "update": [PermDef(["change"], obj_getter="get_permissions_root_obj")],
        "partial_update": [PermDef(["change"], obj_getter="get_permissions_root_obj")],
        "destroy": [PermDef(["change"], obj_getter="get_permissions_root_obj")],
    }


# class PermissibleSelfOrRootMixin(PermissibleCreateIfAuthPerms):
#     """
#     A default configuration of permissions that checks for object-level
#     permissions on BOTH the ROOT of the object that we are trying to access,
#     AND the object that we are trying to access, itself.

#     Note that no global checks are done.
#     """

#     obj_action_perm_map = PermissibleMixin.merge_action_perm_maps(
#         PermissibleDefaultPerms.obj_action_perm_map,
#         PermissibleDefaultChildPerms.obj_action_perm_map,
#     )
