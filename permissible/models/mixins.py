from typing import Optional, Type

from permissible.perm_def import ALLOW_ALL, DENY_ALL, IS_AUTHENTICATED, p

from .permissible_mixin import PermissibleMixin


class PermissibleListIfAuthPerms(PermissibleMixin):
    global_action_perm_map = {"list": IS_AUTHENTICATED}


class PermissibleDenyPerms(PermissibleListIfAuthPerms):
    """
    A default configuration of permissions that denies all standard DRF actions
    on objects, and denies object listing to unauthenticated users.

    Note that no global checks are done.
    Note that no "list" permission checks are done (permissions checks should
    instead be done on the actual object, in the "list" action, via
    `permissible.PermissibleDirectFilter`).
    """

    obj_action_perm_map = {
        "create": DENY_ALL,
        "retrieve": DENY_ALL,
        "update": DENY_ALL,
        "partial_update": DENY_ALL,
        "destroy": DENY_ALL,
    }


class PermissibleDefaultPerms(PermissibleListIfAuthPerms):
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
        "retrieve": p(["view"]),
        "update": p(["change"]),
        "partial_update": p(["change"]),
        "destroy": p(["delete"]),
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
        "create": p(["add"]),
    }

    obj_action_perm_map = {
        **PermissibleDefaultPerms.obj_action_perm_map,
        "create": ALLOW_ALL,
    }
