from .perm_def import p, IS_AUTHENTICATED, DENY_ALL, ALLOW_ALL

# POLICY: Allows all read actions on an object for all, both
# authenticated and unauthenticated users. Other actions are denied.
POLICY_PUBLIC_READ_ONLY = {
    "create": DENY_ALL,
    "list": ALLOW_ALL,
    "retrieve": ALLOW_ALL,
    "update": DENY_ALL,
    "partial_update": DENY_ALL,
    "destroy": DENY_ALL,
}

# POLICY: Allows listing of objects if the user is authenticated.
POLICY_LIST_IF_AUTHENTICATED = {
    "list": IS_AUTHENTICATED,
}

# POLICY: Allows all standard DRF actions on objects. Use this
# when you want either the global or object-level permissions
# to not impede other permission checks - because if ANY
# permissions fail,  global or object-level, then the action is
# denied.
POLICY_NO_RESTRICTION = {
    "create": ALLOW_ALL,
    "list": ALLOW_ALL,
    "retrieve": ALLOW_ALL,
    "update": ALLOW_ALL,
    "partial_update": ALLOW_ALL,
    "destroy": ALLOW_ALL,
}

# POLICY: Allows all standard DRF actions on objects, and denies
# object listing to unauthenticated users. Use this when you want
# either the global or object-level permissions to not impede
# other permission checks - because if ANY permissions fail,
# global or object-level, then the action is denied.
POLICY_NO_RESTRICTION_IF_AUTHENTICATED = {
    "create": IS_AUTHENTICATED,
    "list": IS_AUTHENTICATED,
    "retrieve": IS_AUTHENTICATED,
    "update": IS_AUTHENTICATED,
    "partial_update": IS_AUTHENTICATED,
    "destroy": IS_AUTHENTICATED,
}

# POLICY: Denies all standard DRF actions on objects, and denies
# object listing to unauthenticated users.
POLICY_DENY_ALL = {
    "create": DENY_ALL,
    "list": DENY_ALL,
    "retrieve": DENY_ALL,
    "update": DENY_ALL,
    "partial_update": DENY_ALL,
    "destroy": DENY_ALL,
}

# POLICY: Default permissions for a model. Allows listing of objects
# if the user is authenticated. Allows object retrieval, update, partial
# update, and deletion if the user has the appropriate permissions.
POLICY_DEFAULT_NO_CREATE = {
    "create": DENY_ALL,
    "list": IS_AUTHENTICATED,
    "retrieve": p(["view"]),
    "update": p(["change"]),
    "partial_update": p(["change"]),
    "destroy": p(["delete"]),
}

# POLICY: Default permissions for a model. Allows listing of objects
# if the user is authenticated. Allows object retrieval, update, partial
# update, and deletion if the user has the appropriate permissions.
POLICY_DEFAULT_ALLOW_CREATE = {
    "create": ALLOW_ALL,
    "list": IS_AUTHENTICATED,
    "retrieve": p(["view"]),
    "update": p(["change"]),
    "partial_update": p(["change"]),
    "destroy": p(["delete"]),
}

# POLICY: Default GLOBAL permissions for a model. Similar to how the
# default permissions work in Django without object-level permissions.
POLICY_DEFAULT_GLOBAL = {
    "create": p(["add"]),
    "list": p(["view"]),
    "retrieve": p(["view"]),
    "update": p(["change"]),
    "partial_update": p(["change"]),
    "destroy": p(["delete"]),
}


# POLICY MAKER: Creates a simple policy for a domain-owned object.
def make_simple_domain_owned_policy(domain_field_name: str):
    return {
        "create": p(["change"], domain_field_name),
        "list": p(["view"], domain_field_name),
        "retrieve": p(["view"], domain_field_name),
        "update": p(["change"], domain_field_name),
        "partial_update": p(["change"], domain_field_name),
        "destroy": p(["change"], domain_field_name),
    }


# POLICY MAKER: Creates a policy for a domain-owned object, with
# expanded permissions of "add_on" and "change_on".
def make_domain_owned_policy(domain_attr_path: str):
    return {
        "create": p(["add_on"], domain_attr_path),
        "list": p(["view"], domain_attr_path),
        "retrieve": p(["view"], domain_attr_path),
        "update": p(["change_on"], domain_attr_path),
        "partial_update": p(["change_on"], domain_attr_path),
        "destroy": p(["change_on"], domain_attr_path),
    }


# POLICY MAKER: Creates a policy for a DomainMember object,
# requiring permissions on both the domain and the user.
def make_domain_member_policy(domain_name: str):
    return {
        "create": DENY_ALL,
        "list": DENY_ALL,
        "retrieve": p(["view"], domain_name) & p(["view"], "user"),
        "update": p(["change_on"], domain_name) & p(["change"], "user"),
        "partial_update": p(["change_on"], domain_name) & p(["change"], "user"),
        "destroy": DENY_ALL,
    }


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
