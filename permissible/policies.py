from .perm_def import p, IS_AUTHENTICATED, DENY_ALL, ALLOW_ALL

# POLICY: Allows all read actions on an object for all, both
# authenticated and unauthenticated users. Other actions are denied.
POLICY_PUBLIC_READ_ONLY = {
    "create": DENY_ALL,
    "retrieve": ALLOW_ALL,
    "update": DENY_ALL,
    "partial_update": DENY_ALL,
    "destroy": DENY_ALL,
}

# POLICY: Allows all standard DRF actions on objects. Use this
# when you want either the global or object-level permissions
# to not impede other permission checks - because if ANY
# permissions fail,  global or object-level, then the action is
# denied.
POLICY_NO_RESTRICTION = {
    "create": ALLOW_ALL,
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
POLICY_AUTHENTICATED = {
    "create": IS_AUTHENTICATED,
    "retrieve": IS_AUTHENTICATED,
    "update": IS_AUTHENTICATED,
    "partial_update": IS_AUTHENTICATED,
    "destroy": IS_AUTHENTICATED,
}

# POLICY: Allows all standard DRF actions on objects to authenticated
# users, but restricts object creation to authenticated users who have
# the "add" permission. Use this for global permissions.
POLICY_CREATE_RESTRICTED = {
    "create": p(["add"]),
    "retrieve": IS_AUTHENTICATED,
    "update": IS_AUTHENTICATED,
    "partial_update": IS_AUTHENTICATED,
    "destroy": IS_AUTHENTICATED,
}

# POLICY: Denies all standard DRF actions on objects, and denies
# object listing to unauthenticated users.
POLICY_DENY_ALL = {
    "create": DENY_ALL,
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
    "retrieve": p(["view"]),
    "update": p(["change"]),
    "partial_update": p(["change"]),
    "destroy": p(["delete"]),
}

# POLICY: Default permissions for a model. Allows listing of objects
# if the user is authenticated. Allows object retrieval, update, partial
# update, and deletion if the user has the appropriate permissions.
# Use as object permissions together with
# `POLICY_CREATE_RESTRICTED` for global permissions.
POLICY_DEFAULT_ALLOW_CREATE = {
    "create": ALLOW_ALL,
    "retrieve": p(["view"]),
    "update": p(["change"]),
    "partial_update": p(["change"]),
    "destroy": p(["delete"]),
}

# POLICY: Default GLOBAL permissions for a model. Similar to how the
# default permissions work in Django without object-level permissions.
POLICY_DEFAULT_GLOBAL = {
    "create": p(["add"]),
    "retrieve": p(["view"]),
    "update": p(["change"]),
    "partial_update": p(["change"]),
    "destroy": p(["delete"]),
}

# FULL POLICY: Default permissions for a model. This defers to object
# permissions for all actions, except for "create", which is allowed
# if the user has the "add" permission globally. Only authenticated
# users are allowed for all actions.
FULL_POLICY_DEFAULT = {
    "global": POLICY_CREATE_RESTRICTED,
    "object": POLICY_DEFAULT_ALLOW_CREATE,
}

# FULL POLICY: No object-level permissions are checked, only global.
# Authenticated users only.
FULL_POLICY_GLOBAL_ONLY = {
    "global": POLICY_DEFAULT_GLOBAL,
    "object": POLICY_NO_RESTRICTION,
}


# POLICY MAKER: Creates a simple policy for a domain-owned object.
def make_simple_domain_owned_policy(domain_field_name: str):
    return {
        "create": p(["change"], domain_field_name),
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
        "retrieve": p(["view"], domain_attr_path),
        "update": p(["change_on"], domain_attr_path),
        "partial_update": p(["change_on"], domain_attr_path),
        "destroy": p(["change_on"], domain_attr_path),
    }


# POLICY MAKER: Creates a policy for a DomainMember object.
# All actions have perm_def_admin, which gives permissions to those who have
# the "change_permission" permission on the associated PermDomain object.
# All actions besides "destroy" have perm_def_self, which gives permissions
# to the user who is the user field of this PermDomainMember.
def make_domain_member_policy(domain_name: str):
    perm_def_self = p(
        [],
        obj_filter=("user_id", "==", "_context.request.user.id"),
    )
    perm_def_admin = p(
        ["change_permission"],
        # This is joined user (unretrieved)
        "user",
    )
    return {
        "create": DENY_ALL,
        "retrieve": perm_def_self | perm_def_admin,
        "update": perm_def_self | perm_def_admin,
        "partial_update": perm_def_self | perm_def_admin,
        "destroy": perm_def_admin,
    }
