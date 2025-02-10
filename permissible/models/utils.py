def update_permissions_for_object(obj, group, short_perm_codes):
    """
    Update object-level permissions for a single object. Given a target object,
    a group, and a list of permission “short codes” (as defined in ROLE_DEFINITIONS),
    compute the expected permission codenames and assign (or remove) them as needed.
    """
    from guardian.shortcuts import assign_perm, remove_perm, get_group_perms

    # Compute expected permissions using the object's class method
    expected_perms = set(obj.__class__.get_permission_codenames(short_perm_codes))

    # Retrieve the permissions the group already has on this object
    current_perms = set(get_group_perms(group, obj))

    # Determine which permissions to add and remove
    permissions_to_add = expected_perms - current_perms
    permissions_to_remove = current_perms - expected_perms

    # Perform the necessary permission assignments
    for perm in permissions_to_add:
        assign_perm(perm, group, obj)
    for perm in permissions_to_remove:
        remove_perm(perm, group, obj)
