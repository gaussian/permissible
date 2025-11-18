import logging

from django.contrib.auth.models import Group

from permissible.perm_def import BasePermDefObj

logger = logging.getLogger(__name__)


def update_permissions_for_object(
    obj: BasePermDefObj,
    group: Group,
    short_perm_codes,
):
    """
    Update object-level permissions for a single object. Given a target object,
    a group, and a list of permission “short codes” (as defined in ROLE_DEFINITIONS),
    compute the expected permission codenames and assign (or remove) them as needed.
    """
    from guardian.shortcuts import assign_perm, remove_perm, get_group_perms
    from permissible.signals import perm_domain_role_permissions_updated

    # Compute expected permissions using the object's class method
    expected_perms = set(
        obj.__class__.get_permission_codenames(
            short_perm_codes, include_app_label=False
        )
    )

    # Retrieve the permissions the group already has on this object
    current_perms = set(get_group_perms(group, obj))

    # Determine which permissions to add and remove
    permissions_to_add = expected_perms - current_perms
    permissions_to_remove = current_perms - expected_perms

    if permissions_to_add or permissions_to_remove:
        logger.debug(
            "Updating permissions for %s (id=%s), group=%s: adding=%s, removing=%s",
            obj.__class__.__name__,
            obj.pk,
            group.name,
            permissions_to_add or "none",
            permissions_to_remove or "none",
        )

    # Perform the necessary permission assignments
    for perm in permissions_to_add:
        assign_perm(perm, group, obj)
    for perm in permissions_to_remove:
        remove_perm(perm, group, obj)

    # Send signal (for logging, cache invalidation, etc)
    perm_domain_role_permissions_updated.send(
        sender=obj.__class__,
        obj=obj,
        group=group,
        short_perm_codes=short_perm_codes,
    )
