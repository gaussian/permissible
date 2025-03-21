from typing import Type

from django.contrib.auth.models import Group

from permissible.models.permissible_mixin import PermissibleMixin
from permissible.perm_def import BasePermDefObj


def assign_short_perms(short_perms, user_or_group, obj: BasePermDefObj):
    """
    Assign a single short permission to a user or group on an object.
    """
    from guardian.shortcuts import assign_perm

    for short_perm in short_perms:
        perm = obj.get_permission_codename(short_perm, True)
        assign_perm(perm, user_or_group, obj)


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

    # print(f"Current permissions for {obj} for {group}: {current_perms}")
    # print(f"Expected permissions for {obj} for {group}: {expected_perms}")

    # if permissions_to_add:
    #     print(f"Adding permissions to {obj} for {group}: {permissions_to_add}")
    # if permissions_to_remove:
    #     print(f"Removing permissions from {obj} for {group}: {permissions_to_remove}")

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


def clear_permissions_for_class(
    group: Group,
    obj_class: Type[PermissibleMixin],
    skip_obj_ids: list[str] = [],
):
    """
    Clear all object-level permissions for a class of objects.
    """
    from guardian.shortcuts import (
        get_objects_for_group,
        get_perms_for_model,
        remove_perm,
    )
    from permissible.signals import permissions_cleared

    # Retrieve all objects (of this class) that the group has permissions on
    objs = get_objects_for_group(
        group=group,
        perms=[],
        klass=obj_class,
    ).exclude(id__in=skip_obj_ids)

    # Get all relevant permissions for the object class
    all_obj_class_perms = get_perms_for_model(obj_class)

    # For each permission, remove all permissions for the group on all objects
    for perm in all_obj_class_perms:
        # remove_perm(perm, group, objs)      # TODO: doesnt work with MySQL
        for obj in objs:
            remove_perm(perm, group, obj)

    # Send signal (for logging, cache invalidation, etc)
    permissions_cleared.send(
        sender=obj_class,
        group=group,
    )
