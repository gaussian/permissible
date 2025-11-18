import logging
from typing import Type

from django.contrib.auth.models import Group

from permissible.models.permissible_mixin import PermissibleMixin

logger = logging.getLogger(__name__)


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
