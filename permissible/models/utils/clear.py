import logging
from typing import Type

from django.contrib.auth.models import Group

from permissible.models.permissible_mixin import PermissibleMixin

logger = logging.getLogger(__name__)


def clear_permissions_for_class(
    group: Group,
    obj_class: Type[PermissibleMixin],
    skip_obj_ids: list[str] | None = None,
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

    skip_obj_ids = skip_obj_ids or []

    # Retrieve all objects (of this class) that the group has permissions on
    objs = list(
        get_objects_for_group(
            group=group,
            perms=[],
            klass=obj_class,
        ).exclude(id__in=skip_obj_ids)
    )

    # For each permission, bulk-remove across all objects
    if objs:
        for perm in get_perms_for_model(obj_class):
            remove_perm(perm, group, objs)

    # Send signal (for logging, cache invalidation, etc)
    permissions_cleared.send(
        sender=obj_class,
        group=group,
    )
