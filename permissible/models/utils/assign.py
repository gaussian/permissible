import logging

from permissible.perm_def import BasePermDefObj

logger = logging.getLogger(__name__)


def assign_short_perms(short_perms, user_or_group, obj: BasePermDefObj):
    """
    Assign a single short permission to a user or group on an object.
    """
    from guardian.shortcuts import assign_perm

    for short_perm in short_perms:
        perm = obj.get_permission_codename(short_perm, True)
        assign_perm(perm, user_or_group, obj)
