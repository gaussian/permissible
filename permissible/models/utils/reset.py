from __future__ import annotations

from typing import TYPE_CHECKING

from .clear import clear_permissions_for_class
from .update import bulk_update_permissions_for_objects, ObjectGroupPermSpec

if TYPE_CHECKING:
    from permissible.models.role_based.core import PermDomain, PermDomainRole


def reset_permissions(perm_domain_roles: list[PermDomainRole], clear_existing=False):
    """
    Assign the correct permissions over the associated `PermDomain` to this
    object's Group, according to `self.ROLE_DEFINITIONS`.

    Ideally, this is only called when the object (and its Group) are created,
    but it can also be called via the admin interface in case of
    troubleshooting.
    """

    # Collect all specs for bulk update
    specs = []

    for perm_domain_role in perm_domain_roles:

        # Find the domain object associated with thie object (PermDomain)
        domain_field = perm_domain_role.get_domain_field()
        domain_obj: PermDomain = getattr(perm_domain_role, domain_field.name)

        # Clear existing permissions if requested
        if clear_existing:
            clear_permissions_for_class(
                group=perm_domain_role.group, obj_class=domain_obj.__class__
            )
            # print("==== Cleared existing permissions ====")

        # Determine the new set of permission codenames based on ROLE_DEFINITIONS
        # e.g. {'app_label.add_model', 'app_label.change_model'}
        _, short_perm_codes = perm_domain_role.ROLE_DEFINITIONS[perm_domain_role.role]

        # We need to give/update permissions for the relevant permission target(s)
        # for this domain object - by default (and almost always) this is simply
        # the domain object itself; however, in certain cases (eg in the subclass
        # of `PermDomain` called `HierarchicalPermDomain`) this may be different (eg
        # it may be chidren objects)
        for obj in domain_obj.get_permission_targets():
            specs.append(ObjectGroupPermSpec(
                obj=obj,
                group=perm_domain_role.group,
                short_perm_codes=short_perm_codes,
            ))

    # Bulk update all permissions
    if specs:
        bulk_update_permissions_for_objects(specs)
