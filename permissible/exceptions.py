from django.core.exceptions import PermissionDenied


class RoleChangeDenied(PermissionDenied):
    """Base of the `by=` guards on `assign_roles_to_user` / `remove_roles_from_user`."""


class RoleEscalationDenied(RoleChangeDenied):
    """`by` lacks, on the domain, a permission the role carries."""


class RoleLockoutDenied(RoleChangeDenied):
    """The change would leave no active `change_permission` holder on the domain."""
