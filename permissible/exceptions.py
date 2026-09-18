from django.core.exceptions import PermissionDenied


class RoleChangeDenied(PermissionDenied):
    """Base of the `by=` guards on `assign_roles_to_user` / `remove_roles_from_user`."""


class RoleEscalationDenied(RoleChangeDenied):
    """`by` lacks, on the domain, a permission the role carries."""


class RoleLockoutDenied(RoleChangeDenied):
    """The change would leave no active `change_permission` holder on the domain."""


class RoleGrantRefused(Exception):
    """A `m2m_changed` receiver on `Group.user_set` vetoed a grant; a subclass sets `code`."""

    code = "grant_refused"

    def __init__(self, *args, fields: dict | None = None):
        super().__init__(*args)
        self.fields = fields or {}  # extra keys for the 409 body
