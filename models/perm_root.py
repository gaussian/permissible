"""
Neutron (a Visor module)
Author: Kut Akdogan
(c) 2016- Gaussian Holdings, LLC.

This codebase is confidential and proprietary.
No license for use, viewing, or reproduction without explicit written permission.
"""

from django.contrib.auth.models import Group
from django.db import models

from neutron.permissible.models import UneditableModelWithOriginalMixin


class GroupPermRootBase(UneditableModelWithOriginalMixin, models.Model):
    """
    Base abstract model that joins the Django Group model to another model
    (`PermRootBase`), such as "Team" or "Project". This allows us to have
    additional functionality tied to the Group:
    - Tying to business logic, e.g. Team or Project
    - Adding extra fields without modifying Group
    - Concretely defining a Group as a "role"
    - Managing easily via admin interface

    The models that inherit from this abstract model must also define the join
    key to the model needed, e.g. `team = ForeignKey("accounts.Team")`

    Note that one GroupPermRootBase has only one Group.
    """

    # Owning Group (one-to-one relationship)
    group = models.OneToOneField("auth.Group", on_delete=models.CASCADE, primary_key=True, editable=False,
                                 help_text="The owning group for this join model. "
                                           "There is a one-to-one relationship between "
                                           "this model and Group.")

    # Role definitions:
    # A list of tuples, one for each role, of the following format:
    # 0: role value (for DB)
    # 1: role label
    # 2: object permissions to the  this assigned to the associated Group (in short form, e.g. "view")
    ROLE_DEFINITIONS = {
        200: ("Member", []),
        400: ("Viewer", ["view"]),
        600: ("Contributor", ["view", "add_to"]),
        800: ("Admin", ["view", "add_to", "change"]),
        1000: ("Owner", ["view", "add_to", "change", "delete"]),
    }

    # Role
    role = models.PositiveIntegerField(choices=((role_value, role_label)
                                                for role_value, (role_label, _) in ROLE_DEFINITIONS.items()),
                                       default=ROLE_DEFINITIONS[0][0], editable=False,
                                       help_text="This defines the role of the associated Group, allowing "
                                                 "permissions to function more in line with RBAC.")

    # The core fields of this model should not be editable through any means
    UNEDITABLE_FIELDS = ["group_id", "role"]

    class Meta:
        abstract = True

    def __str__(self):
        raise not NotImplementedError

    def save(self, *args, **kwargs):
        """
        Save the model. When creating a new record, create the associated Group
        and give it the appropriate permissions, according to role_definitions.
        """

        from guardian.shortcuts import assign_perm

        # Create Group before adding a GroupPermRootBase
        if self._state.adding and not self.group_id:
            group = Group(
                name=str(self)
            )
            group.save()
            self.group_id = group.id

            # Set the Group's permissions
            _, short_perm_codes = self.ROLE_DEFINITIONS[self.role]
            for short_perm_code in short_perm_codes:
                pass
                # TODO: assign perm to this Group
                # assign_perm()

        return super().save(*args, **kwargs)


class PermRootBase(models.Model):
    """
    A model that has a corresponding
    """

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

        # On save, automatically create one (associated) GroupPermRootBase record for each
        # role option in the (associated) GroupPermRootBase model
        # TODO: find the first related model that isinstance(o, GroupPermRootBase)
        # TODO: create a GroupPermRootBase record for each role option that the GroupPermRootBase has
