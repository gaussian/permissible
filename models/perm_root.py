"""
Neutron (a Visor module)
Author: Kut Akdogan
(c) 2016- Gaussian Holdings, LLC.

This codebase is confidential and proprietary.
No license for use, viewing, or reproduction without explicit written permission.
"""

from abc import abstractmethod, ABCMeta

from django.contrib.auth.models import Group
from django.db import models

from .permissible_mixin import PermissibleMixin, PermDef


class AbstractModelBase(ABCMeta, models.base.ModelBase):
    pass


class PermRoot(PermissibleMixin, metaclass=AbstractModelBase):
    """
    A model that has a corresponding `PermRootGroup` to associate it with a
    `Group` model, thereby extending the fields and functionality of the default
    Django `Group` model.

    Examples: `Team(PermRoot)`, `Project(PermRoot)`

    IMPORTANT: the inheriting class must define:
    - a `ForeignKey to the `PermRoot` model
    - `groups`, a `ManyToManyField` to the Group model
    """

    @property
    @abstractmethod
    def groups(self) -> models.ManyToManyField:
        """
        e.g. `groups = models.ManyToManyField("auth.Group", through="TeamGroup", related_name="teams")`
        """
        pass

    @property
    @abstractmethod
    def users(self) -> models.ManyToManyField:
        """
        e.g. `users = models.ManyToManyField("accounts.User", through="TeamUser", related_name="teams")`
        """
        pass

    def save(self, *args, **kwargs):
        """
        Save the model. On save, automatically create one (associated)
        `PermRootGroup` record for each role option in the (associated)
        `PermRootGroup` model.

        :param args:
        :param kwargs:
        :return:
        """
        super().save(*args, **kwargs)

        # For new root objects, create the necessary groups/join objects
        if self._state.adding:
            self.create_groups()

    def create_groups(self):
        """
        Create the associated `PermRootGroup` and `Group` objects for this
        `PermRoot`.
        """
        # Find the join relation for the PermRootGroup relation
        join_rel = self.get_group_join_rel()

        # Create PermRootGroup for each role in possible roles
        join_model = join_rel.related_model
        for role, _ in join_model._meta.get_field("role").choices:
            join_model.objects.get_or_create(
                role=role,
                **{self._meta.model_name: self}
            )

    def get_group_join_rel(self) -> models.ManyToOneRel:
        """
        Find the join relation for the (one and only one) `PermRootGroup`
        relation
        """
        join_rels = [field for field in self._meta.get_fields()
                     if isinstance(field, models.ManyToOneRel)
                     and issubclass(field.related_model, PermRootGroup)]

        assert len(join_rels) == 1, f"The associated `PermRootGroup` for this model (`{self.__class__}`) has " \
                                    f"been set up incorrectly. Make sure there is one (and only one) " \
                                    f"`PermRootGroup` model with a ForeignKey to `{self.__class__}`"

        return join_rels[0]

    def get_member_group_qs(self):
        return self.get_group_join_rel().related_model.objects.filter(role="mem")


class PermRootFieldModelMixin(PermissibleMixin):
    perm_def_self = PermDef(None, condition_checker=lambda o, u: o.user_id == u.id)
    perm_def_admin = PermDef(["change_permission"], obj_getter=PermissibleMixin.get_permissions_root_obj)
    perm_defs = [perm_def_self, perm_def_admin]

    obj_action_perm_map = {
        "retrieve": perm_defs,
        "update": perm_defs,
        "partial_update": perm_defs,
        "delete": [perm_def_admin],
    }

    @classmethod
    def get_root_field(cls) -> models.ForeignKey:
        """
        Find the root field for the (one and only one) `PermRootBase`
        foreign-key relation
        """
        root_fields = [field for field in cls._meta.get_fields()
                       if isinstance(field, models.ForeignKey)
                       and issubclass(field.related_model, PermRoot)]

        assert len(root_fields) == 1, f"The associated `PermRoot` for this model (`{cls}`) has " \
                                      f"been set up incorrectly. Make sure this class has one (and only one) " \
                                      f"ForeignKey to a `PermRootGroup`."

        return root_fields[0]

    def get_permissions_root_obj(self) -> object:
        return self.get_unretrieved(self.get_root_field().name)


class PermRootGroup(PermRootFieldModelMixin, models.Model):
    """
    Base abstract model that joins the Django Group model to another model
    (`PermRoot`), such as "Team" or "Project". This allows us to have
    additional functionality tied to the Group:
    - Tying to business logic, e.g. Team or Project
    - Adding extra fields without modifying Group
    - Concretely defining a Group as a "role"
    - Managing easily via admin interface

    The models that inherit from this abstract model must also define the join
    key to the model needed, e.g. `team = ForeignKey("accounts.Team")`

    Note that one PermRootGroup has only one Group.

    IMPORTANT: the inheriting class must define:
    - a `ForeignKey to the `PermRoot` model
    """

    # Owning Group (one-to-one relationship)
    group = models.OneToOneField(Group, on_delete=models.CASCADE, primary_key=True,
                                 help_text="The owning group for this join model. "
                                           "There is a one-to-one relationship between "
                                           "this model and Group.")

    # Role definitions:
    # A list of tuples, one for each role, of the following format:
    # 0: role value (for DB)
    # 1: role label
    # 2: default object permissions given to the associated Group (in short form, e.g. "view")
    ROLE_DEFINITIONS = {
        "mem": ("Member", []),
        "view": ("Viewer", ["view"]),
        "con": ("Contributor", ["view", "add_on", "change_on"]),
        "adm": ("Admin", ["view", "add_on", "change_on", "change", "change_permission"]),
        "own": ("Owner", ["view", "add_on", "change_on", "change", "change_permission", "delete"]),
    }

    # Role
    role = models.CharField(choices=((role_value, role_label)
                                     for role_value, (role_label, _) in ROLE_DEFINITIONS.items()),
                            max_length=4, default="mem",
                            help_text="This defines the role of the associated Group, allowing "
                                      "permissions to function more in line with RBAC.")

    class Meta:
        abstract = True

    def __str__(self):
        root_field = self.get_root_field()
        root_obj = getattr(self, root_field.name)
        return f"[{self.role}] {root_obj}"

    def set_permissions_for_group(self):
        """
        Assign the correct permissions over the associated `PermRoot` to this
        object's Group, according to `self.ROLE_DEFINITIONS`.

        Ideally, this is only called when the object (and its Group) are created,
        but it can also be called via the admin interface in case of
        troubleshooting.
        """
        from guardian.shortcuts import assign_perm

        # Find the root object associated with thie object (PermRoot)
        root_field = self.get_root_field()
        root_obj = getattr(self, root_field.name)

        # Find the permissions we need to assign, using ROLE_DEFINITIONS
        root_model = root_field.related_model
        _, short_perm_codes = self.ROLE_DEFINITIONS[self.role]
        perms = root_model.get_permission_codenames(short_perm_codes)

        # Assign these permissions (for found the PermRoot object) to this object's Group
        for perm in perms:
            assign_perm(perm, self.group, root_obj)

    def save(self, *args, **kwargs):
        """
        Save the model. When creating a new record, create the associated Group
        and give it the appropriate permissions, according to
        `self.ROLE_DEFINITIONS`.
        """

        # Create Group before adding a PermRootGroup
        if self._state.adding and not self.group_id:
            group = Group(
                name=str(self)
            )
            group.save()
            self.group_id = group.id

            # Set the Group's permissions
            self.set_permissions_for_group()

        return super().save(*args, **kwargs)

    def get_permissions_root_obj(self) -> object:
        """This object is the root itself."""
        return self


class PermRootUser(PermRootFieldModelMixin, metaclass=AbstractModelBase):
    """
    A model that acts at the through table between the `PermRoot` and `User`
    models.

    Examples: `TeamUser(PermRootUserBase)`, `ProjecUser(PermRootUserBase)`

    This allows faster retrieval of members of a team, for instance, as well as
    faster retrieval of teams for a user, for instance.

    This model should ideally be automatically created and destroyed (by signals
    in `permissible.signals`) when a user is added or removed from a group.

    IMPORTANT: the inheriting class must define:
    - a `ForeignKey to the `PermRoot` model
    - `user`, a `ForeignKey` to the user model
    """

    @property
    @abstractmethod
    def user(self):
        """
        e.g. `user = models.ForeignKey("User", related_name="team_users", on_delete=models.CASCADE)`
        """
        pass

    def __str__(self):
        root_field = self.get_root_field()
        root_obj = getattr(self, root_field.name)
        return f"{root_obj} / {self.user}"
