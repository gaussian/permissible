"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from abc import abstractmethod

from django.contrib.auth.models import Group
from django.db import models
from django.db.models.signals import post_delete
from django.dispatch import receiver

from .base import AbstractModelMetaclass, BasePermRoot
from .permissible_mixin import PermissibleMixin
from ..perm_def import PermDef
from ..utils.signals import get_subclasses


class PermRoot(BasePermRoot):
    """
    A model that has a corresponding `PermRootGroup` to associate it with a
    `Group` model, thereby extending the fields and functionality of the default
    Django `Group` model.

    Examples: `Team(PermRoot)`, `Project(PermRoot)`

    IMPORTANT: the inheriting class must define:
    - a `ForeignKey to the `PermRoot` model
    - `groups`, a `ManyToManyField` to the Group model
    """

    class Meta:
        abstract = True

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
        adding = self._state.adding

        super().save(*args, **kwargs)

        # For new root objects, create the necessary groups/join objects
        if adding:
            self.create_groups()

    def create_groups(self):
        """
        Create the associated `PermRootGroup` and `Group` objects for this
        `PermRoot`.
        """
        # Find the PermRootGroup model
        root_group_model_class = self.get_group_join_rel().related_model

        # Create PermRootGroup for each role in possible roles
        for role, _ in root_group_model_class._meta.get_field("role").choices:
            root_group_model_class.objects.get_or_create(
                role=role,
                **{self._meta.model_name: self}
            )

    def get_group_ids_for_roles(self, roles=None):
        root_group_model_class = self.get_group_join_rel().related_model
        roles = roles if roles is not None else [role for role, _ in root_group_model_class._meta.get_field("role").choices]
        return root_group_model_class.objects.filter(
            role__in=roles,
            **{self._meta.model_name: self}
        ).values_list("group_id", flat=True)

    def add_user_to_groups(self, user, roles=None):
        group_ids = self.get_group_ids_for_roles(roles=roles)
        user.groups.add(*group_ids)

    def remove_user_from_groups(self, user, roles=None):
        group_ids = self.get_group_ids_for_roles(roles=roles)
        user.groups.remove(*group_ids)

    @classmethod
    def get_group_join_rel(cls) -> models.ManyToOneRel:
        """
        Find the join relation for the (one and only one) `PermRootGroup`
        relation
        """
        return cls._get_join_rel(PermRootGroup)

    @classmethod
    def get_user_join_rel(cls) -> models.ManyToOneRel:
        """
        Find the join relation for the (one and only one) `PermRootUser`
        relation
        """
        return cls._get_join_rel(PermRootUser)

    @classmethod
    def _get_join_rel(cls, subclass) -> models.ManyToOneRel:
        join_rels = [field for field in cls._meta.get_fields()
                     if isinstance(field, models.ManyToOneRel)
                     and issubclass(field.related_model, subclass)]

        assert len(join_rels) == 1, f"The associated `{subclass}` for this model (`{cls}`) has " \
                                    f"been set up incorrectly. Make sure there is one (and only one) " \
                                    f"`{subclass}` model with a ForeignKey to `{cls}`"

        return join_rels[0]

    def get_user_joins(self):
        user_join_attr_name = self.get_user_join_rel().related_name
        return getattr(self, user_join_attr_name)

    def get_group_joins(self):
        group_join_attr_name = self.get_group_join_rel().related_name
        return getattr(self, group_join_attr_name)

    def get_member_group_id(self):
        group_join_obj = self.get_group_joins().filter(role="mem").first()
        if group_join_obj:
            return group_join_obj.group_id
        return None

    # TODO: delete this, not needed as the PermRootGroup models are created on
    #      `PermRoot.save()` anyway
    def copy_related_records(self, new_obj):
        remote_field_name = self.get_group_join_rel().remote_field.attname
        for group_join_obj in self.get_group_joins().all():
            group_join_obj.pk = None
            group_join_obj.group_id = None
            setattr(group_join_obj, remote_field_name, new_obj.pk)
            group_join_obj.save()


class PermRootFieldModelMixin(object):
    @classmethod
    def get_root_field(cls) -> models.ForeignKey:
        """
        Find the root field for the (one and only one) `PermRoot`
        foreign-key relation
        """
        root_fields = [field for field in cls._meta.get_fields()
                       if isinstance(field, models.ForeignKey)
                       and issubclass(field.related_model, PermRoot)]

        assert len(root_fields) == 1, f"The associated `PermRoot` for this model (`{cls}`) has " \
                                      f"been set up incorrectly. Make sure this class has one (and only one) " \
                                      f"ForeignKey to a `PermRootGroup`."

        return root_fields[0]


def build_role_field(role_definitions):
    return models.CharField(choices=((role_value, role_label)
                                     for role_value, (role_label, _) in role_definitions.items()),
                            max_length=4, default="mem",
                            help_text="This defines the role of the associated Group, allowing "
                                      "permissions to function more in line with RBAC.")


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
    # NOTE: any child function overriding `ROLE_DEFINITIONS` must redefine `role` like the below
    ROLE_DEFINITIONS = {
        "mem": ("Member", []),
        "view": ("Viewer", ["view"]),
        "con": ("Contributor", ["view", "add_on", "change_on", "change"]),
        "adm": ("Admin", ["view", "add_on", "change_on", "change", "change_permission"]),
        "own": ("Owner", ["view", "add_on", "change_on", "change", "change_permission", "delete"]),
    }

    # Role field (must call this function to override the field choices correctly in child classes)
    # NOTE: any child function overriding `ROLE_DEFINITIONS` must redefine `role` like the below
    role = build_role_field(ROLE_DEFINITIONS)

    class Meta:
        abstract = True

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)

        # Connect post_delete signal to our custom signal for every subclass
        @receiver(post_delete, sender=cls)
        def post_delete_handler(sender, instance, **kwargs):
            """
            Upon deleting a PermRootGroup subclass, delete the connected Group
            (we do it this way to be able to attach to all subclasses).
            """
            instance.group.delete()
            print(f"Deleted Group {instance.group} for {instance.__class__}: {instance}")

    def __str__(self):
        root_field = self.get_root_field()
        root_obj = getattr(self, root_field.name)
        root_obj_class = root_field.related_model
        class_label = root_obj_class._meta.app_label + "." + root_obj_class.__name__
        return f"[{self.role}][{class_label}] {root_obj} [{root_obj.id}]"

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
        if not self.group_id:
            group = Group(
                name=str(self)
            )
            group.save()
            self.group_id = group.id

            # Set the Group's permissions
            self.set_permissions_for_group()

        return super().save(*args, **kwargs)

    # TODO: handling this in permissible.signals, but it isn't generic enough...
    # def delete(self, *args, **kwargs):
    #     """
    #     Upon deleting a PermRootGroup, delete the connected Group
    #     """
    #     group = self.group
    #     super().delete(*args, **kwargs)
    #     group.delete()

    @classmethod
    def get_root_user_model_class(cls) -> models.Model:
        """
        Find the model class for the (one and only one) `PermRootUser` model,
        found via the `PermRoot` foreign-key relation
        """
        root_model_class = cls.get_root_field().related_model
        return root_model_class.get_user_join_rel().related_model

    def get_permissions_root_obj(self, context=None) -> object:
        """This object is the root itself."""
        return self

    @staticmethod
    def get_root_obj(group_id: int) -> "PermRootGroup":
        all_perm_root_group_classes = get_subclasses(PermRootGroup)
        for perm_root_group_class in all_perm_root_group_classes:
            root_field = perm_root_group_class.get_root_field()
            root_id_field_name = root_field.attname
            root_id = perm_root_group_class.objects.filter(group_id=group_id).values_list(root_id_field_name)[:1]
            if root_id:
                return root_field.related_model(pk=root_id)


class PermRootUser(PermRootFieldModelMixin, PermissibleMixin, models.Model, metaclass=AbstractModelMetaclass):
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

    class Meta:
        abstract = True

    perm_def_self = PermDef(None, condition_checker=lambda o, u, c: o.user_id == u.id)
    perm_def_admin = PermDef(["change_permission"], obj_getter="get_permissions_root_obj")
    perm_defs = [perm_def_self, perm_def_admin]

    obj_action_perm_map = {
        "retrieve": perm_defs,
        "update": perm_defs,
        "partial_update": perm_defs,
        "destroy": [perm_def_admin],
    }

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

    def get_permissions_root_obj(self, context=None) -> object:
        return self.get_unretrieved("user")
