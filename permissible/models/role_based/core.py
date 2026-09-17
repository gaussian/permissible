"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from __future__ import annotations

import logging
from abc import abstractmethod
from typing import Iterable, Optional, Type

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, AbstractBaseUser, PermissionsMixin
from django.db import models, transaction
from django.db.models import Exists, OuterRef
from django.db.models.signals import post_delete
from django.dispatch import receiver
from guardian.shortcuts import get_perms

from permissible.exceptions import RoleEscalationDenied, RoleLockoutDenied
from permissible.exceptions import RoleGrantRefused
from permissible.models.permissible_mixin import PermissibleMixin
from permissible.models.utils import reset_permissions
from permissible.utils.signals import get_subclasses

from .base import AbstractModelMetaclass, BasePermDomain

logger = logging.getLogger(__name__)

# The role every member holds: `build_role_field`'s default, the group the
# member signal watches, and the role `set_roles_for_user` always keeps.
MEMBER_ROLE = "mem"


class PermDomain(BasePermDomain):
    """
    A model that has a corresponding `PermDomainRole` to associate it with a
    `Group` model, thereby extending the fields and functionality of the default
    Django `Group` model.

    Examples: `Team(PermDomain)`, `Project(PermDomain)`

    IMPORTANT: the inheriting class must define:
    - a `ForeignKey to the `PermDomain` model
    - `groups`, a `ManyToManyField` to the Group model
    """

    class Meta:
        abstract = True

    @property
    @abstractmethod
    def groups(self) -> models.ManyToManyField[PermDomain, Group]:
        """
        e.g. `groups = models.ManyToManyField("auth.Group", through="TeamGroup", related_name="teams")`
        """
        pass

    @property
    @abstractmethod
    def users(self) -> models.ManyToManyField[PermDomain, AbstractBaseUser]:
        """
        e.g. `users = models.ManyToManyField("accounts.User", through="TeamUser", related_name="teams")`
        """
        pass

    def save(self, *args, **kwargs):
        """
        Save the model. On save, automatically create one (associated)
        `PermDomainRole` record for each role option in the (associated)
        `PermDomainRole` model.

        :param args:
        :param kwargs:
        :return:
        """
        adding = self._state.adding

        super().save(*args, **kwargs)

        # For new domain objects, create the necessary groups/join objects
        if adding:
            self.reset_domain_roles()

    def get_permission_targets(self) -> Iterable[PermDomain]:
        """
        Return an iterable (or generator) of PermDomain objects for which
        permissions should be set based on this instance.
        For a regular PermDomain, simply yield self.
        """
        yield self

    def reset_domain_roles(self):
        """
        Create the associated `PermDomainRole` and `Group` objects for this
        `PermDomain`, then batch-reset all their permissions in a single call.
        """
        # Find the PermDomainRole model
        domain_role_model_class: Type[PermDomainRole] = (
            self.get_role_join_rel().related_model
        )

        # Create/update PermDomainRole for each role in possible roles
        role_choices = domain_role_model_class._meta.get_field("role").choices
        domain_field = domain_role_model_class.get_domain_field()
        assert isinstance(role_choices, Iterable)

        # 1 query: fetch existing roles
        existing_roles_by_key = {
            r.role: r
            for r in domain_role_model_class.objects.filter(
                **{domain_field.attname: self.pk}
            )
        }

        # Build missing roles
        new_role_objs = [
            domain_role_model_class(role=role, **{domain_field.name: self})
            for role, _ in role_choices
            if role not in existing_roles_by_key
        ]

        # N+1 queries: create Groups individually + bulk create PermDomainRoles
        if new_role_objs:
            domain_role_model_class.bulk_create_with_groups(new_role_objs)

        # ~3 queries: single batched permission reset for all roles
        all_domain_role_objs = list(existing_roles_by_key.values()) + new_role_objs
        reset_permissions(all_domain_role_objs, clear_existing=False)

    def get_group_ids_for_roles(self, roles=None):
        domain_role_model_class: Type[PermDomainRole] = (
            self.get_role_join_rel().related_model
        )
        domain_field = domain_role_model_class.get_domain_field()  # e.g. `team`

        domain_role_filter = {domain_field.attname: self.pk}

        if roles is not None:
            domain_role_filter["role__in"] = roles

        return domain_role_model_class.objects.filter(**domain_role_filter).values_list(
            "group_id", flat=True
        )

    def check_role_change(self, by: PermissionsMixin, roles: Optional[list[str]]):
        """
        No escalation: `by` must hold, on this domain, every permission each role
        carries (`ROLE_DEFINITIONS`); role codes are never compared. `has_perms`
        passes superusers and an empty list, so a role carrying nothing is open
        to all. This bounds WHICH roles `by` may touch; whether `by` may change
        roles at all is `change_permission` on the domain, gated by the caller.
        """
        role_definitions = self.get_role_join_rel().related_model.ROLE_DEFINITIONS
        roles = list(role_definitions if roles is None else roles)
        if unknown := set(roles) - set(role_definitions):
            raise ValueError(f"Unknown roles {unknown} for {self.__class__}")
        needed = {sp for role in roles for sp in role_definitions[role][1]}
        # guardian answers every perm in 2 queries; `has_perms` costs 2 per perm,
        # so it decides only the ones guardian did not grant (and stays the authority)
        granted = set(get_perms(by, self))
        missing = [
            sp
            for sp in sorted(needed)
            if self.get_permission_codename(sp, False) not in granted
        ]
        if not by.has_perms(self.get_permission_codenames(missing, True), self):
            raise RoleEscalationDenied(
                f"{by} may not grant or revoke {roles} on {self}"
            )

    def _check_no_lockout(
        self, user: PermissionsMixin, group_ids: dict[str, int], to_remove: set[str]
    ):
        """
        No lockout: removing `to_remove` from `user` may not take the domain from
        one active `change_permission` holder to none (1 -> 0 only). Runs under
        `_read_roles`'s row lock.
        """
        role_definitions = self.get_role_join_rel().related_model.ROLE_DEFINITIONS
        manager_group_ids = {
            group_ids[role]
            for role, (_, short_perm_codes) in role_definitions.items()
            if "change_permission" in short_perm_codes and role in group_ids
        }
        kept_group_ids = manager_group_ids - {group_ids[r] for r in to_remove}
        active_managers = get_user_model().objects.filter(is_active=True)
        # Managers after the change: anyone else, or `user` via a role that stays
        managers_after = active_managers.filter(
            models.Q(groups__in=kept_group_ids)
            | models.Q(groups__in=manager_group_ids) & ~models.Q(pk=user.pk)
        )
        if (
            not managers_after.exists()
            and active_managers.filter(
                pk=user.pk, groups__in=manager_group_ids
            ).exists()
        ):
            raise RoleLockoutDenied(
                f"{user} is the last active manager of {self}; add another before "
                f"removing their role"
            )

    def _read_roles(self, user: PermissionsMixin, lock: bool):
        """One query: {role: group_id} and the roles `user` holds; locked in pk order."""
        rows = self._role_rows(user).order_by("pk")
        if lock:
            rows = rows.select_for_update()
        rows = list(rows.values_list("role", "group_id", "held"))
        return {r: g for r, g, _ in rows}, {r for r, _, h in rows if h}

    def _change_roles(
        self,
        user: PermissionsMixin,
        group_ids: dict[str, int],
        to_add: set[str],
        to_remove: set[str],
        by: Optional[PermissionsMixin],
        member_if_refused: bool,
    ):
        """
        The one write path. Guards on the delta; adds before it removes, so the
        member signal never sees zero groups (it would delete and re-create the row).
        """
        if unknown := (to_add | to_remove) - group_ids.keys():
            raise ValueError(f"Unknown roles {unknown} for {self.__class__}")
        if by is not None and (to_add or to_remove):
            if to_remove:
                self._check_no_lockout(user, group_ids, to_remove)
            self.check_role_change(by, to_add | to_remove)
        logger.debug("Changing roles of user %s: +%s -%s", user, to_add, to_remove)
        try:
            with transaction.atomic(
                savepoint=member_if_refused
            ):  # a refusal must not poison the outer
                user.groups.add(*[group_ids[r] for r in to_add])
        except RoleGrantRefused if member_if_refused else () as exc:
            logger.error("%s; %s gets %s only on %s", exc, user, MEMBER_ROLE, self)
            user.groups.add(group_ids[MEMBER_ROLE])
        user.groups.remove(*[group_ids[r] for r in to_remove])

    def assign_roles_to_user(
        self,
        user: PermissionsMixin,
        roles: Optional[Iterable[str]],
        by: Optional[PermissionsMixin] = None,
        member_if_refused: bool = False,
    ):
        """
        Add `user` to the groups for `roles` (None: all). Unknown code: `ValueError`.
        `by` enables `check_role_change` on the roles `user` does not hold yet.
        `member_if_refused`: log a receiver's `RoleGrantRefused`; add `MEMBER_ROLE` only.
        """
        with transaction.atomic():
            group_ids, held = self._read_roles(user, lock=by is not None)
            wanted = set(group_ids if roles is None else roles)
            self._change_roles(
                user, group_ids, wanted - held, set(), by, member_if_refused
            )

    def remove_roles_from_user(
        self,
        user: PermissionsMixin,
        roles: Optional[Iterable[str]],
        by: Optional[PermissionsMixin] = None,
    ):
        """
        Remove `user` from the groups for `roles` (None: all). `by` enables
        `_check_no_lockout` and `check_role_change` on the roles `user` holds.
        """
        with transaction.atomic():
            group_ids, held = self._read_roles(user, lock=by is not None)
            unwanted = set(group_ids if roles is None else roles)
            # An unknown code stays in, so `_change_roles` rejects it as in `assign`
            to_remove = (unwanted & held) | (unwanted - group_ids.keys())
            self._change_roles(user, group_ids, set(), to_remove, by, False)

    def _role_rows(self, user: PermissionsMixin):
        """This domain's role rows, annotated with `held`: `user` is in the group."""
        in_group = user.groups.through.objects.filter(
            user_id=user.pk, group_id=OuterRef("group_id")
        )
        return self.get_role_joins().annotate(held=Exists(in_group))

    def get_roles_for_user(self, user: PermissionsMixin) -> models.QuerySet[str]:
        """The role codes `user` holds on this domain: one query on the role rows."""
        return self._role_rows(user).filter(held=True).values_list("role", flat=True)

    def set_roles_for_user(
        self,
        user: PermissionsMixin,
        roles: Iterable[str],
        by: Optional[PermissionsMixin] = None,
    ):
        """
        Replace `user`'s roles on this domain with `roles` + `MEMBER_ROLE`. Unknown
        code: `ValueError`. `by`: the guards of `assign_roles_to_user` /
        `remove_roles_from_user`, on the delta, in one transaction.
        """
        with transaction.atomic():
            group_ids, held = self._read_roles(user, lock=by is not None)
            wanted = set(roles) | {MEMBER_ROLE}
            self._change_roles(user, group_ids, wanted - held, held - wanted, by, False)

    @classmethod
    def get_role_join_rel(cls) -> models.ManyToOneRel:
        """
        Find the join relation for the (one and only one) `PermDomainRole`
        relation
        """
        return cls._get_join_rel(PermDomainRole)

    @classmethod
    def get_user_join_rel(cls) -> models.ManyToOneRel:
        """
        Find the join relation for the (one and only one) `PermDomainMember`
        relation
        """
        return cls._get_join_rel(PermDomainMember)

    @classmethod
    def _get_join_rel(cls, subclass) -> models.ManyToOneRel:
        join_rels = [
            field
            for field in cls._meta.get_fields()
            if isinstance(field, models.ManyToOneRel)
            and issubclass(field.related_model, subclass)
        ]

        assert len(join_rels) == 1, (
            f"The associated `{subclass}` for this model (`{cls}`) has "
            f"been set up incorrectly. Make sure there is one (and only one) "
            f"`{subclass}` model with a ForeignKey to `{cls}`"
        )

        return join_rels[0]

    def get_user_joins(self):
        user_join_attr_name = self.get_user_join_rel().related_name
        assert user_join_attr_name
        return getattr(self, user_join_attr_name)

    def get_role_joins(self):
        group_join_attr_name = self.get_role_join_rel().related_name
        assert group_join_attr_name
        return getattr(self, group_join_attr_name)

    def get_member_group_id(self):
        group_join_obj = self.get_role_joins().filter(role=MEMBER_ROLE).first()
        if group_join_obj:
            return group_join_obj.group_id
        return None

    async def aget_member_group_id(self):
        group_join_obj = await self.get_role_joins().filter(role=MEMBER_ROLE).afirst()
        if group_join_obj:
            return group_join_obj.group_id
        return None


class PermDomainFieldMixin(object):
    @classmethod
    def get_domain_field(cls) -> models.ForeignKey[PermDomain]:
        """
        Find the domain field for the (one and only one) `PermDomain`
        foreign-key relation
        """
        domain_fields = [
            field
            for field in cls._meta.get_fields()
            if isinstance(field, models.ForeignKey)
            and issubclass(field.related_model, PermDomain)
        ]

        assert len(domain_fields) == 1, (
            f"The associated `PermDomain` for this model (`{cls}`) has "
            f"been set up incorrectly. Make sure this class has one (and only one) "
            f"ForeignKey to a `PermDomainRole`."
        )

        return domain_fields[0]

    def get_domain(self) -> PermDomain:
        return getattr(self, self.get_domain_field().name)


def build_role_field(role_definitions):
    return models.CharField(
        choices=(
            (role_value, role_label)
            for role_value, (role_label, _) in role_definitions.items()
        ),
        max_length=4,
        default=MEMBER_ROLE,
        help_text="This defines the role of the associated Group, allowing "
        "permissions to function more in line with RBAC.",
    )


class PermDomainRole(
    PermDomainFieldMixin,
    models.Model,
    metaclass=AbstractModelMetaclass,
):
    """
    Base abstract model that joins the Django Group model to another model
    (`PermDomain`), such as "Team" or "Project". This allows us to have
    additional functionality tied to the Group:
    - Tying to business logic, e.g. Team or Project
    - Adding extra fields without modifying Group
    - Concretely defining a Group as a "role"
    - Managing easily via admin interface

    The models that inherit from this abstract model must also define the join
    key to the model needed, e.g. `team = ForeignKey("accounts.Team")`

    Note that one PermDomainRole has only one Group.

    IMPORTANT: the inheriting class must define:
    - a `ForeignKey to the `PermDomain` model
    """

    # Owning Group (one-to-one relationship)
    group = models.OneToOneField(
        Group,
        on_delete=models.CASCADE,
        primary_key=True,
        help_text="The owning group for this join model. "
        "There is a one-to-one relationship between "
        "this model and Group.",
    )

    # Role definitions:
    # A list of tuples, one for each role, of the following format:
    # 0: role value (for DB)
    # 1: role label
    # 2: default object permissions given to the associated Group (in short form, e.g. "view")
    # NOTE: any child function overriding `ROLE_DEFINITIONS` must redefine `role` like the below
    ROLE_DEFINITIONS: dict[str, tuple[str, list[str]]] = {
        MEMBER_ROLE: ("Member", []),
        "view": ("Viewer", ["view"]),
        "con": ("Contributor", ["view", "add_on", "change_on", "change"]),
        "adm": (
            "Admin",
            ["view", "add_on", "change_on", "change", "change_permission"],
        ),
        "own": (
            "Owner",
            ["view", "add_on", "change_on", "change", "change_permission", "delete"],
        ),
    }

    # Role field (must call this function to override the field choices correctly in child classes)
    # NOTE: any child function overriding `ROLE_DEFINITIONS` must redefine `role` like the below
    role = build_role_field(ROLE_DEFINITIONS)

    class Meta:
        abstract = True

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)

        # Connect post_delete signal to our custom signal for every subclass
        @receiver(post_delete, sender=cls, weak=False)
        def post_delete_handler(sender, instance, **kwargs):
            """
            Upon deleting a PermDomainRole subclass, delete the connected Group
            (we do it this way to be able to attach to all subclasses).
            """
            logger.debug(
                "Deleting Group %s for %s: %s",
                instance.group,
                instance.__class__,
                instance,
            )
            instance.group.delete()

    def __str__(self):
        domain_field = self.get_domain_field()
        domain_obj = getattr(self, domain_field.name)
        domain_obj_class = domain_field.related_model
        class_label = domain_obj_class._meta.app_label + "." + domain_obj_class.__name__
        return f"[{self.role}][{class_label}] {domain_obj} [{domain_obj.id}]"

    def save(self, *args, **kwargs):
        """
        Save the model. When creating a new record, create the associated Group.
        On every save, give that Group the appropriate permissions, according to
        `self.ROLE_DEFINITIONS`.
        """

        # Create Group before adding a PermDomainRole
        if not self.group_id:
            group = Group(name=str(self))
            group.save()
            self.group_id = group.pk

        # Set or reset the Group's permissions
        reset_permissions([self])

        return super().save(*args, **kwargs)

    @classmethod
    def role_labels(cls) -> dict[str, str]:
        """`{code: label}` from `ROLE_DEFINITIONS`."""
        return {code: label for code, (label, _) in cls.ROLE_DEFINITIONS.items()}

    @classmethod
    def bulk_create_with_groups(cls, role_objs):
        """
        Bulk-create PermDomainRoles with their associated Groups.
        Groups are created individually (need PKs for the OneToOneField),
        then PermDomainRoles are bulk_created in a single query.

        Does NOT call reset_permissions — the caller is responsible for that.
        """
        for role_obj in role_objs:
            group = Group.objects.create(name=str(role_obj))
            role_obj.group = group
        if role_objs:
            cls.objects.bulk_create(role_objs)

    @classmethod
    def get_domain_member_model_class(cls) -> Type[PermDomainMember]:
        """
        Find the model class for the (one and only one) `PermDomainMember` model,
        found via the `PermDomain` foreign-key relation
        """
        domain_model_class = cls.get_domain_field().related_model
        return domain_model_class.get_user_join_rel().related_model

    @staticmethod
    def get_domain_obj(group_id: int) -> Optional[PermDomain]:
        all_perm_domain_role_classes = get_subclasses(PermDomainRole)
        for perm_domain_role_class in all_perm_domain_role_classes:
            domain_field = perm_domain_role_class.get_domain_field()
            domain_id_field_name = domain_field.attname
            domain_id = perm_domain_role_class.objects.filter(
                group_id=group_id
            ).values_list(domain_id_field_name)[:1]
            if domain_id:
                return domain_field.related_model(pk=domain_id)


class PermDomainMember(
    PermDomainFieldMixin,
    PermissibleMixin,
    models.Model,
    metaclass=AbstractModelMetaclass,
):
    """
    A model that acts at the through table between the `PermDomain` and `User`
    models.

    Examples: `TeamUser(PermDomainMemberBase)`, `ProjecUser(PermDomainMemberBase)`

    This allows faster retrieval of members of a team, for instance, as well as
    faster retrieval of teams for a user, for instance.

    This model should ideally be automatically created and destroyed (by signals
    in `permissible.signals`) when a user is added or removed from a group.

    IMPORTANT: the inheriting class must define:
    - a `ForeignKey to the `PermDomain` model
    - a joint unique condition on the `PermDomain` and `User` fields (the user field
        has `db_index=False` so the index must be part of the UNIQUE instead)
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, db_index=False, on_delete=models.CASCADE
    )

    class Meta:
        abstract = True

    def __str__(self):
        return f"{self.get_domain()} / {self.user}"
