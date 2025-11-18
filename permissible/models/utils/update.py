import logging
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable, Sequence

from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from guardian.shortcuts import get_group_obj_perms_model
from permissible.perm_def import BasePermDefObj

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ObjectGroupPermSpec:
    obj: BasePermDefObj
    group: Group
    short_perm_codes: Sequence[str]


def bulk_update_permissions_for_objects(
    specs: Iterable[ObjectGroupPermSpec],
):
    """
    Bulk update object-level permissions for MANY (obj, group) pairs.

    - Works with default GroupObjectPermission AND custom per-model through models
      defined via GroupObjectPermissionBase.
    - Minimizes queries:
        * ~1 query/model for existing perms
        * ~1 query/model for Permission rows
        * 1 bulk_create/model
        * 1 delete/model
    """

    # Group all specs by the model class of the object
    specs_by_model: dict[type, list[ObjectGroupPermSpec]] = defaultdict(list)
    specs = list(specs)  # in case it's a generator
    for spec in specs:
        specs_by_model[spec.obj.__class__].append(spec)

    # Do all DB mutations inside a transaction
    with transaction.atomic():
        for Model, model_specs in specs_by_model.items():
            if not model_specs:
                continue

            ObjPermModel = get_group_obj_perms_model(Model)

            # Detect pattern: generic GFK vs per-model FK ("content_object")
            field_names = {f.name for f in ObjPermModel._meta.fields}
            has_content_object_fk = "content_object" in field_names

            ct = ContentType.objects.get_for_model(Model)

            # --- Prepare index structures for this model ---

            # Key all maps by (group_id, object_key)
            # object_key = str(pk) for generic GFK, or pk (int/UUID) for FK
            expected_by_key: dict[tuple[int, str | int], set[str]] = {}
            short_codes_by_key: dict[tuple[int, str | int], Sequence[str]] = {}
            obj_by_key: dict[tuple[int, str | int], BasePermDefObj] = {}
            group_by_key: dict[tuple[int, str | int], Group] = {}

            # Sets to constrain the existing-perms query
            if has_content_object_fk:
                obj_ids: set[int | str] = set()
            else:
                obj_pks_as_str: set[str] = set()
            groups: set[Group] = set()

            for spec in model_specs:
                obj = spec.obj
                group = spec.group
                object_key = obj.pk if has_content_object_fk else str(obj.pk)
                key = (group.pk, object_key)

                # Compute expected permission *codenames* (no app label)
                expected_codenames = set(
                    Model.get_permission_codenames(
                        spec.short_perm_codes,
                        include_app_label=False,
                    )
                )

                expected_by_key[key] = expected_codenames
                short_codes_by_key[key] = spec.short_perm_codes
                obj_by_key[key] = obj
                group_by_key[key] = group

                if has_content_object_fk:
                    obj_ids.add(obj.pk)
                else:
                    obj_pks_as_str.add(str(obj.pk))
                groups.add(group)

            # --- Fetch existing perms in one query for all objects+groups ---

            if has_content_object_fk:
                existing_qs = (
                    ObjPermModel.objects
                    .filter(
                        group__in=groups,
                        content_object__in=[s.obj for s in model_specs],
                    )
                    .select_related("permission", "group")
                )
            else:
                existing_qs = (
                    ObjPermModel.objects
                    .filter(
                        group__in=groups,
                        content_type=ct,
                        object_pk__in=obj_pks_as_str,
                    )
                    .select_related("permission", "group")
                )

            # Map: (group_id, object_key) -> set of current codenames
            current_by_key: dict[tuple[int, str | int], set[str]] = defaultdict(set)

            for gop in existing_qs:
                if has_content_object_fk:
                    object_key = gop.content_object_id
                else:
                    object_key = gop.object_pk
                key = (gop.group_id, object_key)
                current_by_key[key].add(gop.permission.codename)

            # --- Compute diffs per (group, obj) ---

            add_codes_by_key: dict[tuple[int, str | int], set[str]] = {}
            remove_codes_by_key: dict[tuple[int, str | int], set[str]] = {}
            all_add_codes: set[str] = set()

            for key, expected_codenames in expected_by_key.items():
                current_codenames = current_by_key.get(key, set())

                to_add = expected_codenames - current_codenames
                to_remove = current_codenames - expected_codenames

                if to_add:
                    add_codes_by_key[key] = to_add
                    all_add_codes.update(to_add)
                if to_remove:
                    remove_codes_by_key[key] = to_remove

            # Nothing to change for this model
            if not add_codes_by_key and not remove_codes_by_key:
                continue

            # --- Permission lookup for additions (1 query/model) ---

            if all_add_codes:
                perms_by_code = {
                    p.codename: p
                    for p in Permission.objects.filter(
                        content_type=ct,
                        codename__in=all_add_codes,
                    )
                }
                
                # Create any missing permissions
                missing_codes = all_add_codes - set(perms_by_code.keys())
                if missing_codes:
                    new_perms = []
                    for code in missing_codes:
                        # Create a readable permission name from the codename
                        name = f"Can {code.replace('_', ' ')}"
                        new_perms.append(Permission(
                            content_type=ct,
                            codename=code,
                            name=name,
                        ))
                    Permission.objects.bulk_create(new_perms, ignore_conflicts=True)
                    
                    # Refetch to get the IDs of newly created permissions
                    perms_by_code = {
                        p.codename: p
                        for p in Permission.objects.filter(
                            content_type=ct,
                            codename__in=all_add_codes,
                        )
                    }
            else:
                perms_by_code = {}

            # --- Build ObjPermModel instances for bulk_create ---

            new_rows: list[ObjPermModel] = []
            for key, codes_to_add in add_codes_by_key.items():
                group = group_by_key[key]
                obj = obj_by_key[key]

                for code in codes_to_add:
                    perm = perms_by_code[code]  # assume definitions are valid
                    kwargs = {
                        "group": group,
                        "permission": perm,
                    }
                    if has_content_object_fk:
                        kwargs["content_object"] = obj
                    else:
                        kwargs["content_type"] = ct
                        kwargs["object_pk"] = str(obj.pk)
                    new_rows.append(ObjPermModel(**kwargs))

            if new_rows:
                ObjPermModel.objects.bulk_create(
                    new_rows,
                    ignore_conflicts=True,  # protects against double-inserts/races
                )

            # --- Collect rows to delete in one go ---

            to_delete_ids: list[int] = []
            for gop in existing_qs:
                if has_content_object_fk:
                    object_key = gop.content_object_id
                else:
                    object_key = gop.object_pk
                key = (gop.group_id, object_key)
                codes_to_remove = remove_codes_by_key.get(key)
                if codes_to_remove and gop.permission.codename in codes_to_remove:
                    to_delete_ids.append(gop.pk)

            if to_delete_ids:
                ObjPermModel.objects.filter(pk__in=to_delete_ids).delete()

    # --- Signals outside the atomic block (semantics preserved) ---

    from permissible.signals import perm_domain_role_permissions_updated

    for Model, model_specs in specs_by_model.items():
        for spec in model_specs:
            perm_domain_role_permissions_updated.send(
                sender=Model,
                obj=spec.obj,
                group=spec.group,
                short_perm_codes=spec.short_perm_codes,
            )
