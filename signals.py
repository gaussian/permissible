"""
Neutron (a Visor module)
Author: Kut Akdogan
(c) 2016- Gaussian Holdings, LLC.

This codebase is confidential and proprietary.
No license for use, viewing, or reproduction without explicit written permission.
"""

from django.contrib.auth.models import Group
from django.db import models
from django.db.models.signals import m2m_changed
from django.dispatch import receiver

from neutron.permissible.models import PermRootGroup, PermRootUser


@receiver(m2m_changed, sender=Group.user_set.through, dispatch_uid='neutron_post_group_membership_changed')
def post_group_membership_changed(sender, action, instance, model, pk_set, **kwargs):
    """
    After a User is added or removed from a Group:
    - create a PermRootUser record (e.g. TeamUser)  if needed
    """

    user = instance
    if model != Group:
        return
    if action not in ("post_add", "post_remove", "post_clear"):
        return

    # Get reverse field name on the Group that ties to the PermRootGroup
    group_root_fields = [field for field in Group._meta.get_fields()
                         if isinstance(field, models.OneToOneRel) and isinstance(field.related_model, PermRootGroup)]
    assert len(group_root_fields) == 1, f"The associated `PermRootGroup` for the `Group` model has " \
                                        f"been set up incorrectly. Make sure the `PermRootGroup` child model " \
                                        f"has one (and only one) OneToOneField to Django's `Group` model."
    group_root_field = group_root_fields[0]
    group_root_class = group_root_field.related_model

    # Get the corresponding root IDs (e.g. team IDs) for the group IDs in the signal
    root_ids = set(group_root_class.objects.filter(
        group_id__in=pk_set
    ).values_list(group_root_field.attname, flat=True))

    # Get the PermRoot field
    root_field = group_root_class.get_root_field()
    root_class = root_field.related_model

    # Finally, get the PermRootUser field/class (if one exists)
    root_user_rels = [field for field in root_class._meta.get_fields()
                      if isinstance(field, models.ManyToOneRel)
                      and issubclass(field.related_model, PermRootUser)]
    if not root_user_rels:
        return
    assert len(root_user_rels) == 1, f"The associated `PermRoot` for this model (`{root_class}`) has " \
                                     f"been set up incorrectly. Make sure the `PermRoot` child model " \
                                     f"has one (and only one) ForeignKey to the child {root_class} model."
    root_user_rel = root_user_rels[0]
    root_user_class = root_user_rel.related_model

    # If adding a group to this user, make sure the PermRootUser record exists
    if action == "post_add":
        for root_id in root_ids:
            root_user_class.objects.get_or_create(
                user=user.id,
                **{root_field.attname: root_id}
            )

    # If removing a group, check if this user is not part of any more groups that relate
    # to these PermRoot - if not, delete the associated PermRootUser
    # (e.g. delete the TeamUser if this user is no longer part of any groups for this Team)
    if action in ("post_remove", "post_clear"):
        for root_id in root_ids:
            num_group_root_records = user.groups.filter(
                **{group_root_field.name + "__" + root_field.attname: root_id}
            ).count()
            if not num_group_root_records:
                root_user_class.objects.filter(
                    user=user.id,
                    **{root_field.attname: root_id}
                ).delete()
