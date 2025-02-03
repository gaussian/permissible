"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from django.contrib.auth.models import Group
from django.db import models
from django.db.models.signals import m2m_changed, post_delete
from django.dispatch import receiver

from .models import PermRootGroup


@receiver(m2m_changed, sender=Group.user_set.through, dispatch_uid='neutron_post_group_membership_changed')
def post_group_membership_changed(sender, action, instance, model, pk_set, **kwargs):
    """
    After a User is added or removed from a Group:
    - create or remove a PermRootUser record (e.g. TeamUser) if needed
    """
    user = instance
    if model != Group:
        return
    if action not in ("post_add", "post_remove", "post_clear"):
        return

    # Get all the PermRootGroup models
    root_group_fields = [field for field in Group._meta.get_fields()
                         if isinstance(field, models.OneToOneRel)
                         and issubclass(field.related_model, PermRootGroup)]
    if not root_group_fields:
        return

    # If we are clearing all Groups, then must delete all PermRootUser records
    # for this user, for all tables
    if action == "post_clear":
        for root_group_field in root_group_fields:
            root_user_model_class = root_group_field.related_model.get_root_user_model_class()
            qs = root_user_model_class.objects.filter(user=user)
            qs.hard_delete() if hasattr(qs, "hard_delete") else qs.delete()
        return

    # Otherwise, process each Group in turn
    # root_model_classes = [cl.get_root_field().related_model for cl in root_group_model_classes]

    # Get a mapping of each possible PermRootUser class to the PermRoot IDs for the
    # relevant Groups, in the following format: {PermRootUser: (perm_root_id_fieldname, [perm_root_ids])}
    # root_user_model_class_to_group_ids = dict()     # type: Dict[type, Tuple[str, List[int]]]

    # Split the affected Groups into the specific PermRootUser models that they
    # relate to, and get the PermRoot ID for those Groups
    for root_group_field in root_group_fields:
        root_group_model_class = root_group_field.related_model
        root_id_field_name = root_group_model_class.get_root_field().attname
        root_user_model_class = root_group_model_class.get_root_user_model_class()
        root_ids = root_group_model_class.objects.filter(
            group_id__in=pk_set
        ).values_list(root_id_field_name, flat=True)

        # Manage the individual PermRootUser record for this user and this PermRoot
        for root_id in root_ids:
            root_user_kwargs = {
                "user_id": user.id,
                root_id_field_name: root_id
            }

            # ADD:
            # If we just added Group(s), make sure the PermRootUser record exists
            if action == "post_add":
                root_user_model_class.objects.get_or_create(**root_user_kwargs)

            # REMOVE:
            # If we just removed Group(s), check if this user is not part of any more
            # Groups that relate to this PermRoot - if not, delete the associated
            # PermRootUser (e.g. delete the TeamUser if this user is no longer part of
            # any groups for this Team)
            else:
                num_related_user_groups = user.groups.filter(
                    **{root_group_field.name + "__" + root_id_field_name: root_id}
                ).count()
                if not num_related_user_groups:
                    root_user_model_class.objects.filter(**root_user_kwargs).delete()
