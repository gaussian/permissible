"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from django.contrib.auth.models import Group
from django.db import models
from django.db.models.signals import m2m_changed
from django.dispatch import receiver, Signal

from .models import PermDomainRole

perm_domain_role_permissions_updated = Signal()
permissions_cleared = Signal()


@receiver(
    m2m_changed,
    sender=Group.user_set.through,
    dispatch_uid="neutron_post_group_membership_changed",
)
def post_group_membership_changed(sender, action, instance, model, pk_set, **kwargs):
    """
    After a User is added or removed from a Group:
    - create or remove a PermDomainMember record (e.g. TeamUser) if needed
    """
    user = instance
    if model != Group:
        return
    if action not in ("post_add", "post_remove", "post_clear"):
        return

    # Get all the PermDomainRole models
    domain_role_fields = [
        field
        for field in Group._meta.get_fields()
        if isinstance(field, models.OneToOneRel)
        and issubclass(field.related_model, PermDomainRole)
    ]
    if not domain_role_fields:
        return

    # If we are clearing all Groups, then must delete all PermDomainMember records
    # for this user, for all tables
    if action == "post_clear":
        for domain_role_field in domain_role_fields:
            domain_member_model_class = (
                domain_role_field.related_model.get_domain_member_model_class()
            )
            qs = domain_member_model_class.objects.filter(user=user)
            qs.hard_delete() if hasattr(qs, "hard_delete") else qs.delete()
        return

    # Otherwise, process each Group in turn
    # domain_model_classes = [cl.get_domain_field().related_model for cl in domain_role_model_classes]

    # Get a mapping of each possible PermDomainMember class to the PermDomain IDs for the
    # relevant Groups, in the following format: {PermDomainMember: (perm_domain_id_fieldname, [perm_domain_ids])}
    # domain_member_model_class_to_group_ids = dict()     # type: Dict[type, Tuple[str, List[int]]]

    # Split the affected Groups into the specific PermDomainMember models that they
    # relate to, and get the PermDomain ID for those Groups
    for domain_role_field in domain_role_fields:
        domain_role_model_class: PermDomainRole = domain_role_field.related_model
        domain_id_field_name = domain_role_model_class.get_domain_field().attname
        domain_member_model_class = (
            domain_role_model_class.get_domain_member_model_class()
        )
        domain_ids = domain_role_model_class.objects.filter(
            group_id__in=pk_set
        ).values_list(domain_id_field_name, flat=True)

        # Manage the individual PermDomainMember record for this user and this PermDomain
        for domain_id in domain_ids:
            domain_member_kwargs = {"user_id": user.id, domain_id_field_name: domain_id}

            # ADD:
            # If we just added Group(s), make sure the PermDomainMember record exists
            if action == "post_add":
                domain_member_model_class.objects.get_or_create(**domain_member_kwargs)

            # REMOVE:
            # If we just removed Group(s), check if this user is not part of any more
            # Groups that relate to this PermDomain - if not, delete the associated
            # PermDomainMember (e.g. delete the TeamUser if this user is no longer part of
            # any groups for this Team)
            else:
                num_related_user_groups = user.groups.filter(
                    **{domain_role_field.name + "__" + domain_id_field_name: domain_id}
                ).count()
                if not num_related_user_groups:
                    domain_member_model_class.objects.filter(
                        **domain_member_kwargs
                    ).delete()
