"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from django.conf import settings
from rest_framework import filters
from rest_framework.exceptions import PermissionDenied
from rest_framework_guardian.filters import ObjectPermissionsFilter


class PermissibleFilter(ObjectPermissionsFilter):
    """
    Same as django-rest-framework-guardian's `ObjectPermissionsFilter`,
    but does not perform filtering for detail routes (i.e. routes that
    retrieve a specific object).
    """

    def filter_queryset(self, request, queryset, view):
        if view.detail:
            return queryset
        else:
            return super().filter_queryset(request, queryset, view)


class PermissibleRootFilter(filters.BaseFilterBackend):
    """
    For a defined set of fields on the view (`view.filter_perm_fields`),
    check permission on each field AND filter down to that field.

    e.g. for listable "survey questions", we might want to return those
    survey questions that are owned by "surveys" to which this user has
    access

    NOTE: as with `PermissibleFilter`, we do not perform filtering for
    detail routes (i.e. routes that retrieve a specific object).
    """

    def filter_queryset(self, request, queryset, view):
        if view.detail:
            return queryset

        assert hasattr(view, "filter_perm_fields"), \
            "Badly configured view, need `filter_perm_fields`."

        assert not any("__" in f for f in view.filter_perm_fields), \
            f"Cannot yet accommodate joined fields in `PermissibleRootFilter`: {view.filter_perm_fields}"

        # For each "permission" field, check permissions, then filter the queryset
        for perm_filterset_fields, needed_short_perm_code in view.filter_perm_fields:

            # Get related object (e.g. "Team" from "team_id"), nested if need be
            model_class = queryset.model
            related_obj = None
            if not isinstance(perm_filterset_fields, (tuple, list)):
                perm_filterset_fields = (perm_filterset_fields,)
            field_for_filter, pk_for_filter = None, None
            for i, perm_filterset_field in enumerate(perm_filterset_fields):
                related_model = model_class._meta.get_field(perm_filterset_field).related_model
                # First item - get the ID value from the query params object
                if i == 0:
                    related_pk = request.query_params.get(perm_filterset_field)
                    field_for_filter = perm_filterset_field
                    pk_for_filter = related_pk
                # Not the first item, i.e. this is nested - get ID value by traversing the nesting
                else:
                    related_obj.refresh_from_db()
                    related_pk = getattr(related_obj, perm_filterset_field)
                related_obj = related_model(pk=related_pk)
                model_class = related_model

            # Check permission for related object
            perm = f"{related_model._meta.app_label}.{needed_short_perm_code}_{related_model._meta.model_name}"
            if not request.user.has_perm(perm, related_obj):
                message = "Permission denied in filter"
                if settings.DEBUG or settings.IS_TEST:
                    message += f" - {perm}"
                raise PermissionDenied(message)

            # Filter, but only by the first perm_filterset_field (`field_for_filter`,
            # the one that is not nested) as we followed the chain of ownership
            queryset = queryset.filter(**{field_for_filter: pk_for_filter})

        return queryset
