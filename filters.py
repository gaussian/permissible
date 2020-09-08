from rest_framework import filters
from rest_framework.exceptions import PermissionDenied


class PermissibleRootPermissionsFilter(filters.BaseFilterBackend):
    """
    For a defined set of fields on the view (`view.perm_filterset_fields`),
    check permission on each field AND filter down to that field.

    e.g. for listable "survey questions", we might want to return those
    survey questions that are owned by "surveys" to which this user has
    access
    """

    def filter_queryset(self, request, queryset, view):
        assert hasattr(view, "perm_filterset_fields"), \
            "Badly configured view, need `perm_filterset_fields`."

        assert not any("__" in f for f in view.perm_filterset_fields), \
            f"Cannot yet accommodate joined fields in `PermissibleRootPermissionsFilter`: {view.perm_filterset_fields}"

        model_class = queryset.model

        # For each "permission" field, check permissions, then filter the queryset
        for perm_filterset_field in view.perm_filterset_fields:

            # Get related object (e.g. "Team" from "team_id")
            related_model = getattr(model_class, perm_filterset_field).field.related_model
            related_pk = request.query_params.get(perm_filterset_field)
            related_obj = related_model(pk=related_pk)

            # Check permission for related object
            perm = f"{model_class._meta.app_label}.view_{model_class._meta.model_name}"
            if not request.user.has_perm(perm, related_obj):
                raise PermissionDenied("Permission denied, scope required")

            # Filter
            queryset = queryset.filter(**{perm_filterset_field: related_pk})

        return queryset

