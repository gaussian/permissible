"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from django.conf import settings
from rest_framework import filters
from rest_framework.exceptions import PermissionDenied
from rest_framework_guardian.filters import (
    ObjectPermissionsFilter,
)

from permissible.models.permissible_mixin import PermissibleMixin
from permissible.permissions import PermissiblePerms


class PermissibleDirectFilter(ObjectPermissionsFilter):
    """
    A filter backend that limits results to those where the requesting user
    has read object level permissions. Use this when the model we are filtering
    CONTAINS ITS PERMISSIONS, e.g. a Team model that directly has permissions.

    Mostly same as django-rest-framework-guardian's `ObjectPermissionsFilter`.

    Note that this filter is expected to work in conjunction with the permissions
    framework. The "list" permissions will already have been checked by default
    if you are using `PermissiblePerms`. Assertions guarantee that
    `PermissiblePerms` is being used.

    NOTE: we do not perform filtering for detail routes.
    """

    def filter_queryset(self, request, queryset, view):
        if view.detail:
            return queryset

        model_class = view.base_model

        assert issubclass(
            model_class, PermissibleMixin
        ), f"PermissibleDirectFilter model ({model_class}) must be a subclass of PermissibleMixin"

        return super().filter_queryset(request, queryset, view)


class PermissibleIndirectFilter(filters.BaseFilterBackend):
    """
    Filter the queryset indirectly according to policies. This is unlike the
    direct approach above, because in this case, the models we are filtering
    do NOT CONTAIN THEIR PERMISSIONS, e.g. a Survey model may depend on the
    permissions on the Team that owns it.

    Filtering is based on the "filters" in the ACTION_POLICIES of the model
    class, e.g. for a model class "surveys.Survey" owned by its Survey.project,
    we might have the following:

    ```
    ACTION_POLICIES = {
        "surveys.Survey": {
            "filters": ["project"],
            ...
        },
    }
    ```

    Note that this filter is expected to work in conjunction with the permissions
    framework. The "list" permissions will already have been checked by default
    if you are using `PermissiblePerms`. Assertions guarantee that
    `PermissiblePerms` is being used.

    THIS FILTER DOES NOT CHECK PERMISSIONS OR FILTER DOWN TO PERMITTED OBJECTS,
    instead it relies on the ACTION_POLICIES being correctly configured to
    check permissions.

    NOTE: we do not perform filtering for detail routes.
    """

    def filter_queryset(self, request, queryset, view):
        if view.detail:
            return queryset

        model_class = view.base_model

        assert issubclass(
            model_class, PermissibleMixin
        ), f"PermissibleDirectFilter model ({model_class}) must be a subclass of PermissibleMixin"

        # Check that view has permission_classes with PermissiblePerms, OR
        # if permission_classes is empty then check the default permission_classes
        permission_classes = getattr(view, "permission_classes", [])
        if permission_classes:
            assert any(
                [
                    issubclass(permission, PermissiblePerms)
                    for permission in permission_classes
                ]
            ), f"PermissibleDirectFilter view ({view}) must have a permission class of PermissiblePerms"
        else:
            default_permission_classes = getattr(
                settings, "REST_FRAMEWORK", dict()
            ).get("DEFAULT_PERMISSION_CLASSES", [])
            assert (
                "permissible.permissions.PermissiblePerms" in default_permission_classes
            ), f"PermissibleDirectFilter view ({view}) must have a permission class of PermissiblePerms"

        # Get the required filter field attributes for this model
        filter_field_attrs = model_class.get_filters()
        assert (
            filter_field_attrs
        ), f"PermissibleDirectFilter model ({model_class}) must have a 'filters' attribute in the apporiate place under ACTION_POLICIES"

        # Get the actual keys in the query params from these filter fields
        filter_field_keys = [
            getattr(model_class, field_attr).field.attname
            for field_attr in filter_field_attrs
        ]

        # Get the keys that are actually in the query params
        available_filter_field_keys = [
            key for key in filter_field_keys if key in request.query_params
        ]

        # Make sure at least one of the filter field keys is in the query params
        if len(available_filter_field_keys) == 0:
            print(
                f"PermissibleDirectFilter query params must have one of the keys {filter_field_keys}: {request.query_params}"
            )
            raise PermissionDenied("Permission denied in filter")

        # Lastly, filter the queryset down for each of the available filter field keys
        for key in available_filter_field_keys:
            value = request.query_params.get(key)
            queryset = queryset.filter(**{key: value})

        return queryset
