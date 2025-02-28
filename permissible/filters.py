"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from django.conf import settings
from rest_framework import filters
from rest_framework.exceptions import PermissionDenied
from rest_framework_guardian.filters import ObjectPermissionsFilter

from permissible.models.permissible_mixin import PermissibleMixin
from permissible.perm_def.composite import CompositePermDef
from permissible.permissions import PermissiblePerms


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


class ForceListPermissibleFilter(filters.BaseFilterBackend):
    """
    Filter the queryset based on the first attribute in the attribute chain
    of the `obj_getter` for the "list" action.

    e.g. for listable "survey questions", we might want to return those
    survey questions that are owned by "surveys" to which this user has
    access

    Note that this filter is expected to work in conjunction with the permissions
    framework. The "list" permissions will already have been checked by default
    if you are using `PermissiblePerms`. Assertions guarantee that
    `PermissiblePerms` is being used.

    NOTE: we do not perform filtering for non-list routes
    """

    def filter_queryset(self, request, queryset, view):
        if view.action != "list":
            return queryset

        model_class = view.base_model

        assert issubclass(
            model_class, PermissibleMixin
        ), f"ForceListPermissibleFilter model ({model_class}) must be a subclass of PermissibleMixin"

        # Check that view has permission_classes with PermissiblePerms, OR
        # if permission_classes is empty then check the default permission_classes
        permission_classes = getattr(view, "permission_classes", [])
        if permission_classes:
            assert any(
                [
                    issubclass(permission, PermissiblePerms)
                    for permission in permission_classes
                ]
            ), f"ForceListPermissibleFilter view ({view}) must have a permission class of PermissiblePerms"
        else:
            default_permission_classes = getattr(
                settings, "REST_FRAMEWORK", dict()
            ).get("DEFAULT_PERMISSION_CLASSES", [])
            assert (
                "permissible.permissions.PermissiblePerms" in default_permission_classes
            ), f"ForceListPermissibleFilter view ({view}) must have a permission class of PermissiblePerms"

        # Get the PermDef for the "list" action
        list_perm_def = model_class.get_object_perm_map().get("list", None)

        # This PermDef must exist for us to find the first field in the attribute chain
        assert (
            list_perm_def
        ), f"ForceListPermissibleFilter model ({model_class}) must have a PermDef for 'list'"

        # If composite, all of the PermDefs must be for the same field
        if isinstance(list_perm_def, CompositePermDef):
            perm_defs = list_perm_def.perm_defs
        else:
            perm_defs = [list_perm_def]

        # Get the string `obj_getter` for the PermDef(s)
        obj_getters = [perm_def.obj_getter for perm_def in perm_defs]
        str_obj_getters = [
            obj_getter for obj_getter in obj_getters if isinstance(obj_getter, str)
        ]

        assert len(obj_getters) == len(
            str_obj_getters
        ), f"ForceListPermissibleFilter model ({model_class}) must have a string 'obj_getter' for all PermDefs for 'list'"

        attr_paths = set(str_obj_getters)

        assert (
            len(attr_paths) == 1
        ), f"ForceListPermissibleFilter model ({model_class}) must have the same 'obj_getter' for all PermDefs for 'list'"

        # Now check that first item in the attribute chain (and turn it into the actual
        # key, eg "team_id" instead of "team")
        attr_path = attr_paths.pop()
        first_attr = attr_path.split(".")[0]
        first_attr_field = getattr(model_class, first_attr).field
        first_attr_key = first_attr_field.attname

        # filterset_class = getattr(view, "filterset_class", None)
        # filterset_fields = getattr(filterset_class, "filterset_fields", None)

        # Ensure view is configured correctly (attribute key is in the filter)
        # if filterset_class:
        #     assert getattr(
        #         filterset_class, first_attr_key, None
        #     ), f"ForceListPermissibleFilter filterset class ({filterset_class}) must have a field '{first_attr_key}'"
        # elif filterset_fields:
        #     assert (
        #         first_attr_key in filterset_fields
        #     ), f"ForceListPermissibleFilter filterset fields ({filterset_fields}) must have a field '{first_attr_key}'"
        # else:
        #     assert (
        #         filterset_class or filterset_fields
        #     ), f"ForceListPermissibleFilter view ({view}) must have a 'filterset_class' or 'filterset_fields'"

        # Lastly, check that the attribute key is in the query params
        first_attr_value = request.query_params.get(first_attr_key)
        if not first_attr_value:
            raise PermissionDenied(
                f"ForceListPermissibleFilter query params must have a key '{first_attr_key}'"
            )

        # Filter the queryset down just to be sure
        # TODO: this isn't necessary, but it's to be doubly sure!
        return queryset.filter(**{first_attr_key: first_attr_value})
