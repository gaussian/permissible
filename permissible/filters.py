"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from rest_framework import filters

from permissible.models.permissible_mixin import PermissibleMixin
from permissible.utils.views import make_context_from_request
from permissible.views import CheckViewConfigMixin


class PermissibleFilter(CheckViewConfigMixin, filters.BaseFilterBackend):
    """
    A filter backend that limits results to those where the requesting user
    has read object level permissions, according to policies.

    Filtering is based on the actions in the ACTION_POLICIES (either "object"
    or "global") of the model class, e.g. for a model class "surveys.Survey"
    owned by its Survey.project, we might have the following:

    ```
    ACTION_POLICIES = {
        "surveys.Survey": {
            "object": {
                "retrieve": p(["view"], "project"),
                ...
            },
        }
    }
    ```

    Note that if the "list" action policy is not defined, the "retrieve" policy
    will be used for list actions.

    Note that this filter is expected to work in conjunction with the permissions
    framework. Assertions guarantee that `PermissiblePerms` is being used.

    THIS FILTER DOES NOT CHECK PERMISSIONS, instead it relies on the ACTION_POLICIES
    being correctly configured to check permissions. It DOES filter down to permitted
    objects based on the user's permissions.

    THIS FILTER DOES NOT FILTER DOWN BASED ON REQUEST QUERY PARAMETERS, this is
    done by a different filter backend (e.g. the default `DjangoFilterBackend`).

    NOTE: we do not perform filtering for detail routes.
    """

    def filter_queryset(self, request, queryset, view):
        if self.is_detail_view(view) or view.action in ("create", "delete"):
            return queryset

        # We require PermissiblePerms to be used on the view
        self._check_view_config(view, queryset)

        # Get permission config for us to filter down the queryset
        # (use "retrieve" if no permission is defined for "list")
        model_class: PermissibleMixin = queryset.model
        perm_def = model_class.get_object_perm_def(view.action)
        if not perm_def and view.action == "list":
            perm_def = model_class.get_object_perm_def("retrieve")

        assert (
            perm_def
        ), f"No object permission defined for {model_class} action '{view.action}'"

        # Filter down the queryset based on the permissions
        return perm_def.filter_queryset(
            queryset,
            request.user,
            context=make_context_from_request(request),
        )
