"""
Neutron (a Visor module)
Author: Kut Akdogan
(c) 2016- Gaussian Holdings, LLC.

This codebase is confidential and proprietary.
No license for use, viewing, or reproduction without explicit written permission.
"""

from rest_framework.permissions import IsAuthenticated


class NoPermissionsIfListMixin:
    def get_permissions(self):
        # For certain actions, don't bother checking for permissions, as
        # we filter down the objects that are returned (listing/searching),
        # or check permissions some other way
        list_actions = getattr(self, "LIST_ACTIONS", ("list",))
        if self.action in list_actions:
            return [IsAuthenticated()]
        return super().get_permissions()
