"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from functools import lru_cache
from typing import TYPE_CHECKING, Type

from permissible.perm_def import p

from ..mixins import PermissibleCreateIfAuthPerms
from ..permissible_mixin import PermissibleMixin

if TYPE_CHECKING:
    from .core import PermDomain


class DomainOwnedPermMixin(PermissibleMixin):
    """
    A special permissions-checking mixin that checks permissions on the owning
    domain of an object/model. The permissions themselves relate to the domain
    object, not the child object.
    """

    PERM_DOMAIN_ATTR_PATH = None

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if cls.PERM_DOMAIN_ATTR_PATH is None:
            raise NotImplementedError(
                f"{cls.__name__} must define the class variable PERM_DOMAIN_ATTR_PATH"
            )

    def get_domain(self) -> PermDomain:
        """
        Return the PermDomain object associated with this instance.
        """
        assert self.PERM_DOMAIN_ATTR_PATH is not None
        domain = self.get_unretrieved(self.PERM_DOMAIN_ATTR_PATH)

        if not domain:
            raise ValueError(f"{self} has no associated domain")

        return domain

    @classmethod
    @lru_cache(maxsize=None)
    def get_domain_class(cls) -> Type[PermDomain]:
        """
        Return the class of PermDomain object associated with this model.
        """
        assert cls.PERM_DOMAIN_ATTR_PATH is not None
        domain_class = cls.get_unretrieved_class(cls.PERM_DOMAIN_ATTR_PATH)

        assert domain_class, f"{cls} has no associated domain class"

        return domain_class

    def get_root_perm_object(self) -> PermDomain:
        """
        Return the permissions root (i.e. PermDomain object) for this instance.
        """
        return self.get_domain()

    @classmethod
    def get_room_perm_class(cls) -> Type[PermDomain]:
        """
        Return the permissions root class (i.e. PermDomain) for this model.
        """
        return cls.get_domain_class()


class DefaultDomainOwnedPermMixin(DomainOwnedPermMixin, PermissibleCreateIfAuthPerms):
    """
    A default configuration of DomainOwnedPermMixin that specifies some default
    permissions for actions (perm_codes are "add_on" and so forth).

    Note also that no global checks are done.
    """

    obj_action_perm_map = {
        "create": p(["add_on"]),
        "list": p(["view"]),
        "retrieve": p(["view"]),
        "update": p(["change_on"]),
        "partial_update": p(["change_on"]),
        "destroy": p(["change_on"]),
    }


class SimpleDomainOwnedPermMixin(DomainOwnedPermMixin, PermissibleCreateIfAuthPerms):
    """
    An alternative configuration of DomainOwnedPermMixin that specifies some
    alternative permissions. Specifically, it doesn't require the"add_on_XXX"
    and "change_on_XXX" permissions.

    Note that having "change" permission on the domain object confers "create"
    permission on the original (child) object.

    Note also that no global checks are done.
    """

    obj_action_perm_map = {
        "create": p(["change"]),
        "list": p(["view"]),
        "retrieve": p(["view"]),
        "update": p(["change"]),
        "partial_update": p(["change"]),
        "destroy": p(["change"]),
    }
