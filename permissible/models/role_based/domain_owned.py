"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from functools import lru_cache
from typing import Type

from permissible.perm_def import p

from .core import PermDomain
from ..mixins import PermissibleCreateIfAuthPerms
from ..permissible_mixin import PermissibleMixin


class DomainOwnedPermMixin(PermissibleMixin):
    """
    A specialized permissions-checking mixin for objects owned by a domain entity.

    This mixin checks permissions on the owning domain object, rather than on the model
    itself. This approach is useful for hierarchical models where permission logic
    is managed at a higher level in the hierarchy.

    Attributes:
        PERM_DOMAIN_ATTR_PATH (str): Path to the attribute that holds the domain object,
            excluding the model itself. Must be set in subclasses.
            Examples:
            - For a team-owned project: "team"
            - For a file in a team-owned project: "project.team"
            - For a question in a survey in a team-owned project: "survey.project.team"

    Methods:
        get_domain(): Returns the PermDomain object associated with this instance.
        get_domain_class(): Returns the class of PermDomain object associated with this model.
        get_root_perm_object(): Returns the permissions root object for this instance.
        get_room_perm_class(): Returns the permissions root class for this model.

    Raises:
        ValueError: If no domain object is associated with the instance.
        AssertionError: If PERM_DOMAIN_ATTR_PATH is not set or no domain class is found.

    Example:
        ```python
        class Project(DomainOwnedPermMixin, models.Model):
            PERM_DOMAIN_ATTR_PATH = "team"
            team = models.ForeignKey(Team, on_delete=models.CASCADE)
            # ...
        ```

    A special permissions-checking mixin that checks permissions on the owning
    domain of an object/model. The permissions themselves relate to the domain
    object, not the child object.
    """

    # The path to the attribute that holds the domain object. This excludes the
    # model itself. For example, if the domain object is a ForeignKey field on
    # the model, this should be the name of the field.
    # Examples:
    # For a (team-owned) project: "team"
    # For a file inside a team-owned project: "project.team"
    # For a question in a survey in a team-owned project "survey.project.team"
    PERM_DOMAIN_ATTR_PATH = None

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
