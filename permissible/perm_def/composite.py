"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from typing import Iterable, Optional, Type

from django.contrib.auth.models import PermissionsMixin

from .base import BasePermDef, BasePermDefObj


class CompositePermDef(BasePermDef):
    """
    A composite permission definition that combines multiple PermDef objects with logical operators.

    This class allows for complex permission rules by combining multiple PermDef instances
    using logical AND or OR operations. This enables building sophisticated permission checks
    that would be difficult to express in a single PermDef.

    The composite behaves as a single PermDef and implements the same interface, making it
    suitable for use anywhere a regular PermDef is expected (Composition pattern).

    Examples:
        # Create a permission that requires either admin access OR ownership
        admin_perm = PermDef(["admin"], condition_checker=lambda o, u, c: u.is_admin)
        owner_perm = PermDef(["view"], condition_checker=lambda o, u, c: o.owner == u)
        combined = CompositePermDef([admin_perm, owner_perm], "or")

        # Using the overloaded operators for more readable code
        combined = admin_perm | owner_perm

        # Check if a user has complex permission (view AND edit) OR is an admin
        complex_perm = (view_perm & edit_perm) | admin_perm
    """

    def __init__(self, perm_defs, operator):
        """
        Initialize a composite permission definition.

        Args:
            perm_defs (list): A list of PermDef objects to be combined
            operator (str): The logical operator to use - either "and" or "or"
                - "and": All permission definitions must pass for permission to be granted
                - "or": At least one permission definition must pass for permission to be granted

        Raises:
            ValueError: If the operator is not "and" or "or"
        """
        # We don't call super().__init__() because CompositePermDef works differently
        # than a regular PermDef - it delegates to child PermDefs rather than
        # performing checks directly

        # Store the list of permission definitions to delegate to
        self.perm_defs = perm_defs

        # Validate the operator
        if operator not in ("and", "or"):
            raise ValueError("Operator must be 'and' or 'or'")
        self.operator = operator

    def check_global(
        self,
        obj_class: Type[BasePermDefObj],
        user: PermissionsMixin,
        context: Optional[dict] = None,
    ):
        """
        Check if the user has global permissions according to the composite rule.

        Delegates to the constituent PermDef objects and combines their results
        according to the specified operator.

        Args:
            obj_class: The class to check permissions against
            user: The user requesting permission
            context: Optional additional context for the permission check

        Returns:
            bool: True if permission is granted, False otherwise
        """
        # For OR: permission granted if any one passes.
        if self.operator == "or":
            return any(
                perm.check_global(obj_class, user, context) for perm in self.perm_defs
            )
        # For AND: permission granted only if all pass.
        else:  # operator == "and"
            return all(
                perm.check_global(obj_class, user, context) for perm in self.perm_defs
            )

    def check_obj(self, obj, user, context=None):
        """
        Check if the user has object-level permissions according to the composite rule.

        Delegates to the constituent PermDef objects and combines their results
        according to the specified operator.

        Args:
            obj: The object to check permissions for
            user: The user requesting permission
            context: Optional additional context for the permission check

        Returns:
            bool: True if permission is granted, False otherwise
        """
        # For OR operator, if any permission passes, grant access
        if self.operator == "or":
            return any(perm.check_obj(obj, user, context) for perm in self.perm_defs)
        # For AND operator, all permissions must pass to grant access
        else:  # operator == "and"
            return all(perm.check_obj(obj, user, context) for perm in self.perm_defs)

    def filter_queryset(self, queryset, user, context=None):
        """
        Filter a queryset down to the objects permitted by this CompositePermDef.
        Combines child PermDefs using logical AND or OR.
        """
        # Safety check: if no child perm_defs, just return none()
        if not self.perm_defs:
            return queryset.none()

        # For AND logic, we can short-circuit if any perm_def returns empty queryset
        if self.operator == "and":
            for perm_def in self.perm_defs:
                # For each perm_def, check if its pre-check would fail
                # If it's a PermDef with None short_perm_codes, it will always fail
                if getattr(perm_def, "short_perm_codes", None) is None:
                    return queryset.none()

                # Also check if global condition would fail (no need to filter then)
                if hasattr(perm_def, "check_global_condition"):
                    if not perm_def.check_global_condition(user, context):
                        return queryset.none()

        # Get filtered querysets from all child PermDefs
        filtered_querysets = []
        for perm_def in self.perm_defs:
            child_qs = perm_def.filter_queryset(queryset, user, context=context)
            filtered_querysets.append(child_qs)

            # Short circuit for AND: if any queryset is empty, result will be empty
            if self.operator == "and" and not child_qs.exists():
                return queryset.none()

        # Combine results based on operator
        if not filtered_querysets:
            return queryset.none()

        result = filtered_querysets[0]
        for qs in filtered_querysets[1:]:
            if self.operator == "or":
                result = result.union(qs)
            else:  # self.operator == "and"
                result = result.intersection(qs)

        return result

    def iter_perm_defs(self) -> Iterable[BasePermDef]:
        """
        Yield every *leaf* PermDef contained in this composite,
        descending through any nested CompositePermDefs.

        Example
        -------
        >>> for perm in combined.iter_perm_defs():
        ...     print(perm)
        """
        for perm_def in self.perm_defs:
            yield from perm_def.iter_perm_defs()

    def __or__(self, other):
        """
        Overloaded | operator for combining permissions with OR logic.

        This allows for a more readable syntax when combining permission definitions:
        `perm1 | perm2` instead of `CompositePermDef([perm1, perm2], "or")`

        Args:
            other: Another PermDef instance to combine with this one

        Returns:
            CompositePermDef: A new composite with OR logic
        """
        # If self is already an OR composite, flatten the structure by adding to the existing list
        # This prevents unnecessary nesting of composites which would affect performance
        if self.operator == "or":
            new_list = self.perm_defs + [other]
        else:
            new_list = [self, other]
        return CompositePermDef(new_list, "or")

    def __and__(self, other):
        """
        Overloaded & operator for combining permissions with AND logic.

        This allows for a more readable syntax when combining permission definitions:
        `perm1 & perm2` instead of `CompositePermDef([perm1, perm2], "and")`

        Args:
            other: Another PermDef instance to combine with this one

        Returns:
            CompositePermDef: A new composite with AND logic
        """
        # If self is already an AND composite, flatten the structure by adding to the existing list
        # This prevents unnecessary nesting of composites which would affect performance
        if self.operator == "and":
            new_list = self.perm_defs + [other]
        else:
            new_list = [self, other]
        return CompositePermDef(new_list, "and")
