"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from .perm_def import PermDef


class CompositePermDef(PermDef):
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

    def check_global(self, obj_class, user, context=None):
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
