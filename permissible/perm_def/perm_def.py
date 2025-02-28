"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from typing import List, Type, Union, Optional, Callable

from django.contrib.auth.models import PermissionsMixin

from .model_resolver import LazyModelResolverMixin
from .short_perms import ShortPermsMixin


class BaseObj(ShortPermsMixin, LazyModelResolverMixin):
    pass


class PermDef:
    """
    A simple data structure to hold instructions for permissions configuration.

    Examples:
        PermDef(["view"], obj_getter=lambda o, c: o.project.team)
        PermDef([], condition_checker=lambda o, u, c: o.is_public)
        PermDef(["view", "change"], condition_checker=lambda o, u: not o.is_public and u.is_superuser)
    """

    def __init__(
        self,
        short_perm_codes: Optional[List[str]],
        obj_getter: Optional[
            Union[Callable[[object, object], Optional[BaseObj]], str]
        ] = None,
        condition_checker: Optional[
            Union[Callable[[object, object, object], bool], str]
        ] = None,
    ):
        """
        Initialize.
        :param short_perm_codes: A list of short permission codes, e.g. ["view", "change"]
        :param obj_getter: A function that takes an initial object and returns the obj to check
        object, e.g. a "survey" might be the object to check for "survey question" objects, OR
        a string that is a path of attributes to get the object from the initial object,
        excluding the initial clas (e.g. "survey.project.team" for a Question model)
        :param condition_checker: A function/str that takes an object, the user, and additional
        context, and returns a boolean, which is AND'd with the result of user.has_perms to
        return whether permission is successful
        """
        self.short_perm_codes = short_perm_codes
        self.obj_getter = obj_getter
        self.condition_checker = condition_checker

    def check_global(
        self,
        obj_class: Type[BaseObj],
        user: PermissionsMixin,
        context=None,
    ):
        """
        Check global permissions
        """
        return self._check(
            must_check_obj=False,
            obj=None,
            obj_class=obj_class,
            user=user,
            context=context,
        )

    def check_obj(
        self,
        obj: BaseObj,
        user: PermissionsMixin,
        context=None,
    ):
        """
        Check object permissions
        """
        return self._check(
            must_check_obj=True,
            obj=obj,
            obj_class=obj.__class__,
            user=user,
            context=context,
        )

    def _check(
        self,
        must_check_obj: bool,
        obj: Optional[BaseObj],
        obj_class: Type[BaseObj],
        user: PermissionsMixin,
        context=None,
    ):
        """ """
        # Try to get the necessary object (if object-level permissions, fail if no obj found)
        obj = self.get_obj_to_check(obj=obj, context=context)
        if must_check_obj and (not obj or not obj.pk):
            return False

        # Check the "condition checker"
        obj_check_passes = self.check_condition(obj=obj, user=user, context=context)

        # If short_perm_codes is None, we cannot pass permissions
        # (note that if short_perm_codes is [], permissions WILL ALWAYS pass)
        if self.short_perm_codes is None:
            return False

        # Actually check permissions!
        perms = obj_class.get_permission_codenames(self.short_perm_codes)
        has_perms = user.has_perms(perms, obj)

        # Both `has_perms` and `check_condition` must have passed
        if has_perms and obj_check_passes:
            return True

        return False

    def get_obj_to_check(
        self,
        obj: Optional[BaseObj],
        context=None,
    ) -> Optional[BaseObj]:
        """
        Using the provided object and context, return the actual object for which we will
        be checking permissions.

        :param obj: Initial object, from which to find the object to check perms on
        :param context: Context dictionary for additional context
        :return: Object for which permissions will be checked
        """
        # Getter function is set - use it
        if self.obj_getter:

            # Getter function is a string (member of object)...
            if isinstance(self.obj_getter, str):
                assert obj, "Object must be provided to get object from"
                return obj.get_unretrieved(self.obj_getter)

            # ...or getter function is a lambda
            return self.obj_getter(obj, context)

        # Getter function is not set - return the original object
        return obj

    def check_condition(self, obj, user, context=None) -> bool:
        """
        Using the provided object, context, and user, perform the condition check
        for this `PermDef`, if one was provided.

        :param obj: Initial object, from which to find the object to check perms on
        :param user: Authenticating user
        :param context: Context dictionary for additional context
        :return: Did check pass?
        """
        # No checker - check passes by default
        if not self.condition_checker:
            return True

        # Checker function is a string (member of object)...
        if isinstance(self.condition_checker, str):
            return getattr(obj, self.condition_checker)(user, context)

        # ...or checker function is a lambda
        return self.condition_checker(obj, user, context)

    def __or__(self, other):
        from .composite import CompositePermDef

        if not isinstance(other, PermDef):
            return NotImplemented
        return CompositePermDef([self, other], "or")

    def __and__(self, other):
        from .composite import CompositePermDef

        if not isinstance(other, PermDef):
            return NotImplemented
        return CompositePermDef([self, other], "and")


# Shorthand alias for the class
p = PermDef
