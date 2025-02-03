"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from typing import List, Union, Optional, Callable


class ShortPermsMixin(object):
    @classmethod
    def get_permission_codename(cls, short_permission):
        return f"{cls._meta.app_label}.{short_permission}_{cls._meta.model_name}"

    @classmethod
    def get_permission_codenames(cls, short_permissions):
        return [cls.get_permission_codename(sp) for sp in short_permissions]


class PermDef:
    """
    A simple data structure to hold instructions for permissions configuration.

    Examples:
        PermDef(["change"], obj_getter=PermissibleMixin.get_permissions_root_obj
        PermDef(["view"], obj_getter=lambda o, c: o.project.team)
        PermDef([], condition_checker=lambda o, u, c: o.is_public)
        PermDef(["view", "change"], condition_checker=lambda o, u: not o.is_public and u.is_superuser)
    """

    def __init__(
            self,
            short_perm_codes: Optional[List[str]],
            obj_getter: Optional[Union[Callable[[object, object], ShortPermsMixin], str]] = None,
            condition_checker: Optional[Union[Callable[[object, object, object], bool], str]] = None
    ):
        """
        Initialize.
        :param short_perm_codes: A list of short permission codes, e.g. ["view", "change"]
        :param obj_getter: A function/str that takes an initial object and returns its root
        object, e.g. a "survey" might be the root of "survey question" objects
        :param condition_checker: A function/str that takes an object, the user, and additional
        context, and returns a boolean, which is AND'd with the result of user.has_perms to
        return whether permission is successful
        """
        self.short_perm_codes = short_perm_codes
        self.obj_getter = obj_getter
        self.condition_checker = condition_checker

    def check_global(self, user, context=None):
        """
        Check global permissions
        :return:
        """
        return self._check(is_obj=False, obj=None, user=user, context=context)

    def check_obj(self, obj: ShortPermsMixin, user, context=None):
        """
        Check object permissions
        :return:
        """
        return self._check(is_obj=True, obj=obj, user=user, context=context)

    def _check(self, is_obj: bool, obj: Optional[ShortPermsMixin], user, context=None):
        """
        """
        # Try to get the necessary object (if object-level permissions, fail if no obj found)
        obj = self.get_obj(obj=obj, context=context)
        if is_obj and (not obj or not obj.pk):
            return False

        # Check the "condition checker"
        obj_check_passes = self.check_condition(obj=obj, user=user, context=context)

        # Check permissions
        if self.short_perm_codes is None:
            has_perms = True
        else:
            perms = obj.get_permission_codenames(self.short_perm_codes)
            has_perms = user.has_perms(perms, obj)

        # Both `has_perms` and `check_condition` must have passed
        if has_perms and obj_check_passes:
            return True

    def get_obj(self, obj: ShortPermsMixin, context=None) -> ShortPermsMixin:
        """
        Using the provided object and context, return the actual object for which we will
        be checking permissions.

        :param obj: Initial object, from which to find root object
        :param context: Context dictionary for additional context
        :return: Object (root object) for which permissions will be checked
        """
        # Getter function is set - use it
        if self.obj_getter:

            # Getter function is a string (member of object)...
            if isinstance(self.obj_getter, str):
                return getattr(obj, self.obj_getter)(context)

            # ...or getter function is a lambda
            return self.obj_getter(obj, context)

        # Getter function is not set - return the original object
        return obj

    def check_condition(self, obj, user, context=None) -> bool:
        """
        Using the provided object, context, and user, perform the condition check
        for this `PermDef`, if one was provided.

        :param obj: Initial object, from which to find root object
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


ALLOW_ALL = None
DENY_ALL = []

IS_AUTHENTICATED = PermDef(None, condition_checker=lambda o, u, c: bool(u.id))
IS_PUBLIC = PermDef(None, condition_checker=lambda o, u, c: o.is_public)
