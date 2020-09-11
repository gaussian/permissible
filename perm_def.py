from typing import List, Union, Optional, Callable


class PermDef:
    """
    A simple data structure to hold instructions for permissions configuration.

    Examples:
        PermDef(["change"], obj_getter=PermissibleMixin.get_permissions_root_obj
        PermDef(["view"], obj_getter=lambda o, c: o.project.team)
        PermDef([], condition_checker=lambda o, u, c: o.is_public)
        PermDef(["view", "change"], condition_checker=lambda o, u: not o.is_public and u.is_superuser)
    """

    def __init__(self, short_perm_codes: Optional[List[str]],
                 obj_getter: Optional[Union[Callable[[object, object], object], str]] = None,
                 condition_checker: Optional[Union[Callable[[object, object, object], bool], str]] = None):
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

    def get_obj(self, obj, context=None) -> object:
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
