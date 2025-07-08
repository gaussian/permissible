"""
`permissible` (a `neutron` module by Gaussian)
Author: Kut Akdogan & Gaussian Holdings, LLC. (2016-)
"""

from typing import Any, Type, Optional, Callable

from django.apps import apps
from django.contrib.auth.models import PermissionsMixin

from .base import BasePermDefObj, BasePermDef


class PermDef(BasePermDef):
    """
    A simple data structure to hold instructions for permissions configuration.

    This class allows defining permissions using short permission codes, object getters,
    and condition checkers. It supports both global and object-level permission checks.

    Examples:
        Define a permission that checks for "view" permission on the object's project's team
        `PermDef(["view"], obj_path="project.team")`

        Define a permission that checks if the object is public
        `PermDef([], global_condition_checker=lambda o, u, c: o.is_public)`

        Define a permission that checks for "view" and "change" permissions and if the user is a superuser
        `PermDef(["view", "change"], condition_checker=lambda o, u: not o.is_public and u.is_superuser)`
    """

    def __init__(
        self,
        short_perm_codes: Optional[list[str]],
        obj_path: Optional[str] = None,
        obj_filter: Optional[tuple[str, str, Any]] = None,
        global_condition_checker: Optional[Callable[[object, object], bool]] = None,
        allow_blank: bool = False,
        model_label: Optional[str] = None,
    ):
        """
        Initialize.
        :param short_perm_codes: A list of short permission codes, e.g. ["view", "change"].
        :param obj_path: A string that is a path of attributes to get the object from the
        input object, excluding the initial class (e.g. "survey.project.team" for a Question
        model). If not provided, the input object will be used. If the first element is "_context",
        then we will try to get the object from the context that is also provided to the check.
        :param obj_filter: A tuple of strings for additional filtering on the object in the format of (obj_attr, operator, needed_value)). Needed value can also be a path starting with "_context" to get the value from the context (e.g. ("project_id", "==", "_context.project_id")).
        :param global_condition_checker: A function/str that takes the user and additional
        context, and returns a boolean, which is AND'd with the result of user.has_perms to
        return whether permission is successful.
        :param allow_blank: If True, the obejct permission will pass if the object is None.
        :param model_label: A string that is the label of the model to be used in the permission
        check. If not provided, the model of the input object will be used. This should usually
        be `None` unless you are checking permissions on a model referenced from the context object
        (i.e. `obj_path` starts with "_context.").
        """
        self.short_perm_codes = short_perm_codes
        self.obj_filter = obj_filter
        self.global_condition_checker = global_condition_checker
        self.allow_blank = allow_blank
        self.model_label = model_label

        # Parse the obj_path
        # (if the first element is "_context", then we will try to get the object
        # from the context when it is provided to the check functions)
        self.obj_path = obj_path
        self.obj_path_chain = obj_path.split(".") if obj_path else []
        self.key_to_obj_in_context = None
        if self.obj_path_chain:
            if self.obj_path_chain[0] == "_context":
                assert (
                    len(self.obj_path_chain) == 2
                ), f"If obj_path starts with '_context', it must have exactly one more key in the chain, got {self.obj_path_chain}"
                assert (
                    self.model_label
                ), "If obj_path starts with '_context', model_label must be provided"
                self.key_to_obj_in_context = self.obj_path_chain[1]
            else:
                assert (
                    not self.model_label
                ), "Model label should not be provided if using obj_path but not using _context"

    def __repr__(self):
        """
        String representation of the permission definition.
        """
        return (
            f"PermDef(short_perm_codes={self.short_perm_codes}, "
            f"obj_path={self.obj_path}, "
            f"obj_filter={self.obj_filter}, "
            f"global_condition_checker={self.global_condition_checker}, "
            f"allow_blank={self.allow_blank}, "
            f"model_label={self.model_label})"
        )

    def check_global(
        self,
        obj_class: Type[BasePermDefObj],
        user: PermissionsMixin,
        context: Optional[dict] = None,
    ):
        """
        Check global permissions.
        """

        # Check the "condition checker" (and fail if it does not pass)
        if not self.check_global_condition(user=user, context=context):
            return False

        # Try to get the necessary object class
        if self.model_label:
            obj_class = apps.get_model(self.model_label)
        elif self.obj_path:
            obj_class = obj_class.get_unretrieved_class(self.obj_path)

        # Fail if no object class
        if not obj_class:
            return False

        assert (
            not self.obj_filter
        ), "Object filter not supported for global checks, check your ACTION_POLICIES"

        # Actually check global permissions
        return self._check_perms(user=user, obj_class=obj_class)

    def check_obj(
        self,
        obj: BasePermDefObj,
        user: PermissionsMixin,
        context=None,
    ):
        """
        Check object permissions.
        """

        assert obj, "Object must be provided to check object permissions"

        # Configuration check
        if not self.key_to_obj_in_context:
            assert (
                not self.model_label
            ), f"Cannot use model label ({self.model_label}) for object permissions check if not using '_context' (in `obj_path`) to get the model PK"

        # Check the "condition checker" (and fail if it does not pass)
        if not self.check_global_condition(user=user, context=context):
            return False

        # Get the necessary object, if not the current one
        # Get from context...
        if self.key_to_obj_in_context:
            assert context, "Context must be provided to get object from"
            obj_pk = context.get(self.key_to_obj_in_context)
            if not obj_pk:
                print(f"Warning: No {self.key_to_obj_in_context} found in context")
                return False
            obj_class = apps.get_model(self.model_label)
            try:
                obj = obj_class.objects.get(pk=obj_pk)
            except obj_class.DoesNotExist:
                print(f"Warning: Object with PK {obj_pk} does not exist")
                return False

        # ...or get by following the attribute path from the input object
        elif self.obj_path:
            obj = obj.get_unretrieved(self.obj_path)

        # No object was discovered (i.e. via obj_path or context), which means
        # no more checks are possible. The question is whether to allow or deny...
        if self.key_to_obj_in_context or self.obj_path:
            if not obj or not obj.pk:
                # ...which depends on self.allow_blank
                return self.allow_blank

        # Check object conditions
        if not self._check_obj_filter(obj, context):
            return False

        # Actually check object permissions
        return self._check_perms(user=user, obj=obj)

    def filter_queryset(
        self,
        queryset,
        user: PermissionsMixin,
        context=None,
    ):
        """
        Filter a queryset down to permitted objects.
        """
        from guardian.shortcuts import get_objects_for_user

        # Check the "condition checker" (and fail if it does not pass)
        if not self.check_global_condition(user=user, context=context):
            return queryset.none()

        # Choose the appropriate model for permissions checking
        obj_class: Type[BasePermDefObj] = queryset.model

        # If obj_path is set, we need to change our model class by following the path
        obj_query_path = None
        if self.obj_path and not self.key_to_obj_in_context:
            # eg obj_path = "survey.project.team" for a Question model
            chain_information = obj_class.resolve_chain(self.obj_path)
            # obj_class is the final model in the chain
            # eg Team for the Question model above
            obj_class = chain_information["final_model_class"]
            # Query path is the path from the original object for filtering
            # eg "survey__project__team_id" for the Question model above
            obj_query_path = chain_information["full_query_path"]
            # Get the queryset of all objects
            obj_queryset = obj_class.objects.all()

        # If obj_path is not set, we don't need to change our model class and can
        # use the original queryset
        else:
            obj_queryset = queryset

        # Apply the self.obj_filter
        obj_queryset = self._apply_obj_filter_to_queryset(obj_queryset, context)

        # In some cases we don't even need to check perms
        # If pre-check fails, return an empty queryset, but if it passes, continue
        # without doing perm checking (the reason we don't return immediately if
        # the pre-check succeeds is that we may still need to translate the
        # obj_queryset to the original model's queryset)
        perm_precheck = self._pre_check_perms()
        if perm_precheck is False:
            return queryset.none()

        # Pre-check didn't give an auto-success or failure:
        # Filter down to the objects that pass permissions
        if perm_precheck is None:
            perms = obj_class.get_permission_codenames(self.short_perm_codes, True)
            obj_queryset = get_objects_for_user(
                klass=obj_queryset,
                user=user,
                perms=perms,
                accept_global_perms=False,
            )

        # If obj_path is set, we need to translate this queryset to the original
        # model's queryset
        if self.obj_path:
            # Get the queryset of PKs of the objects that pass permissions
            obj_pks_queryset = obj_queryset.values_list("pk")
            # Get the query path to the primary key attribute
            # eg "survey__project__team_id__in" for the Question model above
            obj_pk_root_query_path = f"{obj_query_path}__in"
            # Filter the original queryset down to the objects that pass permissions
            queryset = queryset.filter(**{obj_pk_root_query_path: obj_pks_queryset})

        # Otherwise, we can just return the queryset we were manipulating
        else:
            queryset = obj_queryset

        return queryset

    def _check_obj_filter(
        self,
        obj: BasePermDefObj,
        context: Optional[dict] = None,
    ):
        if self.obj_filter:
            obj_attr, operator, _ = self.obj_filter
            needed_value = self._get_needed_value_for_obj_filter(context)
            obj_attr_chain = obj_attr.split(".")
            current_value = obj
            for attr in obj_attr_chain:
                current_value = getattr(current_value, attr)
            if operator == "==":
                if current_value != needed_value:
                    return False
            elif operator == "!=":
                if current_value == needed_value:
                    return False
            elif operator == ">":
                if current_value <= needed_value:
                    return False
            elif operator == "<":
                if current_value >= needed_value:
                    return False
            else:
                raise ValueError(f"Operator {operator} not supported")

        # Return True if there's no filter or if all checks pass
        return True

    def _apply_obj_filter_to_queryset(
        self,
        queryset,
        context: Optional[dict] = None,
    ):
        if self.obj_filter:
            obj_attr, operator, _ = self.obj_filter
            needed_value = self._get_needed_value_for_obj_filter(context)
            queryset_kwarg = obj_attr.replace(".", "__")
            if operator == "==":
                queryset = queryset.filter(**{queryset_kwarg: needed_value})
            elif operator == "!=":
                queryset = queryset.exclude(**{queryset_kwarg: needed_value})
            elif operator == ">":
                queryset = queryset.filter(**{queryset_kwarg + "__gt": needed_value})
            elif operator == "<":
                queryset = queryset.filter(**{queryset_kwarg + "__lt": needed_value})
            else:
                raise ValueError(f"Operator {operator} not supported")
        return queryset

    def _get_needed_value_for_obj_filter(
        self,
        context: Optional[dict] = None,
    ):
        if self.obj_filter:
            _, _, needed_value = self.obj_filter

            # If it's not a string, return it directly (handles numbers, booleans, etc)
            if not isinstance(needed_value, str):
                return needed_value

            # Otherwise, handle string values which might be context paths
            needed_value_chain = needed_value.split(".")
            if needed_value_chain[0] == "_context":
                assert context, "Context must be provided to get object from"
                current_value = context[needed_value_chain[1]]
                # Use getattr for the remaining path components (after context lookup)
                for key in needed_value_chain[2:]:
                    if hasattr(current_value, key):
                        current_value = getattr(current_value, key)
                    else:
                        current_value = current_value[key]
                return current_value
            else:
                # Regular string value (not a context path)
                return needed_value

    def _pre_check_perms(self):
        # If short_perm_codes is None, we cannot pass permissions
        if self.short_perm_codes is None:
            return False

        # If short_perm_codes is [] (empty), permissions WILL ALWAYS pass
        # (this is useful for objects that are always public, or when we
        # want to check a condition eg "is authenticated" earlier without
        # checking permissions)
        if len(self.short_perm_codes) == 0:
            return True

        return None

    def _check_perms(
        self,
        user: PermissionsMixin,
        obj_class: Optional[Type[BasePermDefObj]] = None,
        obj: Optional[BasePermDefObj] = None,
    ):
        assert obj or obj_class, "Either obj or obj_class must be provided"
        obj_class = obj_class or obj.__class__
        assert obj_class

        assert not obj or hasattr(obj, "pk"), "The object must have a primary key."

        # In some cases we don't even need to check perms
        perm_precheck = self._pre_check_perms()
        if perm_precheck is not None:
            return perm_precheck

        # Get full permission codenames
        perms = obj_class.get_permission_codenames(self.short_perm_codes, True)

        # Check perms (if obj is None, we are checking global perms)
        return user.has_perms(perms, obj)

    def get_obj_to_check(
        self,
        obj: Optional[BasePermDefObj],
    ) -> Optional[BasePermDefObj]:
        """
        Using the provided object and context, return the actual object for which we will
        be checking permissions.

        :param obj: Initial object, from which to find the object to check perms on
        :param context: Context dictionary for additional context
        :return: Object for which permissions will be checked
        """
        # Obj path is set (i.e. a chain of attributes)...
        if self.obj_path:
            assert obj, "Object must be provided to get object from"
            return obj.get_unretrieved(self.obj_path)

        # Getter function is not set - return the original object
        return obj

    def check_global_condition(self, user, context=None) -> bool:
        """
        Using the provided object, context, and user, perform the condition check
        for this `PermDef`, if one was provided.

        :param user: Authenticating user
        :param context: Context dictionary for additional context
        :return: Did check pass?
        """
        # No checker - check passes by default
        if not self.global_condition_checker:
            return True

        # Ryun checker function
        return self.global_condition_checker(user, context)

    def iter_perm_defs(self):
        """Yield myself so I acts like a 1-element collection."""
        yield self

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
        from .composite import CompositePermDef

        if not isinstance(other, PermDef):
            return NotImplemented
        return CompositePermDef([self, other], "or")

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
        from .composite import CompositePermDef

        if not isinstance(other, PermDef):
            return NotImplemented
        return CompositePermDef([self, other], "and")


# Shorthand alias for the class
p = PermDef
