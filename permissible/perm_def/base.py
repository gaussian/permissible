from typing import Optional, Type

from django.contrib.auth.models import PermissionsMixin

from .short_perms import ShortPermsMixin
from .model_resolver import LazyModelResolverMixin


class BasePermDefObj(ShortPermsMixin, LazyModelResolverMixin):
    pass


class BasePermDef:
    def check_global(
        self,
        obj_class: Type[BasePermDefObj],
        user: PermissionsMixin,
        context: Optional[dict] = None,
    ):
        raise NotImplementedError

    def check_obj(
        self,
        obj: BasePermDefObj,
        user: PermissionsMixin,
        context: Optional[dict] = None,
    ):
        raise NotImplementedError

    def filter_queryset(self, queryset, user, context=None):
        raise NotImplementedError

    def __or__(self, other):
        raise NotImplementedError

    def __and__(self, other):
        raise NotImplementedError
