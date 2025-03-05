from .short_perms import ShortPermsMixin
from .model_resolver import LazyModelResolverMixin


class BasePermDefObj(ShortPermsMixin, LazyModelResolverMixin):
    pass
