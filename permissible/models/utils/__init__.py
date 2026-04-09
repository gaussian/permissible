from .assign import *
from .clear import *
from .reset import *

# Exposed for tests — these are guardian-coupled internals
from .update import guardian_bulk_update_permissions, ObjectGroupPermSpec

# Backwards compatibility alias
bulk_update_permissions_for_objects = guardian_bulk_update_permissions
