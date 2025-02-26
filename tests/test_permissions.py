import unittest
from django.http import Http404
from permissible.permissions import PermissiblePerms, PermissiblePermsUnauthAllowed

# Pseudocode:
# 1. Create dummy classes to simulate request, user, view, queryset, model and object behavior.
#    - DummyUser: holds is_authenticated flag.
#    - DummyModel: class with classmethods has_global_permission, make_dummy_obj_from_query_params, and make_objs_from_data.
#       These methods return values based on preset flags.
#    - DummyObj: instance with an 'allowed' flag; its has_object_permission method returns that flag.
#    - DummyQuerySet: simple object with a 'model' attribute equal to DummyModel.
#    - DummyView: simulate a Django Rest Framework view; holds attributes like _ignore_model_permissions,
#      action, detail, query_params, data, and LIST_ACTIONS.
#
# 2. For each test case, create a dummy request with a DummyUser; create a dummy view; assign
#    a lambda to the permission instance's _queryset method that returns our DummyQuerySet.
#
# 3. Test various scenarios:
#    - Test that when view._ignore_model_permissions is True, has_permission returns True.
#    - Test that unauthenticated users are denied when the permission class requires authentication.
#    - Test that global permission being False causes has_permission to return False.
#    - Test the list action, ensuring that has_object_permission is evaluated on a dummy object.
#    - Test non-detail actions (e.g., create) with multiple dummy objects.
#    - Test for PermissiblePermsUnauthAllowed that unauthenticated users are processed.
#
# 4. Write tests in unittest and use absolute imports of PermissiblePerms and PermissiblePermsUnauthAllowed.


# Dummy classes for testing
class DummyUser:
    def __init__(self, is_authenticated):
        self.is_authenticated = is_authenticated


class DummyObj:
    def __init__(self, allowed=True):
        self.allowed = allowed

    def has_object_permission(self, user, action, context):
        return self.allowed


class DummyModel:
    # Class-level flag for global permission result
    global_permission = True

    @classmethod
    def has_global_permission(cls, user, action, context):
        return cls.global_permission

    @classmethod
    def make_dummy_obj_from_query_params(cls, params):
        # For testing, if params has key 'allow_obj' set to False, return denied object.
        allowed = params.get("allow_obj", True)
        return DummyObj(allowed=allowed)

    @classmethod
    def make_objs_from_data(cls, data):
        # Data is expected to be a list of dicts with key 'allow'
        objs = []
        for item in data:
            objs.append(DummyObj(allowed=item.get("allow", True)))
        return objs


class DummyQuerySet:
    # Return DummyModel as the model
    model = DummyModel


class DummyView:
    # Simulate a DRF view with required attributes
    def __init__(
        self,
        action,
        detail=True,
        ignore=False,
        query_params=None,
        data=None,
        list_actions=None,
    ):
        self._ignore_model_permissions = ignore
        self.action = action
        self.detail = detail
        self.query_params = query_params or {}
        self.data = data or []
        self.LIST_ACTIONS = list_actions if list_actions is not None else ("list",)


class DummyRequest:
    def __init__(self, user, query_params=None, data=None):
        self.user = user
        self.query_params = query_params or {}
        self.data = data or {}


class TestPermissiblePerms(unittest.TestCase):

    def setUp(self):
        # Reset global permission to default True before each test
        DummyModel.global_permission = True

    def get_permission_instance(self, permission_class):
        instance = permission_class()
        # Monkey-patch _queryset to return DummyQuerySet
        instance._queryset = lambda view: DummyQuerySet()
        return instance

    def test_ignore_model_permissions(self):
        # When view._ignore_model_permissions is True, has_permission should return True
        user = DummyUser(is_authenticated=False)
        view = DummyView(action="any", ignore=True)
        request = DummyRequest(user=user)
        perms = self.get_permission_instance(PermissiblePerms)
        result = perms.has_permission(request, view)
        self.assertTrue(result)

    def test_unauthenticated_denied_when_required(self):
        # When user is not authenticated and permission requires authentication, it should return False.
        user = DummyUser(is_authenticated=False)
        view = DummyView(action="retrieve", detail=True)
        request = DummyRequest(user=user)
        perms = self.get_permission_instance(PermissiblePerms)
        # In has_permission, if user is not authenticated and authenticated_users_only is True
        # (default in PermissiblePerms), then return False.
        result = perms.has_permission(request, view)
        self.assertFalse(result)

    def test_global_permission_false(self):
        # Authenticated user but global permission check fails should return False.
        DummyModel.global_permission = False
        user = DummyUser(is_authenticated=True)
        view = DummyView(action="retrieve", detail=True)
        request = DummyRequest(user=user)
        perms = self.get_permission_instance(PermissiblePerms)
        result = perms.has_permission(request, view)
        self.assertFalse(result)

    def test_list_action_object_permission_true(self):
        # Test list action where dummy object's has_object_permission returns True.
        user = DummyUser(is_authenticated=True)
        # In list action, detail is not applicable; simulate with action in LIST_ACTIONS.
        query_params = {"allow_obj": True}
        view = DummyView(action="list", detail=True, query_params=query_params)
        request = DummyRequest(user=user, query_params=query_params)
        perms = self.get_permission_instance(PermissiblePerms)
        result = perms.has_permission(request, view)
        self.assertTrue(result)

    def test_non_detail_action_with_multiple_objects_all_allowed(self):
        # For actions like create (non-detail), has_permission returns True if all dummy objs allow access.
        user = DummyUser(is_authenticated=True)
        # detail False to simulate non-detail action like create.
        data = [{"allow": True}, {"allow": True}]
        view = DummyView(action="create", detail=False)
        request = DummyRequest(user=user, data=data)
        perms = self.get_permission_instance(PermissiblePerms)
        result = perms.has_permission(request, view)
        self.assertTrue(result)

    def test_non_detail_action_with_multiple_objects_one_denied(self):
        # Test non-detail action where one of the dummy objects denies permission.
        user = DummyUser(is_authenticated=True)
        data = [{"allow": True}, {"allow": False}]
        view = DummyView(action="create", detail=False)
        request = DummyRequest(user=user, data=data)
        perms = self.get_permission_instance(PermissiblePerms)
        # Since one object returns False, overall result should be False.
        result = perms.has_permission(request, view)
        self.assertFalse(result)


class TestPermissiblePermsUnauthAllowed(unittest.TestCase):

    def setUp(self):
        DummyModel.global_permission = True

    def get_permission_instance(self, permission_class):
        instance = permission_class()
        # Monkey-patch _queryset to return DummyQuerySet
        instance._queryset = lambda view: DummyQuerySet()
        return instance

    def test_unauthenticated_allowed_but_checked(self):
        # For PermissiblePermsUnauthAllowed, even unauthenticated users are checked.
        user = DummyUser(is_authenticated=False)
        view = DummyView(action="retrieve", detail=True)
        request = DummyRequest(user=user)
        perms = self.get_permission_instance(PermissiblePermsUnauthAllowed)
        # In our dummy setup, global permission is True.
        # However, in has_permission, if not authenticated, it returns False unless _ignore_model_permissions is True.
        result = perms.has_permission(request, view)
        self.assertFalse(result)

    def test_ignore_model_permissions_with_unauthenticated(self):
        # When _ignore_model_permissions is True, even an unauthenticated user passes.
        user = DummyUser(is_authenticated=False)
        view = DummyView(action="retrieve", detail=True, ignore=True)
        request = DummyRequest(user=user)
        perms = self.get_permission_instance(PermissiblePermsUnauthAllowed)
        result = perms.has_permission(request, view)
        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()
