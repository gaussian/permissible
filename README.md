`permissible` is a module to make it easier to configure object-level permissions,
and to help unify the different places performing permissions checks (including DRF
and Django admin) to create a full permissions check that can work without any
further architectural pondering.

It is built on top of django-guardian but can be easily configured for other
object-level libraries.


# Introduction

This module allows us to define permission requirements in our Models
(similarly to how django-rules does it in Model.Meta). Given that different
view engines (e.g. DRF vs Django's admin) have different implementations for
checking permissions, this allows us to centralize the permissions
configuration and keep the code clear and simple. This approach also allows
us to unify permissions checks across both Django admin and DRF (and indeed
any other place you use PermissibleMixin).

# Installation

1. Install the package (use of `django-guardian` is optional but needed for most Features below):
   ```sh
   pip install permissible               # Django, djangorestframework
   pip install permissible[guardian]     # Same + django-guardian, djangorestframework-guardian
   ```

2. If using `django-guardian`, make sure to add the `ObjectPermissionsBackend` to your `AUTHENTICATION_BACKENDS` (otherwise enable object permissions in your own desired way):
    ```
    AUTHENTICATION_BACKENDS = (
        'django.contrib.auth.backends.ModelBackend',  # default
        'guardian.backends.ObjectPermissionBackend',
    )
    ```


# Features

## Feature 1: Consistent permissions configuration

In its simplest form, `permissible` can be used just for its permissions
configuration. This has no impact on your database, and does not rely on any
particular object-level permissions library. (It does require one; we prefer
django-guardian.)

Here, we add the `PermissibleMixin` to each model we want to protect, and
define "permissions maps" that define what permissions are needed for each action
that is taken on an object in the model (e.g. a "retrieve" action on a "survey").
(We can also use classes like `PermissibleDefaultPerms` to define good default
permission maps for our models.)

With the permissions configured, now we can force different views to use them:
- If you would like the permissions to work for API views (via
`django-rest-framework`): Add `PermissiblePerms` to the `permission_classes` for
the viewsets for our models
- If you would like the permissions to work in the Django admin: Add
`PermissibleAdminMixin` to the admin classes for our models

That's it. Actions are now protected by permissions checks. But there is no easy
way to create the permissions in the first place. That's where the next two
features come in.


## Feature 2: Simple, role-based permissions assignment using "root" models (RBAC)

The `permissible` library can also help automatically assign permissions based on
certain "root" models. The root model is the model we should check permissions
against. For instance, the root model for a "project file" might be a "project",
in which case having certain permissions on the "project" would confer other
permissions for the "project files", even though no specific permission exists
for the "project file".
Of course, it's easy to link a "project" to a "project file" through a foreign key.
But `permissible` solves the problem of tying this to the Django `Group` model,
which is what we use for permissions, according to **roles**.
Each resulting `Group` (managed on the backend) corresponds to a single role.

To accomplish this, `permissible` provides 3 base model classes that you should use:
1. **`PermRoot`**: Make the root model (e.g. `Team`) derive from `PermRoot`
2. **`PermRootGroup`**: Create a new model that derives from `PermRootGroup`
and has a `ForeignKey` to the root model - and defines `ROLE_DEFINITIONS`
3. **`PermRootUser`**: Create a new model that derives from `PermRootUser`
and has a `ForeignKey` to the root model (this model automatically adds and
removes records when a user is a member of the appropriate `PermRootGroup`)

You can then simply adjust your permissions maps in `PermissibleMixin` to
incorporate checking of the root model for permissions. See the documentation for
`PermDef` and `PermissibleMixin.has_object_permissions` for info and examples.

Remember: `PermRoot` is the core model on which roles are defined (eg Project or
Team) and `PermRootGroup` is the model that represents a single role (and
therefore a single Django `auth.Group`) for a single `PermRoot` - eg Team Admins.
The `PermRootGroup.ROLE_DEFINITIONS` defines what object permissions will be
given to each role/group for every `PermRoot`.

You can also use `PermRootAdminMixin` to help you manage the `PermRoot` records
and the subsequent role-based access control:

![RBAC admin](admin_1.png)


## Feature 3: Assignment on record creation

`permissible` can automatically assign object permissions on object creation,
through use of 3 view-related mixins:
- `admin.PermissibleObjectAssignMixin` (for admin classes - give creating user all
permissions)
- `serializers.PermissibleObjectAssignMixin` (for serializers - give creating user
all permissions)
- `serializers.PermissibleRootObjectAssignMixin` (for serializers for root models
like "Team" or "Project - add creating user to all root model's Groups)

NOTE: this feature is dependent on django-guardian, as it uses the `assign_perm`
shortcut. Also, `admin.PermissibleObjectAssignMixin` extends the
`ObjectPermissionsAssignmentMixin` mixin from djangorestframework-guardian.


# Core concepts

## PermissibleMixin:

- Add `PermissibleMixin` to any model you want to protect
- Define `global_action_perm_map` and `obj_action_perm_map` on each model, otherwise
  use mixins in `permissible.models.permission_mixin` that define them out of the
  box (eg `PermissibleDenyDefaultMixin`, `PermissibleDefaultPerms`)
  - If defining `global_action_perm_map` and `obj_action_perm_map` on your own,
    remember that (just like Django's permission checking normally) both global
    and object permissions must pass
  - Both `global_action_perm_map` and `obj_action_perm_map` use the same format:
    a map of actions to a list of `PermDef` objects
  - Actions are the same as those defined by DRF (for convenience):
    `list`, `create`, `retrieve`, `update`, `partial_update`, `destroy`, and any others
    you want to define and check later
- See below for `PermDef` explanation


## PermDef

- A simple data structure to hold permissions configuration. Each action inside
  `global_action_perm_map` and `obj_action_perm_map` has a list of `PermDef`
- Each `PermDef` is defined with the following:
    - `short_perm_codes`: A list of short permission codes, e.g. ["view", "change"]
    - `obj_getter`: A function/str that takes the object we are checking, and returns
      a **potentially different** object on whom we will actually check permissions.
      (For instance if you want to check a related parent object to determine whether
      the user has access to the child object. This is critical for PermRoot behavior.)
    - `condition_checker`: An ADDITIONAL check, on top of the usual permissions-checking
      (`user.has_perms`).


# Example flow

- The application has the following models:
    - `User` (inherits Django's base abstract user model)
    - `Group` (Django's model)
    - `Team` (inherits `PermRoot`)
    - `TeamGroup` (inherits `PermRootGroup`)
    - `TeamUser` (inherits `PermRootUser`)
    - `TeamInfo` (contains a foreign key to `Team`)
   
### Create a team
 - A new team is created (via Django admin), which triggers the creation of appropriate
 groups and assignment of permissions:
    - `Team.save()` creates several `TeamGroup` records, one for each possible role
    (e.g. member, owner)
    - For each `TeamGroup`, the `save()` method triggers the creation of a new `Group`,
    and assigns permissions to each of these groups, in accordance with
    `PermRootGroup.role_definitions`:
        - `TeamGroup` with "Member" role is given no permissions
        - `TeamGroup` with "Viewer" role is given "view_team" permission
        - `TeamGroup` with "Contributor" role is given "contribute_to_team" and "view_team"
        permissions
        - `TeamGroup` with "Admin" role is given "change_team", "contribute_to_team" and
        "view_team" permissions
        - `TeamGroup` with "Owner" role is given "delete", "change_team", "contribute_to_team"
        and "view_team" permissions
        - (NOTE: this behavior can be customized)
    - Note that no one is given permission to create `Team` to begin with - it must have
    been created by a superuser or someone who was manually given such permission in the admin

### Create a user
- A new user is created (via Django admin), and added to the relevant groups (e.g. members, admins)
- A `TeamUser` record is added automatically when this user joins those groups.
  Note that if the user is removed from ALL of those groups for this `Team`, they will
  automatically have their `TeamUser` record removed.

### Edit a team-related record
- The user tries to edit a `TeamInfo` record, either via API (django-rest-framework) or Django
 admin, triggering the following checks:
    - View/viewset checks global permissions
    - View/viewset checks object permissions:
        - Checking object permission directly FAILS (as this user was not given any permission for
        this object in particular)
        - Checking permission for root object (i.e. team) SUCCEEDS if the user was added to the
        correct groups

### Create a team-related record
- The user tries to create a `TeamInfo` record, either via API (django-rest-framework) or Django
 admin, triggering the following checks:
    - View/viewset checks global permissions
    - View/viewset checks creation permissions:
        - Checking object permission directly FAILS as this object doesn't have an ID yet, so
        can't have any permissions associated with it
        - Checking permission for root object (i.e. team) SUCCEEDS if the user was added to the
        correct groups
    - View/viewset does not check object permission (this is out of our control, and makes sense
    as there is no object)
