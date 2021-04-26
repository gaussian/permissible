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

Install with `pip install https://github.com/gaussian/permissible.git`.


# Features

## Feature 1: Consistent permissions configuration

In its simplest form, `permissible` can be used just for its permissions
configuration. This has no impact on your database, and does not rely on any
particular object-level permissions library. (It does require one; we prefer
django-guardian.)

Here, we add the `PermissibleMixin` to each model we want to protect, and
define "permissions maps" that define what permissions are needed for each action
that is taken on an object in the model (e.g. a "retrieve" action on a "survey").
(We can also use classes like `PermissibleSelfOnlyMixin` to define good default
permission maps for our models.)

With the permissions configured, now we can force different views to use them:
- If you would like the permissions to work for API views (via
django-rest-framework): Add `PermissiblePerms` to the `permission_classes` for
the viewsets for our models
- If you would like the permissions to work in the Django admin: Add
`PermissibleAdminMixin` to the admin classes for our models

That's it. Actions are now protected by permissions checks. But there is no easy
way to create the permissions in the first place. That's where the next two
features come in.


## Feature 2: Simple permissions assignment using "root" models

The `permissible` library can also help automatically assign permissions based on
certain "root" models. The root model is the model we should check permissions
against. For instance, the root model for a "project file" might be a "project",
in which case having certain permissions on the "project" would confer other
permissions for the "project files", even though no specific permission exists
for the "project file".
Of course, it's easy to link a "project" to a "project file" through a foreign key.
But `permissible` solves the problem of tying this to the Django `Group` model,
which is what we use for permissions.

To accomplish this, `permissible` provides two base model classes that you should use:
1. **`PermRoot`**: Make the root model (e.g. `Team`) derive from `PermRoot`
2. **`PermRootGroup`**: Create a new model that derives from `PermRootGroup`
and has a `ForeignKey` to the root model

You can then simply adjust your permissions maps in `PermissibleMixin` to
incorporate checking of the root model for permissions. See the documentation for
`PermDef` and `PermissibleMixin.has_object_permissions` for info and examples.

You can also use `PermRootAdminMixin` to help you manage the `PermRoot` records.


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


# Full instructions

1. 


# Example flow

- The application has the following models:
    - `User` (inherits Django's base abstract user model)
    - `Group` (Django's model)
    - `Team` (inherits `PermRoot`)
    - `TeamGroup` (inherits `PermRootGroup`)
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
- Upon create