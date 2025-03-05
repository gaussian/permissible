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

## Feature 1: Consistent, policy-based permissions configuration

In its simplest form, `permissible` can be used just for its permissions
configuration. This has no impact on your database, and does not rely on any
particular object-level permissions library. (It does require one; we prefer
django-guardian.)

Here, we add the `PermissibleMixin` to each model we want to protect, and
define policies for ach that define what permissions are needed for each action
that is taken on an object in the model (e.g. a "retrieve" action on a "survey").

Policies are defined in a `policies.py`, in a dict called `ACTION_POLICIES`, eg:
```
ACTION_POLICIES = {
    "surveys.Survey": {
        "global": {
            "create": NO_RESTRICTION,
            "retrieve": NO_RESTRICTION,
            ...
        },
        "object": {
            "create": NO_RESTRICTION,
            "retrieve": p(["view"]),
            ...
        },
    }
}
```

With the permissions configured, now we can force different views to use them:
- If you would like the permissions to work for API views (via
`django-rest-framework`): Add `PermissiblePerms` to the `permission_classes` for
the viewsets for our models
- If you would like the permissions to work in the Django admin: Add
`PermissibleAdminMixin` to the admin classes for our models

That's it. Actions are now protected by permissions checks. But there is no easy
way to create the permissions in the first place. That's where the next two
features come in.


## Feature 2: Simple, role-based permissions assignment using "domain" models (RBAC)

The `permissible` library can also help automatically assign permissions based on
certain "domain" models. The domain model is the model we should check permissions
against. For instance, the domain model for a "project file" might be a "project",
in which case having certain permissions on the "project" would confer other
permissions for the "project files", even though no specific permission exists
for the "project file". Loosely speaking, a domain "owns" other models. The concept of
"domains" is fairly consistent in RBAC.

Of course, it's easy to link a "project" to a "project file" through a foreign key.
But `permissible` solves the problem of tying this to the Django `Group` model,
which is what we use for permissions, according to **roles**.
Each resulting `Group` (managed on the backend) corresponds to a single role.

To accomplish this, `permissible` provides 3 base model classes that you should use:
1. **`PermDomain`**: Make the domain model (e.g. `Team`) derive from `PermDomain`
2. **`PermDomainRole`**: Create a new model that derives from `PermDomainRole`
and has a `ForeignKey` to the domain model - and defines `ROLE_DEFINITIONS`
3. **`PermDomainMember`**: Create a new model that derives from `PermDomainMember`
and has a `ForeignKey` to the domain model (this model automatically adds and
removes records when a user is a member of the appropriate `PermDomainRole`)

Then, set up the `ACTION_POLICIES` appropriately. For instance, for a model class
"surveys.Survey" owned by its Survey.project.team, we might have the following:
```
ACTION_POLICIES = {
    "surveys.Survey": {
        "global": {
            "create": NO_RESTRICTION,
            "retrieve": NO_RESTRICTION,
            ...
        },
        "object": {
            "create": p(["add_on"], "project.team"),
            "retrieve": p(["view_on"], "project.team"),
            ...
        },
    }
}

You can adjust `ACTION_POLICIES` to incorporate checking of the domain model for
permissions. See the documentation for `PermDef` and
`PermissibleMixin.has_object_permissions` for info and examples.

Remember: `PermDomain` is the core model on which roles are defined (eg Project or
Team) and `PermDomainRole` is the model that represents a single role (and
therefore a single Django `auth.Group`) for a single `PermDomain` - eg Team Admins.
The `PermDomainRole.ROLE_DEFINITIONS` defines what object permissions will be
given to each role/group for every `PermDomain`.

You can also use `PermDomainAdminMixin` to help you manage the `PermDomain` records
and the subsequent role-based access control:

![RBAC admin](admin_1.png)


## Feature 3: Assignment on record creation

`permissible` can automatically assign object permissions on object creation,
through use of 3 view-related mixins:
- `admin.PermissibleObjectAssignMixin` (for admin classes - give creating user all
permissions)
- `serializers.PermissibleObjectAssignMixin` (for serializers - give creating user
all permissions)
- `serializers.PermDomainObjectAssignMixin` (for serializers for domain models
like "Team" or "Project - add creating user to all domain model's Groups)

NOTE: this feature is dependent on django-guardian, as it uses the `assign_perm`
shortcut. Also, `admin.PermissibleObjectAssignMixin` extends the
`ObjectPermissionsAssignmentMixin` mixin from djangorestframework-guardian.


# Core concepts

## PermissibleMixin:

- Add `PermissibleMixin` to any model you want to protect
- Define `ACTION_POLICIES` in `policies.py` for each app, where each key is the
  full model label (eg `accounts.User`), see example above
  - Remember that (just like Django's permission checking normally) both global
    and object permissions must pass
  - Both `"global"` and `"object"` keys use the same format: a map of actions
    to a list of `PermDef` objects
  - Actions are the same as those defined by DRF (for convenience):
    `create`, `retrieve`, `update`, `partial_update`, `destroy`, and any others
    you want to define and check later (`list` uses `retrieve` permissions
    by default but can also define its own if needed)
- See below for `PermDef` explanation


## PermDef

- A simple data structure to hold permissions configuration.
- Each `PermDef` is defined with the following:
    - `short_perm_codes`: A list of short permission codes, e.g. ["view", "change"]
    - `obj_path`: An optional string path (e.g. "project.team") from the original object to
      a **potentially different** object on whom we will actually check permissions.
      (For instance if you want to check a related parent object to determine whether
      the user has access to the child object. This is critical for PermDomain behavior.)
    - `global_condition_checker`: An ADDITIONAL check, on top of the usual
      permissions-checking (`user.has_perms`). Is passed the user instance and the
      context object (by default, the values inside the `request` object)
    - `obj_filter`: A tuple of `(attr, operator, needed_value)` to further check the
      object - e.g. `("is_public", "==", True)`. For `PermissibleFilter`, this is
      also used to filter the queryset down to permitted objects.
    - `model_label`: A fully qualified model label to use a different model class
      for checks. This is only used if the `obj_path` actually points to the context
      (e.g. `obj_path="_context.team_id"`) to perform additional permission checks
      based on the context (i.e. what is inside the request object)
- PermDef objects can be combined with each other, either with `|` or `&` - e.g.
  `PermDef(["view"]) | PermDef(["custom_perm"])`


# Example flow

- The application has the following models:
    - `User` (inherits Django's base abstract user model)
    - `Group` (Django's model)
    - `Team` (inherits `PermDomain`)
    - `TeamGroup` (inherits `PermDomainRole`)
    - `TeamUser` (inherits `PermDomainMember`)
    - `TeamInfo` (contains a foreign key to `Team`)
   
### Create a team
 - A new team is created (via Django admin), which triggers the creation of appropriate
 groups and assignment of permissions:
    - `Team.save()` creates several `TeamGroup` records, one for each possible role
    (e.g. member, owner)
    - For each `TeamGroup`, the `save()` method triggers the creation of a new `Group`,
    and assigns permissions to each of these groups, in accordance with
    `PermDomainRole.role_definitions`:
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
        - Checking permission for domain object (i.e. team) SUCCEEDS if the user was added to the
        correct groups

### Create a team-related record
- The user tries to create a `TeamInfo` record, either via API (django-rest-framework) or Django
 admin, triggering the following checks:
    - View/viewset checks global permissions
    - View/viewset checks creation permissions:
        - Checking object permission directly FAILS as this object doesn't have an ID yet, so
        can't have any permissions associated with it
        - Checking permission for domain object (i.e. team) SUCCEEDS if the user was added to the
        correct groups
    - View/viewset does not check object permission (this is out of our control, and makes sense
    as there is no object)
