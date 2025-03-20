from typing import Any, Optional, Type, Union

from django.db import models


class LazyModelResolverMixin(object):
    """
    Mixin to allow a model to retrieve an *unretrieved* model instance for a
    dot-separated chain of foreign keys, using exactly one DB query if multi-level,
    and zero queries if single-level.
    """

    def get_unretrieved(self, attr_key: str) -> Optional[models.Model]:
        """
        Return an *unretrieved* model instance for a dot-separated chain of foreign keys,
        using exactly one DB query if multi-level, and zero queries if single-level.

        Examples:
        get_unretrieved("team")
            -> returns Team(pk=self.team_id), no DB query

        get_unretrieved("experiment.team")
            -> executes one query:
                Experiment.objects.filter(pk=self.experiment_id)
                        .values_list("team_id", flat=True)
            -> returns Team(pk=<that_team_id>)

        get_unretrieved("chainer_session.chainer.team")
            -> executes one query:
                ChainerSession.objects.filter(pk=self.chainer_session_id)
                            .values_list("chainer__team_id", flat=True)
            -> returns Team(pk=<the_team_id>)

        Returns:
        A model instance with the correct primary key (but not fetched from the DB) or None
        if the primary key is null or if the query returns a number of results != 1.
        """
        res = self.resolve_chain(attr_key)
        final_model_class = res["final_model_class"]

        root_field = res["root_field"]
        root_pk = getattr(self, root_field.attname)
        root_model_class = root_field.related_model

        # The root_pk (eg self.team_id for an illustrative single-length chain,
        # or self.opportunity_id for an illustrative multi-length chain) is null,
        # so we can't proceed. This is not an error - the result is simply "None".
        if not root_pk:
            return None

        # If a query path is set, use it to find the final primary key, i.e.
        # the primary key of the final model in the chain.
        root_query_path = res.get("root_query_path", None)
        if root_query_path:
            # Filter to root models with the root PK, then use values_list
            # to get the final PK (nested with "__" if appropriate).
            results = list(
                root_model_class.objects.filter(pk=root_pk).values_list(
                    root_query_path, flat=True
                )
            )
            if len(results) != 1:
                return None
            final_pk = results[0]

            # The primary key found is null, so no related object exists, so
            # return None.
            if not final_pk:
                return None

        # If no query path is set, the final primary key is directly available.
        else:
            final_pk = root_pk

        # Return the unretrieved model instance (i.e. construct it, no retrieval).
        return final_model_class(pk=final_pk)

    @classmethod
    def get_unretrieved_class(cls, attr_key: str) -> Optional[Type[models.Model]]:
        """
        Return the final model class determined by a stored dot-separated attribute chain
        in attr_key.

        Example:
        If attr_key is "experiment.team", this property returns the Team model class.
        """
        res = cls.resolve_chain(attr_key)
        return res["final_model_class"]

    @classmethod
    def resolve_chain(cls, attr_key: str) -> dict[str, Any]:
        """
        Traverse a dot-separated chain of foreign key attributes and return a dictionary
        with all details needed to either directly construct the final model instance or
        to perform a single DB query to retrieve the final primary key.

        This method does NOT hit the database.

        The returned dictionary contains:
        - final_model_class: the model class of the final attribute in the chain.
        - final_attname: the attribute name for the final field (for example, "team_id").
        - root_field: the field of the first attribute in the chain, whose model
                            will be queried.
        - root_query_path: the lookup string (e.g. "chainer__team_id") to be used with
                        .values_list() on the root model.

        This helper unifies the chain resolution so that both direct (no DB query) and query
        modes share the same traversal logic.

        Examples:
        - Single-level chain "team":
                * Chain: ["team"]
                * final_model_class is determined from the related field of 'team'.
                * final_pk is taken from self.team_id.
                * no DB hit will be needed.

        - Multi-level chain "experiment.team":
                * Chain: ["experiment", "team"]
                * The root attribute "experiment" gives root_model_class and root_pk (from self.experiment_id).
                * The final attribute "team" yields final_model_class and final_attname ("team_id").
                * root_query_path becomes "team_id".
                * DB hit will be needed.

        - Multi-level chain "chainer_session.chainer.team":
                * Chain: ["chainer_session", "chainer", "team"]
                * The root attribute "chainer_session" gives root_model_class and root_pk (from self.chainer_session_id).
                * The penultimate step ("chainer") is traversed.
                * The final attribute "team" yields final_model_class and final_attname.
                * root_query_path becomes "chainer__team_id".
                * DB hit will be needed.
        """
        chain = attr_key.split(".")
        current_model = cls
        root_field = None

        # Iterate through the chain to capture both the root and final field information.
        for i, attr in enumerate(chain):
            # Get the field descriptor from the current model class.
            field = getattr(current_model, attr).field
            if i == 0:
                # Save the first field as the root field for later reference.
                root_field = field
            # Move to the related model for the next attribute in the chain.
            current_model = field.related_model

        # 'field' now holds the final attribute in the chain.

        # The model class for the final attribute.
        final_model_class = field.related_model
        final_attname = field.attname  # e.g. "team_id"

        # Replace the last attribute in the chain with the final attribute name.
        chain_with_final_attname = chain[:-1] + [final_attname]

        result = {
            "final_model_class": final_model_class,
            "root_field": root_field,
            "full_query_path": "__".join(chain_with_final_attname),
        }

        # Build the query lookup path using intermediate attributes (if any).
        # For chain ["chainer_session", "chainer", "team"]:
        #   penultimate_path becomes "chainer" and root_query_path becomes "chainer__team_id".
        if len(chain) > 1:
            result["root_query_path"] = "__".join(chain_with_final_attname[1:])

        return result

    @classmethod
    def make_objs_from_data(
        cls, obj_dict_or_list: Union[dict, list[dict]]
    ) -> list[models.Model]:
        """
        Turn data (usually request.data) into a model object (or a list of model
        objects). Allows multiple objects to be built.

        Helpful for non-detail, non-list actions (in particular, the "create"
        action), to allow us to check if the provided user can do the action via
        `policies.ACTION_POLICIES[<model_label>]["object"]`.

        :param obj_dict_or_list: Model data, in dictionary form (or list of
        dictionaries).
        :return: models.Model object (or list of such objects)
        """
        if isinstance(obj_dict_or_list, list):
            return [cls.make_obj_from_data(obj_dict=d) for d in obj_dict_or_list]
        return [cls.make_obj_from_data(obj_dict=obj_dict_or_list)]

    @classmethod
    def make_obj_from_data(cls, obj_dict: dict) -> models.Model:
        """
        Turn data (usually request.data) into a model object. This finds fields
        in the data that are valid fields for the model, and creates an object
        with those fields.

        No validation is done, and no database queries are made.
        """
        valid_fields = [
            f
            for f in cls._meta.get_fields()
            if not isinstance(f, (models.ForeignObjectRel, models.ManyToManyField))
        ]
        valid_dict_key_to_field_name = {f.name: f.attname for f in valid_fields}
        valid_dict_key_to_field_name.update(
            {f.attname: f.attname for f in valid_fields}
        )
        obj_dict = {
            valid_dict_key_to_field_name[f]: v
            for f, v in obj_dict.items()
            if f in valid_dict_key_to_field_name
        }
        obj = cls(**obj_dict)
        if obj_dict.get("id"):
            obj._state.adding = False
        return obj

    @classmethod
    def make_unretrieved_obj_from_query_params(cls, param_dict: dict) -> object:
        """
        Turn query parameters (usually request.query_params) into a dummy object.

        Helpful for "list" action, to allow us to check if the provided user can
        do the action on a related object, as defined in
        `policies.ACTION_POLICIES[<model_label>]["object"]`.

        :param param_dict: Parameters, in dictionary form.
        :return: models.Model object (or list of such objects)
        """
        obj = cls()
        [setattr(obj, k, v) for k, v in param_dict.items()]
        return obj
