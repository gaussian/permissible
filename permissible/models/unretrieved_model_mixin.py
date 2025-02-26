from typing import Optional, Union

from django.db import models


class UnretrievedModelMixin(object):
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
                -> single query: Experiment.objects.filter(pk=self.experiment_id)
                                              .values_list("team_id", flat=True)
                -> returns Team(pk=<that_team_id>)

            get_unretrieved("chainer_session.chainer.team")
                -> single query: ChainerSession.objects.filter(pk=self.chainer_session_id)
                                          .values_list("chainer__team_id", flat=True)
                -> returns Team(pk=<the_team_id>)

        Returns:
            Model instance with the correct PK but not fetched (unretrieved),
            or None if the PK is null or if the single query returns != 1 result.
        """
        chain = attr_key.split(".")

        # ------------------------------------------------
        # 1) SINGLE-LEVEL SHORTCUT (NO DB QUERY)
        # ------------------------------------------------
        if len(chain) == 1:
            attr_name = chain[0]
            field = getattr(self.__class__, attr_name).field
            final_model_class = field.related_model
            final_pk = getattr(self, field.attname)  # e.g. self.team_id

            if not final_pk:
                return None

            return final_model_class(pk=final_pk)

        # ------------------------------------------------
        # 2) MULTI-LEVEL LOOKUP (SINGLE DB QUERY)
        # ------------------------------------------------
        # Example chain: ["chainer_session", "chainer", "team"]

        # (a) The "root" attribute on `self`: e.g. self.chainer_session_id
        root_attr = chain[0]
        root_field = getattr(self.__class__, root_attr).field
        root_model_class = root_field.related_model
        root_pk = getattr(self, root_field.attname)
        if not root_pk:
            return None

        # (b) The "penultimate" path in chain[1:-1]
        #     e.g. chain[1:-1] = ["chainer"] for ["chainer_session","chainer","team"]
        penultimate_path_list = chain[1:-1]  # all but last
        penultimate_path_str = "__".join(penultimate_path_list)  # e.g. "chainer"

        # (c) Traverse penultimate_path_list to find the *penultimate model class*
        penultimate_model_class = root_model_class
        for sub_attr in penultimate_path_list:
            sub_field = getattr(penultimate_model_class, sub_attr).field
            penultimate_model_class = sub_field.related_model

        # (d) The *final* attribute name & field attname
        #     e.g. final_attr = "team", final_attname = "team_id"
        final_attr = chain[-1]
        final_field = getattr(penultimate_model_class, final_attr).field
        final_model_class = final_field.related_model
        final_attname = final_field.attname  # "team_id"

        # (e) Build the final path for .values_list(...):
        #     If penultimate_path_str is "chainer", we get "chainer__team_id"
        #     If penultimate_path_str is empty, we get "team_id"
        if penultimate_path_str:
            final_path = f"{penultimate_path_str}__{final_attname}"
        else:
            final_path = final_attname

        # (f) Single DB query on the root model
        qs = root_model_class.objects.filter(pk=root_pk).values_list(
            final_path, flat=True
        )
        results = list(qs)

        # (g) Must have exactly 1 result
        if len(results) != 1:
            return None

        final_pk = results[0]
        if not final_pk:
            return None

        # (h) Return the "unretrieved" instance
        return final_model_class(pk=final_pk)

    @classmethod
    def make_objs_from_data(
        cls, obj_dict_or_list: Union[dict, list[dict]]
    ) -> Union[models.Model, list[models.Model]]:
        """
        Turn data (usually request.data) into a model object (or a list of model
        objects). Allows multiple objects to be built.

        Helpful for non-detail, non-list actions (in particular, the "create"
        action), to allow us to check if the provided user can do the action via
        `obj_action_perm_map`.

        :param obj_dict_or_list: Model data, in dictionary form (or list of
        dictionaries).
        :return: models.Model object (or list of such objects)
        """
        if isinstance(obj_dict_or_list, list):
            return [cls._make_obj_from_data(obj_dict=d) for d in obj_dict_or_list]
        return [cls._make_obj_from_data(obj_dict=obj_dict_or_list)]

    @classmethod
    def _make_obj_from_data(cls, obj_dict: dict) -> models.Model:
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
    def make_dummy_obj_from_query_params(cls, param_dict: dict) -> object:
        """
        Turn query parameters (usually request.query_params) into a dummy object.

        Helpful for "list" action, to allow us to check if the provided user can
        do the action on a related object, as defined in `obj_action_perm_map`.

        :param param_dict: Parameters, in dictionary form.
        :return: models.Model object (or list of such objects)
        """
        obj = cls()
        [setattr(obj, k, v) for k, v in param_dict.items()]
        return obj
