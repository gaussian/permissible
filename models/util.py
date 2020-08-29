"""
Neutron (a Visor module)
Author: Kut Akdogan
(c) 2016- Gaussian Holdings, LLC.

This codebase is confidential and proprietary.
No license for use, viewing, or reproduction without explicit written permission.
"""


class ModelWithOriginalMixin(object):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._loaded_values = dict()

    @classmethod
    def from_db(cls, db, field_names, values):
        instance = super().from_db(db, field_names, values)

        # Store the original field values on the instance
        instance._loaded_values = dict(zip(field_names, values))

        return instance

    def original(self, field_name: str):
        return self._loaded_values.get(field_name, None)

    def has_changed(self, field_name: str) -> bool:
        try:
            current_value = getattr(self, field_name)
        except AttributeError:
            return False
        original_value = self._loaded_values.get(field_name, None)
        result = original_value != current_value

        return result

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

        # Update loaded values
        for field in self._meta.concrete_fields:
            field_name = field.attname
            self._loaded_values[field_name] = getattr(self, field_name, None)


class UneditableModelWithOriginalMixin(ModelWithOriginalMixin):
    UNEDITABLE_FIELDS = []

    def save(self, *args, **kwargs):
        if not self._state.adding and any(self.has_changed(f) for f in self.UNEDITABLE_FIELDS):
            raise PermissionError(f"Trying to change uneditable field in {self.__class__} {self}")

        super().save(*args, **kwargs)
