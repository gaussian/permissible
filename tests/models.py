"""
This module must exist (even if empty) so that Django's test-database setup
creates tables for models registered under the `tests` app: syncdb-style table
creation skips apps whose `models_module` is None. Concrete test models are
defined in the test modules themselves with `Meta.app_label = "tests"`.
"""
