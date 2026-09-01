from __future__ import annotations

from tests.conftest import make_source
from vibecheck.auth.symbol_index import build_python_symbol_index


def test_defined_names_include_functions_classes_and_imports():
    source = make_source(
        """
        from flask import Flask
        import os

        class Foo:
            pass

        def bar():
            pass
        """
    )
    index = build_python_symbol_index([source])
    assert {"Flask", "os", "Foo", "bar"} <= index.defined_names


def test_referenced_names_include_calls_and_attribute_access():
    source = make_source(
        """
        def helper():
            pass

        def caller():
            helper()
            obj.helper()
        """
    )
    index = build_python_symbol_index([source])
    assert "helper" in index.referenced_names


def test_assignment_target_counts_as_defined():
    source = make_source('require_admin = make_role_guard("admin")\n')
    index = build_python_symbol_index([source])
    assert "require_admin" in index.defined_names


def test_star_import_file_is_recorded():
    source = make_source("from myapp.decorators import *\n")
    index = build_python_symbol_index([source])
    assert source.rel_path in index.star_import_files
    assert "*" not in index.defined_names


def test_normal_import_does_not_mark_file_as_star_import():
    source = make_source("from myapp.decorators import require_admin\n")
    index = build_python_symbol_index([source])
    assert source.rel_path not in index.star_import_files


def test_function_never_called_is_not_in_referenced_names():
    source = make_source(
        """
        def unused_helper():
            pass
        """
    )
    index = build_python_symbol_index([source])
    assert "unused_helper" not in index.referenced_names
    assert any(fd.name == "unused_helper" for fd in index.function_defs)
