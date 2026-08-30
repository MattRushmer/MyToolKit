from mcp_sentinel.probes.payloads import build_probe_arguments


def test_no_schema_returns_empty_args():
    assert build_probe_arguments({}) == {}


def test_no_required_properties_returns_empty_args():
    schema = {"type": "object", "properties": {"q": {"type": "string"}}}
    assert build_probe_arguments(schema) == {}


def test_required_string_uses_name_hint():
    schema = {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}
    args = build_probe_arguments(schema)
    assert args == {"city": "London"}


def test_required_string_with_no_hint_uses_generic_probe_text():
    schema = {"type": "object", "properties": {"note": {"type": "string"}}, "required": ["note"]}
    args = build_probe_arguments(schema)
    assert args["note"]


def test_required_enum_picks_first_value():
    schema = {"type": "object", "properties": {"mode": {"type": "string", "enum": ["fast", "slow"]}}, "required": ["mode"]}
    args = build_probe_arguments(schema)
    assert args == {"mode": "fast"}


def test_required_boolean_and_integer_defaults():
    schema = {
        "type": "object",
        "properties": {"confirm": {"type": "boolean"}, "count": {"type": "integer"}},
        "required": ["confirm", "count"],
    }
    args = build_probe_arguments(schema)
    assert args == {"confirm": False, "count": 0}


def test_required_object_param_returns_none():
    schema = {"type": "object", "properties": {"filters": {"type": "object"}}, "required": ["filters"]}
    assert build_probe_arguments(schema) is None


def test_required_array_param_returns_none():
    schema = {"type": "object", "properties": {"tags": {"type": "array"}}, "required": ["tags"]}
    assert build_probe_arguments(schema) is None


def test_required_property_missing_from_properties_returns_none():
    schema = {"type": "object", "properties": {}, "required": ["mystery"]}
    assert build_probe_arguments(schema) is None
