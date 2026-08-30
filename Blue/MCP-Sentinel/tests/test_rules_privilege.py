from factories import make_tool

from mcp_sentinel.rules.privilege import check_tool_privileges


def test_exec_pattern_in_name_flagged_high():
    tool = make_tool(name="run_shell_command", description="Runs an arbitrary shell command.")
    findings = check_tool_privileges("srv:demo", tool)
    assert any(f.finding_id.startswith("priv-exec:") for f in findings)
    exec_finding = next(f for f in findings if f.finding_id.startswith("priv-exec:"))
    assert exec_finding.severity.value == "high"


def test_exec_pattern_auto_approved_is_critical():
    tool = make_tool(name="execute_code", description="Executes arbitrary code.")
    findings = check_tool_privileges("srv:demo", tool, auto_approved_tools=("*",))
    exec_finding = next(f for f in findings if f.finding_id.startswith("priv-exec:"))
    assert exec_finding.severity.value == "critical"


def test_benign_readonly_tool_has_no_exec_finding():
    tool = make_tool(name="get_weather", description="Returns the current weather for a city.", read_only_hint=True)
    findings = check_tool_privileges("srv:demo", tool)
    assert not any(f.finding_id.startswith("priv-exec:") for f in findings)


def test_destructive_language_with_false_hint_flags_mismatch():
    tool = make_tool(name="delete_record", description="Deletes a customer record.", destructive_hint=False)
    findings = check_tool_privileges("srv:demo", tool)
    assert any(f.finding_id.startswith("priv-mismatch:") for f in findings)


def test_destructive_language_with_no_annotations_flags_undeclared():
    tool = make_tool(name="delete_record", description="Deletes a customer record.")
    findings = check_tool_privileges("srv:demo", tool)
    assert any(f.finding_id.startswith("priv-undeclared:") for f in findings)


def test_destructive_language_with_true_hint_does_not_flag_mismatch_or_undeclared():
    tool = make_tool(name="delete_record", description="Deletes a customer record.", destructive_hint=True)
    findings = check_tool_privileges("srv:demo", tool)
    assert not any(f.finding_id.startswith("priv-mismatch:") for f in findings)
    assert not any(f.finding_id.startswith("priv-undeclared:") for f in findings)


def test_unconstrained_path_param_flagged():
    tool = make_tool(
        name="read_file",
        description="Reads a file.",
        input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
        read_only_hint=True,
    )
    findings = check_tool_privileges("srv:demo", tool)
    assert any(f.finding_id.startswith("priv-broad-schema:") for f in findings)


def test_constrained_param_not_flagged():
    tool = make_tool(
        name="read_file",
        description="Reads a file.",
        input_schema={"type": "object", "properties": {"path": {"type": "string", "enum": ["a.txt", "b.txt"]}}},
        read_only_hint=True,
    )
    findings = check_tool_privileges("srv:demo", tool)
    assert not any(f.finding_id.startswith("priv-broad-schema:") for f in findings)


def test_open_world_false_suppresses_broad_schema_finding():
    tool = make_tool(
        name="read_file",
        description="Reads a file.",
        input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
        open_world_hint=False,
    )
    findings = check_tool_privileges("srv:demo", tool)
    assert not any(f.finding_id.startswith("priv-broad-schema:") for f in findings)


def test_auto_approved_destructive_tool_flagged():
    tool = make_tool(name="delete_record", description="Deletes a record.", destructive_hint=True)
    findings = check_tool_privileges("srv:demo", tool, auto_approved_tools=("delete_record",))
    assert any(f.finding_id.startswith("priv-auto-approve-destructive:") for f in findings)


def test_auto_approved_readonly_tool_not_flagged_for_auto_approve():
    tool = make_tool(name="get_weather", description="Returns weather.", read_only_hint=True)
    findings = check_tool_privileges("srv:demo", tool, auto_approved_tools=("get_weather",))
    assert not any(f.finding_id.startswith("priv-auto-approve-destructive:") for f in findings)
