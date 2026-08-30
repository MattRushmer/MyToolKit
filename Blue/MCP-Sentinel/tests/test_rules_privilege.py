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


def test_camel_case_shell_command_name_is_still_flagged():
    tool = make_tool(name="runShellCommand", description="Runs a shell command.")
    findings = check_tool_privileges("srv:demo", tool)
    assert any(f.finding_id.startswith("priv-exec:") for f in findings)


def test_evaluate_expression_tool_is_not_a_false_positive():
    tool = make_tool(name="evaluate_expression", description="Evaluates a math expression and returns the result.", read_only_hint=True)
    findings = check_tool_privileges("srv:demo", tool)
    assert not any(f.finding_id.startswith("priv-exec:") for f in findings)


def test_evaluation_report_tool_is_not_a_false_positive():
    tool = make_tool(name="get_evaluation_report", description="Returns the latest performance evaluation report.", read_only_hint=True)
    findings = check_tool_privileges("srv:demo", tool)
    assert not any(f.finding_id.startswith("priv-exec:") for f in findings)


def test_bare_eval_tool_name_is_still_flagged():
    tool = make_tool(name="eval", description="Evaluates arbitrary code.")
    findings = check_tool_privileges("srv:demo", tool)
    assert any(f.finding_id.startswith("priv-exec:") for f in findings)


def test_dropdown_menu_tool_is_not_a_false_positive():
    tool = make_tool(name="dropdown_menu_selector", description="Selects an option from a dropdown menu.", read_only_hint=True)
    findings = check_tool_privileges("srv:demo", tool)
    assert not any(f.finding_id.startswith("priv-mismatch:") or f.finding_id.startswith("priv-undeclared:") for f in findings)


def test_drop_table_is_still_flagged_destructive():
    tool = make_tool(name="drop_table", description="Drops a database table.", destructive_hint=False)
    findings = check_tool_privileges("srv:demo", tool)
    assert any(f.finding_id.startswith("priv-mismatch:") for f in findings)


def test_format_date_utility_tool_is_not_a_false_positive():
    tool = make_tool(name="format_date", description="Formats a date string.", read_only_hint=True)
    findings = check_tool_privileges("srv:demo", tool)
    assert not any(f.finding_id.startswith("priv-mismatch:") or f.finding_id.startswith("priv-undeclared:") for f in findings)


def test_wip_status_tracker_is_not_a_false_positive():
    tool = make_tool(name="wip_status_tracker", description="Tracks work-in-progress items.", read_only_hint=True)
    findings = check_tool_privileges("srv:demo", tool)
    assert not any(f.finding_id.startswith("priv-mismatch:") or f.finding_id.startswith("priv-undeclared:") for f in findings)


def test_wipe_disk_tool_is_still_flagged_destructive():
    tool = make_tool(name="wipe_disk", description="Wipes the target disk.", destructive_hint=False)
    findings = check_tool_privileges("srv:demo", tool)
    assert any(f.finding_id.startswith("priv-mismatch:") for f in findings)


def test_camel_case_delete_all_records_is_flagged_for_undeclared_annotation():
    tool = make_tool(name="deleteAllRecords", description="Deletes all records from the table.")
    findings = check_tool_privileges("srv:demo", tool)
    assert any(f.finding_id.startswith("priv-undeclared:") for f in findings)


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


def test_acronym_prefixed_exec_name_is_flagged():
    # Regression test: a round-2 review found the first camelCase boundary
    # rule alone (lower/digit -> upper) never isolates an acronym fused
    # directly onto the following verb - "OSExec" stayed as one word since
    # there's no lowercase/digit before the "E" of "Exec".
    for name in ("OSExec", "APIShell"):
        tool = make_tool(name=name, description="")
        findings = check_tool_privileges("srv:demo", tool)
        assert any(f.finding_id.startswith("priv-exec:") for f in findings), f"{name} should be flagged"


def test_acronym_prefixed_destructive_name_is_flagged():
    for name in ("HTTPDropTable", "DBDropAll", "IOSDeleteAll"):
        tool = make_tool(name=name, description="")
        findings = check_tool_privileges("srv:demo", tool)
        assert any(f.finding_id.startswith("priv-undeclared:") for f in findings), f"{name} should be flagged"
