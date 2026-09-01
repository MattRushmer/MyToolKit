from __future__ import annotations

from tests.conftest import make_source
from vibecheck.models import Language
from vibecheck.rules.catalog import VIBE_SEC_DANGEROUS_EVAL, VIBE_SEC_SHELL_INJECTION, VIBE_SEC_UNSAFE_DESERIALIZATION
from vibecheck.rules.dangerous_calls import check_dangerous_calls


def test_flags_eval():
    source = make_source("result = eval(user_input)\n")
    findings = check_dangerous_calls(source)
    assert any(f.rule_id == VIBE_SEC_DANGEROUS_EVAL for f in findings)


def test_flags_exec():
    source = make_source("exec(code)\n")
    findings = check_dangerous_calls(source)
    assert any(f.rule_id == VIBE_SEC_DANGEROUS_EVAL for f in findings)


def test_does_not_flag_ast_literal_eval():
    source = make_source("import ast\nresult = ast.literal_eval(user_input)\n")
    findings = check_dangerous_calls(source)
    assert findings == []


def test_flags_os_system_with_dynamic_command_as_critical():
    source = make_source('import os\nos.system(f"ping {host}")\n')
    findings = check_dangerous_calls(source)
    hit = next(f for f in findings if f.rule_id == VIBE_SEC_SHELL_INJECTION)
    assert hit.severity == "critical"


def test_flags_os_system_with_static_command_as_high_not_critical():
    source = make_source('import os\nos.system("ls -la")\n')
    findings = check_dangerous_calls(source)
    hit = next(f for f in findings if f.rule_id == VIBE_SEC_SHELL_INJECTION)
    assert hit.severity == "high"


def test_flags_subprocess_shell_true_with_dynamic_command():
    source = make_source('import subprocess\nsubprocess.run(f"ls {path}", shell=True)\n')
    findings = check_dangerous_calls(source)
    assert any(f.rule_id == VIBE_SEC_SHELL_INJECTION for f in findings)


def test_does_not_flag_subprocess_with_arg_list():
    source = make_source('import subprocess\nsubprocess.run(["ls", "-la", path])\n')
    findings = check_dangerous_calls(source)
    assert findings == []


def test_flags_pickle_loads():
    source = make_source("import pickle\nobj = pickle.loads(data)\n")
    findings = check_dangerous_calls(source)
    assert any(f.rule_id == VIBE_SEC_UNSAFE_DESERIALIZATION for f in findings)


def test_flags_yaml_load_without_safe_loader():
    source = make_source("import yaml\nconfig = yaml.load(data)\n")
    findings = check_dangerous_calls(source)
    assert any(f.rule_id == VIBE_SEC_UNSAFE_DESERIALIZATION for f in findings)


def test_does_not_flag_yaml_safe_load():
    source = make_source("import yaml\nconfig = yaml.safe_load(data)\n")
    findings = check_dangerous_calls(source)
    assert findings == []


def test_does_not_flag_yaml_load_with_safe_loader_kwarg():
    source = make_source("import yaml\nconfig = yaml.load(data, Loader=yaml.SafeLoader)\n")
    findings = check_dangerous_calls(source)
    assert findings == []


def test_flags_js_eval():
    source = make_source("eval(userInput);\n", rel_path="test.js", language=Language.JAVASCRIPT)
    findings = check_dangerous_calls(source)
    assert any(f.rule_id == VIBE_SEC_DANGEROUS_EVAL for f in findings)


def test_flags_js_child_process_exec_with_template_literal():
    source = make_source("child_process.exec(`ls ${dir}`);\n", rel_path="test.js", language=Language.JAVASCRIPT)
    findings = check_dangerous_calls(source)
    hit = next(f for f in findings if f.rule_id == VIBE_SEC_SHELL_INJECTION)
    assert hit.severity == "critical"


def test_does_not_flag_js_exec_with_static_string():
    source = make_source('child_process.exec("ls -la");\n', rel_path="test.js", language=Language.JAVASCRIPT)
    findings = check_dangerous_calls(source)
    hit = next(f for f in findings if f.rule_id == VIBE_SEC_SHELL_INJECTION)
    assert hit.severity == "medium"
