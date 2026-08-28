from pathlib import Path
import yaml
from detection_forge.backtest.log_loader import flatten_record, load_ndjson_logs
from detection_forge.backtest.matcher import run_backtest
from detection_forge.models import GeneratedRule

ROOT = Path(__file__).parents[1]
def example(name):
    text = (ROOT / "detection_forge/rules/examples" / name).read_text(); raw = yaml.safe_load(text)
    return GeneratedRule(text, raw["title"], raw["id"])

def test_loader_flattens_and_skips_bad_lines(tmp_path):
    path = tmp_path / "e.ndjson"; path.write_text('{"winlog":{"event_data":{"Image":"x","Tags":["a","b"]}}}\nbad\n')
    parsed_file = load_ndjson_logs(path); flat = flatten_record(parsed_file.records[0])
    assert flat["Image"] == "x" and flat["winlog.event_data.Tags"] == "a b"

def test_nested_sysmon_mshta_match_and_unmapped_fields(tmp_path):
    path = tmp_path / "e.ndjson"; path.write_text('{"winlog":{"event_data":{"Image":"C:\\\\Windows\\\\mshta.exe","CommandLine":"mshta javascript:1"}}}\n{"winlog":{"event_data":{"Image":"notepad.exe","CommandLine":"ok"}}}\n')
    result = run_backtest(example("mshta_suspicious_execution.yml"), [path])
    assert result.total_events_scanned == 2 and result.match_count == 1
    assert set(result.matched_events[0].matched_selection_names) == {"selection_img", "selection_cli"}
    assert "TargetImage" in run_backtest(example("lsass_memory_access.yml"), [path]).unmapped_fields


def _rule(detection_yaml: str) -> GeneratedRule:
    text = f"""
title: test rule
id: 22222222-2222-2222-2222-222222222222
status: experimental
logsource:
    category: test
detection:
{detection_yaml}
level: low
"""
    raw = yaml.safe_load(text)
    return GeneratedRule(text, raw["title"], raw["id"])


def test_literal_bracket_characters_in_value_are_matched_literally(tmp_path):
    # Regression: fnmatch interprets '[...]' as a character class, which is not
    # part of the Sigma wildcard spec - a hand-built fnmatch pattern from a
    # SigmaString silently fails to match real .NET-reflection PowerShell
    # command lines like this one.
    path = tmp_path / "e.ndjson"
    path.write_text('{"CommandLine": "powershell.exe [System.Reflection.Assembly]::Load(1)"}\n')
    rule = _rule(
        "    selection:\n"
        "        CommandLine|contains: '[System.Reflection.Assembly]'\n"
        "    condition: selection\n"
    )
    result = run_backtest(rule, [path])
    assert result.match_count == 1


def test_cidr_compare_and_exists_modifiers_match(tmp_path):
    path = tmp_path / "e.ndjson"
    path.write_text('{"ipfield": "10.1.2.3", "numfield": 150, "somefield": "present"}\n')
    rule = _rule(
        "    selection:\n"
        "        ipfield|cidr: '10.0.0.0/8'\n"
        "        numfield|gt: 100\n"
        "        somefield|exists: true\n"
        "    condition: selection\n"
    )
    result = run_backtest(rule, [path])
    assert result.match_count == 1


def test_exists_false_matches_when_field_absent(tmp_path):
    path = tmp_path / "e.ndjson"
    path.write_text('{"other": "x"}\n')
    rule = _rule(
        "    selection:\n"
        "        missingfield|exists: false\n"
        "    condition: selection\n"
    )
    result = run_backtest(rule, [path])
    assert result.match_count == 1
