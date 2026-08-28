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
    rows = load_ndjson_logs(path); flat = flatten_record(rows[0])
    assert flat["Image"] == "x" and flat["winlog.event_data.Tags"] == "a b"

def test_nested_sysmon_mshta_match_and_unmapped_fields(tmp_path):
    path = tmp_path / "e.ndjson"; path.write_text('{"winlog":{"event_data":{"Image":"C:\\\\Windows\\\\mshta.exe","CommandLine":"mshta javascript:1"}}}\n{"winlog":{"event_data":{"Image":"notepad.exe","CommandLine":"ok"}}}\n')
    result = run_backtest(example("mshta_suspicious_execution.yml"), [path])
    assert result.total_events_scanned == 2 and result.match_count == 1
    assert set(result.matched_events[0].matched_selection_names) == {"selection_img", "selection_cli"}
    assert "TargetImage" in run_backtest(example("lsass_memory_access.yml"), [path]).unmapped_fields
