from pathlib import Path
import yaml
from detection_forge.export import export_all
from detection_forge.models import GeneratedRule

def test_exports_and_best_effort_wazuh_warning():
    path = Path(__file__).parents[1] / "detection_forge/rules/examples/lsass_memory_access.yml"
    text = path.read_text(); raw = yaml.safe_load(text); rule = GeneratedRule(text, raw["title"], raw["id"])
    items = {item.target: item for item in export_all(rule, ["sigma", "splunk", "elasticsearch", "wazuh", "bogus"])}
    assert "title:" in items["sigma"].content and items["splunk"].filename.endswith(".spl")
    assert items["elasticsearch"].filename.endswith(".lucene") and "<group" in items["wazuh"].content
    assert any("No official Sigma-to-Wazuh converter" in w for w in items["wazuh"].warnings) and items["bogus"].warnings
