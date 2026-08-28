from pathlib import Path

from detection_forge.attack.attack_data import validate_attack_tags
from detection_forge.ingest.cti_ingest import load_cti_from_text
from detection_forge.ingest.ioc_extract import extract_cve_ids, extract_iocs
from detection_forge.rules.validator import validate_structure

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "detection_forge" / "rules" / "examples"


def test_extract_iocs_finds_cve_hash_ip_domain_and_clean_path():
    text = (
        "The actor exploited CVE-2024-21412 to drop a payload with SHA256 "
        "3a7bd3e2360a3d2a3a90d0f4b6a2b0f0a3a7bd3e2360a3d2a3a90d0f4b6a2b0f to "
        "C:\\Users\\Public\\update.exe, then used powershell.exe -EncodedCommand "
        "to contact 185.220.101.5 and evil-c2-domain.xyz for C2."
    )
    iocs = extract_iocs(text)
    by_type = {i.ioc_type: i.value for i in iocs}

    assert by_type["cve"] == "CVE-2024-21412"
    assert by_type["sha256"] == "3a7bd3e2360a3d2a3a90d0f4b6a2b0f0a3a7bd3e2360a3d2a3a90d0f4b6a2b0f"
    assert by_type["ipv4"] == "185.220.101.5"
    assert by_type["domain"] == "evil-c2-domain.xyz"
    # regression check: the windows_path regex must not swallow trailing prose
    assert by_type["windows_path"] == "C:\\Users\\Public\\update.exe"


def test_extract_cve_ids_dedupes_and_uppercases():
    text = "Seen in cve-2024-1111 and CVE-2024-1111 and CVE-2023-9999."
    assert extract_cve_ids(text) == ["CVE-2024-1111", "CVE-2023-9999"]


def test_load_cti_from_text_rejects_empty():
    import pytest

    with pytest.raises(ValueError):
        load_cti_from_text("   ")


def test_all_example_rules_are_structurally_valid():
    for path in EXAMPLES_DIR.glob("*.yml"):
        rule_yaml = path.read_text(encoding="utf-8")
        is_valid, errors, title, sigma_id = validate_structure(rule_yaml)
        assert is_valid, f"{path.name} failed structural validation: {errors}"
        assert title
        assert sigma_id


def test_validate_attack_tags_flags_hallucinated_technique():
    results = validate_attack_tags(["attack.t9999.999", "attack.t1059.001"])
    by_tag = {r.tag: r for r in results}

    assert by_tag["attack.t9999.999"].valid is False
    assert "hallucinated" in (by_tag["attack.t9999.999"].reason or "").lower()

    assert by_tag["attack.t1059.001"].valid is True
    assert by_tag["attack.t1059.001"].technique_name == "PowerShell"


def test_validate_attack_tags_skips_non_attack_tags():
    results = validate_attack_tags(["cve.2024-21412", "tlp.amber"])
    assert results == []
