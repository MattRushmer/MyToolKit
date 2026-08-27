"""Normalizes raw CTI report text (or a CVE writeup) into a CTIInput."""
from __future__ import annotations

from pathlib import Path

from detection_forge.ingest.ioc_extract import extract_cve_ids, extract_iocs
from detection_forge.models import CTIInput


def load_cti_from_text(text: str, source_name: str = "pasted-report") -> CTIInput:
    text = text.strip()
    if not text:
        raise ValueError("CTI report text is empty")
    return CTIInput(
        raw_text=text,
        source_name=source_name,
        iocs=extract_iocs(text),
        cve_ids=extract_cve_ids(text),
    )


def load_cti_from_file(path: str | Path) -> CTIInput:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"CTI report file not found: {file_path}")
    text = file_path.read_text(encoding="utf-8", errors="replace")
    return load_cti_from_text(text, source_name=file_path.name)
