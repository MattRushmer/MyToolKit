"""Download/refresh the offline MITRE ATT&CK Enterprise STIX bundle.

Run this occasionally to pick up newly published techniques:
    python scripts/download_attack_data.py
"""
from __future__ import annotations

import sys
import urllib.request
from pathlib import Path

SOURCE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from detection_forge.config import ATTACK_STIX_PATH, DATA_DIR  # noqa: E402


def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {SOURCE_URL} ...")
    urllib.request.urlretrieve(SOURCE_URL, ATTACK_STIX_PATH)
    size_mb = ATTACK_STIX_PATH.stat().st_size / (1024 * 1024)
    print(f"Saved {ATTACK_STIX_PATH} ({size_mb:.1f} MB)")


if __name__ == "__main__":
    main()
