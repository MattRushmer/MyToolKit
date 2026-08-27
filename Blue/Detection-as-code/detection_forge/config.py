"""Runtime configuration, sourced from environment variables / .env."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent
DATA_DIR = PROJECT_ROOT / "data"
ATTACK_STIX_PATH = DATA_DIR / "enterprise-attack.json"
EXAMPLE_RULES_DIR = PACKAGE_ROOT / "rules" / "examples"


def _load_dotenv() -> None:
    """Minimal .env loader so we don't need python-dotenv as a hard dependency."""
    env_path = PROJECT_ROOT / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


_load_dotenv()


@dataclass(frozen=True)
class Settings:
    anthropic_api_key: str | None = os.environ.get("ANTHROPIC_API_KEY")
    anthropic_model: str = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-5")
    max_generation_retries: int = int(os.environ.get("DF_MAX_GEN_RETRIES", "2"))
    noise_critical_threshold: float = float(os.environ.get("DF_NOISE_CRITICAL", "80"))
    noise_high_threshold: float = float(os.environ.get("DF_NOISE_HIGH", "55"))
    noise_medium_threshold: float = float(os.environ.get("DF_NOISE_MEDIUM", "30"))

    @property
    def has_llm_key(self) -> bool:
        return bool(self.anthropic_api_key)


settings = Settings()
