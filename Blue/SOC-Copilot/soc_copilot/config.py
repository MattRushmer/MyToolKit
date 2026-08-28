"""Runtime configuration, sourced from environment variables / .env."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent
SAMPLES_DIR = PROJECT_ROOT / "samples"


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

    # Alerts on the same client+host (or client+user) within this many minutes
    # of each other are grouped into one incident.
    correlation_window_minutes: int = int(os.environ.get("SOC_CORRELATION_WINDOW_MIN", "60"))

    # List-price defaults for the cost tracker; override per your model/contract.
    cost_per_1m_input: float = float(os.environ.get("SOC_COST_PER_1M_INPUT", "3.00"))
    cost_per_1m_output: float = float(os.environ.get("SOC_COST_PER_1M_OUTPUT", "15.00"))

    @property
    def has_llm_key(self) -> bool:
        return bool(self.anthropic_api_key)


settings = Settings()
