"""Runtime configuration, sourced from environment variables / .env."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent
FIXTURES_DIR = PROJECT_ROOT / "fixtures"


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
    # default_factory (not a bare `= os.environ.get(...)`): a plain dataclass
    # field default is evaluated once at first import of this module, not per
    # instantiation - that would freeze every Settings() to whatever the
    # environment was at first import, silently ignoring a later change (e.g.
    # a test doing monkeypatch.setenv(...) then Settings()).
    anthropic_api_key: str | None = field(default_factory=lambda: os.environ.get("ANTHROPIC_API_KEY"))
    anthropic_model: str = field(default_factory=lambda: os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-5"))

    state_dir: str = field(default_factory=lambda: os.environ.get("AGENTWARDEN_STATE_DIR", ".agentwarden_state"))
    default_ttl_seconds: int = field(default_factory=lambda: int(os.environ.get("AGENTWARDEN_DEFAULT_TTL_SECONDS", "60")))
    blast_radius_ceiling: int = field(default_factory=lambda: int(os.environ.get("AGENTWARDEN_BLAST_RADIUS_CEILING", "3")))
    upstream_timeout_seconds: float = field(default_factory=lambda: float(os.environ.get("AGENTWARDEN_UPSTREAM_TIMEOUT_SECONDS", "15")))

    @property
    def has_llm_key(self) -> bool:
        return bool(self.anthropic_api_key)

    @property
    def db_path(self) -> Path:
        return Path(self.state_dir) / "agentwarden.db"


settings = Settings()
