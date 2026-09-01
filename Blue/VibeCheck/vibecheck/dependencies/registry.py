"""Check whether a declared dependency actually exists on its real package
registry (PyPI / npm) - the concrete, checkable signal behind "hallucinated
dependency" ('slopsquatting') findings: an LLM confidently names a package
that sounds right but was never published, and if an attacker later
registers that exact name, every future run of the same generated code (or
anyone re-running the same prompt) installs whatever they put there.

Network calls are cached to disk with a TTL and every failure mode (offline,
timeout, rate limit, unexpected status) degrades to "unknown" rather than
"hallucinated" - a registry miss must be an actual 404, never an inference
from an error, or this would be worse than useless as a supply-chain check.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

import httpx

from vibecheck.dependencies.models import DeclaredDependency

_CACHE_FILENAME = "dependency_registry_cache.json"
_DEFAULT_TTL_SECONDS = 24 * 60 * 60


@dataclass(frozen=True)
class RegistryCheckResult:
    name: str
    ecosystem: str
    exists: bool | None  # None = could not be determined (offline / non-definitive response)


def _registry_url(dep: DeclaredDependency) -> str:
    if dep.ecosystem == "pypi":
        return f"https://pypi.org/pypi/{quote(dep.name, safe='')}/json"
    return f"https://registry.npmjs.org/{quote(dep.name, safe='@')}"


def _load_cache(cache_path: Path) -> dict:
    if not cache_path.exists():
        return {}
    try:
        return json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _save_cache(cache_path: Path, cache: dict) -> None:
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    except OSError:
        pass  # cache is a pure optimization; failing to persist it is never fatal


def check_dependencies_exist(
    deps: list[DeclaredDependency],
    cache_dir: Path,
    timeout_seconds: float = 5.0,
    ttl_seconds: float = _DEFAULT_TTL_SECONDS,
) -> dict[tuple[str, str], RegistryCheckResult]:
    """Returns a {(ecosystem, name): RegistryCheckResult} map for every
    unique (ecosystem, name) pair in `deps`."""
    cache_path = cache_dir / _CACHE_FILENAME
    cache = _load_cache(cache_path)
    now = time.time()

    unique: dict[tuple[str, str], DeclaredDependency] = {(d.ecosystem, d.name): d for d in deps}
    results: dict[tuple[str, str], RegistryCheckResult] = {}
    to_query: list[DeclaredDependency] = []

    for key, dep in unique.items():
        cache_key = f"{dep.ecosystem}:{dep.name}"
        entry = cache.get(cache_key)
        if entry is not None and (now - entry.get("checked_at", 0)) < ttl_seconds:
            results[key] = RegistryCheckResult(dep.name, dep.ecosystem, entry.get("exists"))
        else:
            to_query.append(dep)

    if to_query:
        try:
            with httpx.Client(timeout=timeout_seconds, follow_redirects=True) as client:
                for dep in to_query:
                    exists = _query_one(client, dep)
                    key = (dep.ecosystem, dep.name)
                    results[key] = RegistryCheckResult(dep.name, dep.ecosystem, exists)
                    cache[f"{dep.ecosystem}:{dep.name}"] = {"exists": exists, "checked_at": now}
        except Exception:  # noqa: BLE001 - any client-construction-level failure must not sink the whole scan
            for dep in to_query:
                key = (dep.ecosystem, dep.name)
                if key not in results:
                    results[key] = RegistryCheckResult(dep.name, dep.ecosystem, None)

    _save_cache(cache_path, cache)
    return results


def _query_one(client: httpx.Client, dep: DeclaredDependency) -> bool | None:
    try:
        response = client.get(_registry_url(dep))
    except httpx.HTTPError:
        return None
    if response.status_code == 200:
        return True
    if response.status_code == 404:
        return False
    return None  # rate-limited, 5xx, etc. - not a definitive answer either way
