from __future__ import annotations

from pathlib import Path

import httpx
import pytest

import vibecheck.dependencies.registry as registry
from vibecheck.dependencies.models import DeclaredDependency
from vibecheck.dependencies.registry import check_dependencies_exist


class _FakeResponse:
    def __init__(self, status_code: int):
        self.status_code = status_code


class _FakeClient:
    def __init__(self, status_by_name: dict[str, int], call_log: list[str]):
        self._status_by_name = status_by_name
        self._call_log = call_log

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def get(self, url: str):
        self._call_log.append(url)
        for name, code in self._status_by_name.items():
            if name in url:
                return _FakeResponse(code)
        return _FakeResponse(404)


class _OfflineClient:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def get(self, url: str):
        raise httpx.ConnectError("offline", request=None)


def test_existing_package_resolves_true(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    call_log: list[str] = []
    monkeypatch.setattr(registry, "httpx", type("M", (), {"Client": lambda **kw: _FakeClient({"requests": 200}, call_log)}))
    deps = [DeclaredDependency(name="requests", ecosystem="pypi", manifest_file="requirements.txt", line=1)]
    results = check_dependencies_exist(deps, tmp_path)
    assert results[("pypi", "requests")].exists is True


def test_hallucinated_package_resolves_false(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    call_log: list[str] = []
    monkeypatch.setattr(registry, "httpx", type("M", (), {"Client": lambda **kw: _FakeClient({"totally-fake-package": 404}, call_log)}))
    deps = [DeclaredDependency(name="totally-fake-package", ecosystem="pypi", manifest_file="requirements.txt", line=1)]
    results = check_dependencies_exist(deps, tmp_path)
    assert results[("pypi", "totally-fake-package")].exists is False


def test_offline_degrades_to_unknown_without_raising(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr(registry, "httpx", type("M", (), {"Client": lambda **kw: _OfflineClient()}))
    deps = [DeclaredDependency(name="requests", ecosystem="pypi", manifest_file="requirements.txt", line=1)]
    results = check_dependencies_exist(deps, tmp_path)
    assert results[("pypi", "requests")].exists is None


def test_second_call_within_ttl_uses_cache_not_network(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    call_log: list[str] = []
    monkeypatch.setattr(registry, "httpx", type("M", (), {"Client": lambda **kw: _FakeClient({"requests": 200}, call_log)}))
    deps = [DeclaredDependency(name="requests", ecosystem="pypi", manifest_file="requirements.txt", line=1)]

    check_dependencies_exist(deps, tmp_path)
    first_call_count = len(call_log)
    check_dependencies_exist(deps, tmp_path)

    assert first_call_count == 1
    assert len(call_log) == 1  # second call served entirely from cache
