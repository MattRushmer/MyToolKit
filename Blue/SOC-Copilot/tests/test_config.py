from soc_copilot.config import Settings


def test_settings_reflects_environment_at_instantiation_not_first_import(monkeypatch):
    """A bare dataclass field default (`= os.environ.get(...)`) is evaluated
    once at class-definition time, not per-instance - this was silently
    freezing every Settings() to whatever the environment was at first
    import. default_factory fixes that; this test would fail against the
    old bare-default implementation whenever run after the module's first
    import in a process (i.e. always, in a real test suite)."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert Settings().has_llm_key is False

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-123")
    assert Settings().anthropic_api_key == "sk-test-123"
    assert Settings().has_llm_key is True

    monkeypatch.setenv("SOC_CORRELATION_WINDOW_MIN", "15")
    assert Settings().correlation_window_minutes == 15
