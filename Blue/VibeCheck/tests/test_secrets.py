from __future__ import annotations

from tests.conftest import make_source
from vibecheck.rules.secrets import check_secrets


def test_flags_aws_access_key():
    source = make_source('AWS_KEY = "AKIAABCDEFGHIJKLMNOP"\n')
    findings = check_secrets(source)
    assert any("AWS" in f.title for f in findings)


def test_flags_anthropic_key():
    source = make_source('ANTHROPIC_API_KEY = "sk-ant-abcdefghijklmnopqrstuvwx"\n')
    findings = check_secrets(source)
    assert any("Anthropic" in f.title for f in findings)


def test_flags_generic_high_entropy_credential_assignment():
    source = make_source('db_password = "Xk9mQ2vRz8Lp4Wn7Ht3F"\n')
    findings = check_secrets(source)
    assert len(findings) == 1
    assert "db_password" in findings[0].title


def test_does_not_flag_env_var_lookup():
    source = make_source('api_key = os.environ["API_KEY"]\n')
    findings = check_secrets(source)
    assert findings == []


def test_does_not_flag_placeholder_value():
    source = make_source('API_KEY = "changeme_replace_with_real_key"\n')
    findings = check_secrets(source)
    assert findings == []


def test_does_not_flag_short_value():
    source = make_source('password = "abc123"\n')
    findings = check_secrets(source)
    assert findings == []


def test_vendor_key_never_appears_raw_in_snippet_or_evidence():
    raw_secret = "AKIAABCDEFGHIJKLMNOP"
    source = make_source(f'AWS_KEY = "{raw_secret}"\n')
    findings = check_secrets(source)
    assert findings, "expected at least one finding"
    for finding in findings:
        assert raw_secret not in finding.snippet
        assert raw_secret not in str(finding.evidence)


def test_generic_credential_value_never_appears_raw_in_snippet_or_evidence():
    raw_secret = "Xk9mQ2vRz8Lp4Wn7Ht3F"
    source = make_source(f'db_password = "{raw_secret}"\n')
    findings = check_secrets(source)
    assert findings, "expected at least one finding"
    for finding in findings:
        assert raw_secret not in finding.snippet
        assert raw_secret not in str(finding.evidence)
