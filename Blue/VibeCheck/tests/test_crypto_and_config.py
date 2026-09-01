from __future__ import annotations

from tests.conftest import make_source
from vibecheck.rules.catalog import (
    VIBE_SEC_DEBUG_ENABLED,
    VIBE_SEC_PERMISSIVE_CORS,
    VIBE_SEC_TLS_VERIFICATION_DISABLED,
    VIBE_SEC_WEAK_PASSWORD_HASH,
)
from vibecheck.rules.crypto_and_config import check_crypto_and_config


def test_flags_md5_password_hash():
    source = make_source("pwd_hash = hashlib.md5(password.encode()).hexdigest()\n")
    findings = check_crypto_and_config(source)
    assert any(f.rule_id == VIBE_SEC_WEAK_PASSWORD_HASH for f in findings)


def test_does_not_flag_md5_on_unrelated_data():
    source = make_source("checksum = hashlib.md5(file_bytes).hexdigest()\n")
    findings = check_crypto_and_config(source)
    assert findings == []


def test_does_not_flag_bcrypt():
    source = make_source("pwd_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())\n")
    findings = check_crypto_and_config(source)
    assert findings == []


def test_flags_requests_verify_false():
    source = make_source('requests.get(url, verify=False)\n')
    findings = check_crypto_and_config(source)
    assert any(f.rule_id == VIBE_SEC_TLS_VERIFICATION_DISABLED for f in findings)


def test_does_not_flag_default_requests_call():
    source = make_source("requests.get(url)\n")
    findings = check_crypto_and_config(source)
    assert findings == []


def test_flags_wildcard_cors_with_credentials_as_critical():
    source = make_source(
        """
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        """
    )
    findings = check_crypto_and_config(source)
    hit = next(f for f in findings if f.rule_id == VIBE_SEC_PERMISSIVE_CORS)
    assert hit.severity == "critical"


def test_flags_wildcard_cors_alone_as_medium():
    source = make_source("response.headers['Access-Control-Allow-Origin'] = '*'\n")
    findings = check_crypto_and_config(source)
    hit = next(f for f in findings if f.rule_id == VIBE_SEC_PERMISSIVE_CORS)
    assert hit.severity == "medium"


def test_does_not_flag_specific_cors_origin():
    source = make_source("response.headers['Access-Control-Allow-Origin'] = 'https://example.com'\n")
    findings = check_crypto_and_config(source)
    assert findings == []


def test_flags_flask_debug_true():
    source = make_source("app.run(debug=True)\n")
    findings = check_crypto_and_config(source)
    assert any(f.rule_id == VIBE_SEC_DEBUG_ENABLED for f in findings)


def test_does_not_flag_debug_false():
    source = make_source("app.run(debug=False)\n")
    findings = check_crypto_and_config(source)
    assert findings == []
