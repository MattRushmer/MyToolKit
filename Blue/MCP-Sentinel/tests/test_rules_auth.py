from factories import make_config

from mcp_sentinel.models import TransportType
from mcp_sentinel.rules.auth import check_transport_auth


def test_remote_http_without_auth_header_is_critical():
    config = make_config(transport=TransportType.HTTP, url="https://mcp.example.com/mcp", has_auth_header=False)
    findings = check_transport_auth(config)
    assert len(findings) == 1
    assert findings[0].severity.value == "critical"


def test_remote_http_with_auth_header_not_flagged():
    config = make_config(transport=TransportType.HTTP, url="https://mcp.example.com/mcp", has_auth_header=True)
    findings = check_transport_auth(config)
    assert findings == []


def test_localhost_without_auth_header_is_low_not_critical():
    config = make_config(transport=TransportType.SSE, url="http://127.0.0.1:8000/sse", has_auth_header=False)
    findings = check_transport_auth(config)
    assert len(findings) == 1
    assert findings[0].severity.value == "low"


def test_stdio_transport_not_flagged_for_missing_auth_header():
    config = make_config(transport=TransportType.STDIO, command="python", url=None)
    findings = check_transport_auth(config)
    assert findings == []


def test_stdio_secret_flag_name_flagged():
    config = make_config(transport=TransportType.STDIO, command="python", args=("--api-key", "sk-abcdef1234567890"))
    findings = check_transport_auth(config)
    assert any("secret" in f.finding_id for f in findings)


def test_stdio_benign_args_not_flagged():
    config = make_config(transport=TransportType.STDIO, command="python", args=("--port", "8080", "-v"))
    findings = check_transport_auth(config)
    assert findings == []
