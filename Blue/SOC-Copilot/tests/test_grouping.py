from datetime import datetime, timedelta, timezone

from soc_copilot.correlate.grouping import group_into_incidents
from soc_copilot.models import Alert

T0 = datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc)


def _alert(alert_id, minutes_offset, host="HOST-A", user="", client_id="client-a", source="generic"):
    return Alert(
        alert_id=alert_id,
        client_id=client_id,
        source=source,
        timestamp=T0 + timedelta(minutes=minutes_offset),
        host=host,
        user=user,
        title=f"alert {alert_id}",
    )


def test_alerts_within_window_on_same_host_merge_into_one_incident():
    alerts = [_alert("a1", 0), _alert("a2", 10), _alert("a3", 30)]
    incidents = group_into_incidents(alerts, window_minutes=60)
    assert len(incidents) == 1
    assert len(incidents[0].alerts) == 3


def test_gap_beyond_window_splits_into_separate_incidents():
    alerts = [_alert("a1", 0), _alert("a2", 10), _alert("a3", 200)]
    incidents = group_into_incidents(alerts, window_minutes=60)
    assert len(incidents) == 2
    assert len(incidents[0].alerts) == 2
    assert len(incidents[1].alerts) == 1


def test_different_hosts_never_merge():
    alerts = [_alert("a1", 0, host="HOST-A"), _alert("a2", 5, host="HOST-B")]
    incidents = group_into_incidents(alerts, window_minutes=60)
    assert len(incidents) == 2


def test_different_clients_never_merge_even_on_same_host_name():
    alerts = [_alert("a1", 0, host="HOST-A", client_id="client-a"), _alert("a2", 5, host="HOST-A", client_id="client-b")]
    incidents = group_into_incidents(alerts, window_minutes=60)
    assert len(incidents) == 2
    assert {i.client_id for i in incidents} == {"client-a", "client-b"}


def test_hostless_alerts_group_by_user_instead():
    alerts = [_alert("a1", 0, host="", user="jsmith"), _alert("a2", 5, host="", user="jsmith")]
    incidents = group_into_incidents(alerts, window_minutes=60)
    assert len(incidents) == 1
    assert incidents[0].user == "jsmith"


def test_duplicate_alert_id_from_same_source_is_deduped():
    a1 = _alert("dup-1", 0)
    a2 = _alert("dup-1", 5)  # same id+source+client -> same alert re-ingested
    incidents = group_into_incidents([a1, a2], window_minutes=60)
    assert len(incidents) == 1
    assert len(incidents[0].alerts) == 1


def test_incident_id_is_deterministic_for_same_inputs():
    alerts = [_alert("a1", 0), _alert("a2", 10)]
    first = group_into_incidents(alerts, window_minutes=60)
    second = group_into_incidents(list(alerts), window_minutes=60)
    assert first[0].incident_id == second[0].incident_id


def test_multi_source_incident_reports_all_sources():
    alerts = [_alert("a1", 0, source="defender"), _alert("a2", 5, source="huntress")]
    incidents = group_into_incidents(alerts, window_minutes=60)
    assert incidents[0].sources == ["defender", "huntress"]
