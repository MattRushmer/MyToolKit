"""End-to-end: run the real scripted scenario against three in-memory demo
MCP servers and confirm every planted outcome category actually fires -
this is the integration-test target VibeCheck-style tools use fixtures for."""
from __future__ import annotations

from agentwarden.models import CallOutcome
from agentwarden.store.connection import Store
from fixtures.demo_scenario import build_demo_proxy, run_demo_scenario


async def test_demo_scenario_produces_every_outcome_category(tmp_path):
    store = Store(tmp_path / "demo.db")
    await store.open()
    proxy, pool = await build_demo_proxy(store, instance_id="test-instance")
    try:
        result = await run_demo_scenario(proxy)
    finally:
        await pool.stop()
        await store.close()

    error_flags = [s.is_error for s in result.steps]
    assert error_flags == [False, False, True, True, False, False, True, True]

    # step 3: explicit deny -> "denied by rule"; step 4: scope violation -> "constraints"
    assert "denied by rule" in result.steps[2].result_text
    assert "constraints" in result.steps[3].result_text
    # step 5.3 (index 6): rate limit
    assert "already minted" in result.steps[6].result_text
    # step 6 (index 7): blast radius
    assert "distinct upstream" in result.steps[7].result_text


async def test_demo_scenario_audit_trail_covers_expected_event_types(tmp_path):
    from agentwarden.store import audit as audit_store

    store = Store(tmp_path / "demo.db")
    await store.open()
    proxy, pool = await build_demo_proxy(store, instance_id="test-instance")
    try:
        await run_demo_scenario(proxy)
        events = await audit_store.list_events(store)
    finally:
        await pool.stop()
        await store.close()

    event_types = {e.event_type.value for e in events}
    assert {"session_opened", "delegation_accepted", "policy_denied", "scope_violation", "rate_exceeded", "blast_radius_exceeded"} <= event_types


async def test_demo_scenario_blast_radius_report(tmp_path):
    from agentwarden.analysis.blast_radius import compute_blast_radius
    from agentwarden.clock import SystemClock
    from fixtures.demo_scenario import DEMO_BLAST_RADIUS_CEILING, ROOT_TASK_ID

    store = Store(tmp_path / "demo.db")
    await store.open()
    proxy, pool = await build_demo_proxy(store, instance_id="test-instance")
    try:
        await run_demo_scenario(proxy)
        report = await compute_blast_radius(store, ROOT_TASK_ID, DEMO_BLAST_RADIUS_CEILING, SystemClock())
    finally:
        await pool.stop()
        await store.close()

    assert report.exceeded
    assert ("payments-mcp", "issue_refund") in report.reachable
    assert ("fs-mcp", "write_file") in report.reachable
