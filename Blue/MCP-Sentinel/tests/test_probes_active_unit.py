"""Unit tests for probes/active.py's pure helpers - no live server needed.
Complements tests/test_probes_active.py's real-stdio integration coverage.
"""
from __future__ import annotations

from types import SimpleNamespace

from mcp_sentinel.probes.active import _MAX_RESPONSE_CHARS, _extract_text


def _result_with_text_blocks(*texts: str):
    return SimpleNamespace(content=[SimpleNamespace(text=t) for t in texts])


def test_extract_text_joins_multiple_blocks():
    result = _result_with_text_blocks("hello", "world")
    assert _extract_text(result) == "hello\nworld"


def test_extract_text_ignores_blocks_without_text():
    result = SimpleNamespace(content=[SimpleNamespace(text=None), SimpleNamespace(text="kept")])
    assert _extract_text(result) == "kept"


def test_extract_text_handles_no_content():
    assert _extract_text(SimpleNamespace(content=None)) == ""
    assert _extract_text(SimpleNamespace(content=[])) == ""


def test_extract_text_caps_a_single_oversized_block():
    huge = "A" * (_MAX_RESPONSE_CHARS + 10_000)
    result = _result_with_text_blocks(huge)
    text = _extract_text(result)
    assert len(text) == _MAX_RESPONSE_CHARS


def test_extract_text_stops_accumulating_once_over_the_cap_across_blocks():
    # A hostile server could return many small blocks rather than one huge
    # one - the cap must still hold across the whole response, not just
    # per-block, and must not scan/hold an unbounded number of blocks first.
    block_size = 1_000
    num_blocks_to_exceed_cap = (_MAX_RESPONSE_CHARS // block_size) + 5
    blocks = ["B" * block_size] * num_blocks_to_exceed_cap
    result = _result_with_text_blocks(*blocks)
    text = _extract_text(result)
    assert len(text) <= _MAX_RESPONSE_CHARS
