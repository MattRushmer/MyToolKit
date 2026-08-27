"""Shared data contracts used across the detection_forge pipeline.

Every module (ingest, llm, rules, backtest, scoring, export) reads/writes
these types so the CLI and web app can share one core pipeline.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ExtractedIOC:
    """A single indicator pulled out of a CTI report during ingestion."""

    ioc_type: str  # ip | domain | sha256 | sha1 | md5 | cve | filename | registry_key
    value: str
    context: str = ""  # surrounding sentence/snippet the IOC was found in


@dataclass
class CTIInput:
    """Normalized CTI report ready to hand to the LLM rule generator."""

    raw_text: str
    source_name: str = "unnamed-report"
    iocs: list[ExtractedIOC] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)


@dataclass
class AttackTagValidation:
    tag: str  # e.g. "attack.t1059.001"
    technique_id: str  # e.g. "T1059.001"
    valid: bool
    technique_name: str | None = None
    reason: str | None = None  # populated when valid=False


@dataclass
class GeneratedRule:
    """The Sigma rule drafted by the LLM, plus everything needed to trust it."""

    rule_yaml: str
    title: str
    sigma_id: str
    attack_tags: list[str] = field(default_factory=list)
    attack_validations: list[AttackTagValidation] = field(default_factory=list)
    structural_errors: list[str] = field(default_factory=list)  # from pySigma validation
    structurally_valid: bool = False
    model_used: str = ""
    raw_llm_response: str = ""
    generation_notes: str = ""  # LLM's own reasoning/caveats, shown to analyst


@dataclass
class MatchedEvent:
    line_number: int
    record: dict[str, Any]
    matched_selection_names: list[str] = field(default_factory=list)


@dataclass
class BacktestResult:
    log_file: str
    total_events_scanned: int
    matched_events: list[MatchedEvent] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)
    unmapped_fields: list[str] = field(default_factory=list)  # fields the rule needs but never seen in logs

    @property
    def match_count(self) -> int:
        return len(self.matched_events)

    @property
    def match_rate(self) -> float:
        if self.total_events_scanned == 0:
            return 0.0
        return self.match_count / self.total_events_scanned


@dataclass
class NoiseFactor:
    name: str
    score_impact: float  # 0-100 contribution
    explanation: str


@dataclass
class NoiseScore:
    total_score: float  # 0 (silent) - 100 (extremely noisy), lower is better
    band: str  # "low" | "medium" | "high" | "critical"
    factors: list[NoiseFactor] = field(default_factory=list)
    summary: str = ""


@dataclass
class ExportedRule:
    target: str  # "sigma" | "splunk" | "elasticsearch" | "wazuh"
    content: str
    filename: str
    warnings: list[str] = field(default_factory=list)


@dataclass
class PipelineResult:
    cti: CTIInput
    rule: GeneratedRule
    backtest: BacktestResult | None
    noise: NoiseScore | None
    exports: list[ExportedRule] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)

    @property
    def ready_to_ship(self) -> bool:
        """Conservative gate: structurally valid, all ATT&CK tags real, and not critically noisy."""
        if not self.rule.structurally_valid:
            return False
        if any(not v.valid for v in self.rule.attack_validations):
            return False
        if self.noise and self.noise.band == "critical":
            return False
        return True
