"""An illustrative MSP-facing pricing calculator, NOT a market survey.

The enterprise AI SOC platforms this tool is positioned against (Prophet
Security, Dropzone AI, Conifers, Intezer) sell per-seat/per-integration deals
that assume an existing SIEM and a security team to supervise the agent - out
of reach for an MSP servicing 20 SMB clients on a shoestring. This module is
a *starting point* an MSP owner edits with their own real costs (LLM spend
from economics/cost.py + their own labor/overhead), not a competitor pricing
scrape or a claim about what the market actually charges. Every number here
is a configurable default - see the constants below and README.md.
"""
from __future__ import annotations

from dataclasses import dataclass

# Endpoint-count breakpoints and an illustrative $/endpoint/month band at each.
# Declining per-endpoint price reflects the usual MSP volume-discount shape;
# edit freely for a specific MSP's cost base and target margin.
_TIERS: list[dict] = [
    {"name": "Starter", "max_endpoints": 250, "price_per_endpoint_low": 1.25, "price_per_endpoint_high": 2.00},
    {"name": "Growth", "max_endpoints": 1000, "price_per_endpoint_low": 0.90, "price_per_endpoint_high": 1.50},
    {"name": "Scale", "max_endpoints": 5000, "price_per_endpoint_low": 0.60, "price_per_endpoint_high": 1.10},
    {"name": "Enterprise MSP", "max_endpoints": None, "price_per_endpoint_low": 0.40, "price_per_endpoint_high": 0.85},
]

_MONTHLY_FLOOR = 149.0  # suggested minimum monthly, so a 40-endpoint client isn't priced at $50/mo


@dataclass(frozen=True)
class PricingSuggestion:
    tier_name: str
    endpoint_count: int
    price_per_endpoint_low: float
    price_per_endpoint_high: float
    monthly_price_low: float
    monthly_price_high: float
    notes: str


def suggest_pricing(endpoint_count: int) -> PricingSuggestion:
    if endpoint_count <= 0:
        raise ValueError("endpoint_count must be positive")
    tier = next((t for t in _TIERS if t["max_endpoints"] is None or endpoint_count <= t["max_endpoints"]), _TIERS[-1])
    low = max(endpoint_count * tier["price_per_endpoint_low"], _MONTHLY_FLOOR)
    high = max(endpoint_count * tier["price_per_endpoint_high"], _MONTHLY_FLOOR)
    return PricingSuggestion(
        tier_name=tier["name"],
        endpoint_count=endpoint_count,
        price_per_endpoint_low=tier["price_per_endpoint_low"],
        price_per_endpoint_high=tier["price_per_endpoint_high"],
        monthly_price_low=round(low, 2),
        monthly_price_high=round(high, 2),
        notes=(
            "Illustrative default, not a market survey - edit soc_copilot/economics/pricing.py "
            "with your own LLM cost (see economics/cost.py) and labor overhead per client."
        ),
    )
