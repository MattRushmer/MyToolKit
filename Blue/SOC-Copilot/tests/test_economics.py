import pytest

from soc_copilot.economics.pricing import suggest_pricing
from soc_copilot.models import UsageCost


def test_usage_cost_math():
    usage = UsageCost(input_tokens=1_000_000, output_tokens=1_000_000)
    assert usage.cost_usd(cost_per_1m_input=3.0, cost_per_1m_output=15.0) == pytest.approx(18.0)


def test_usage_cost_zero_tokens_is_free():
    assert UsageCost().cost_usd(3.0, 15.0) == 0.0


def test_pricing_rejects_non_positive_endpoints():
    with pytest.raises(ValueError):
        suggest_pricing(0)
    with pytest.raises(ValueError):
        suggest_pricing(-5)


def test_pricing_applies_monthly_floor_for_tiny_client():
    suggestion = suggest_pricing(5)
    assert suggestion.monthly_price_low >= 149.0


def test_pricing_tier_selection_scales_with_endpoint_count():
    small = suggest_pricing(100)
    large = suggest_pricing(3000)
    assert small.tier_name == "Starter"
    assert large.tier_name == "Scale"
    # Per-endpoint price should decline as scale increases (volume discount shape).
    assert large.price_per_endpoint_high <= small.price_per_endpoint_low
