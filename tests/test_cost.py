"""Unit tests for cost.py."""

import unittest

import cost
from cost import ScanStats, TokenCostBreakdown


class CostTests(unittest.TestCase):
  """Unit tests for model pricing, per-token-type USD breakdowns, and summary formatting."""

  def test_resolve_model_pricing_and_per_token_type_breakdown(self) -> None:
    self.assertEqual(cost.resolve_model_pricing("gemini-4-hydrogen"), (1.50, 0.075, 7.50))
    self.assertEqual(
        cost.resolve_model_pricing("gemini-4-hydrogen-cyber-permissive"),
        (1.50, 0.075, 7.50),
    )
    self.assertEqual(cost.resolve_model_pricing("gemini-4-neon"), (3.00, 0.15, 15.00))
    self.assertEqual(cost.resolve_model_pricing("gemini-4-argon"), (4.00, 0.20, 20.00))
    self.assertEqual(cost.resolve_model_pricing("gemini-4-carbon"), (4.00, 0.20, 20.00))
    self.assertEqual(cost.resolve_model_pricing("gemini-3.8-flash-cyber"), (0.50, 0.05, 3.00))
    self.assertIsNone(cost.resolve_model_pricing("custom-private-model"))

    bd = cost.estimate_token_cost_breakdown(
        "gemini-4-hydrogen",
        input_tokens=500_000,
        cached_tokens=300_000,
        output_tokens=5_000,
        thought_tokens=15_000,
    )
    self.assertIsNotNone(bd)
    assert bd is not None
    # 200k uncached * $1.50/1M = $0.30
    self.assertAlmostEqual(bd.uncached_input_usd, 0.30, places=6)
    # 300k cached * $0.075/1M = $0.0225
    self.assertAlmostEqual(bd.cached_input_usd, 0.0225, places=6)
    # 5k output * $7.50/1M = $0.0375
    self.assertAlmostEqual(bd.output_usd, 0.0375, places=6)
    # 15k thinking * $7.50/1M = $0.1125
    self.assertAlmostEqual(bd.thought_usd, 0.1125, places=6)
    self.assertAlmostEqual(bd.total_usd, 0.4725, places=6)

  def test_scan_stats_format_summary_includes_each_token_type_price(self) -> None:
    stats = ScanStats(
        session_ids=["s1"],
        models=["gemini-4-hydrogen"],
        total_turns=2,
        tool_turns=4,
        input_tokens=500_000,
        cached_tokens=300_000,
        output_tokens=5_000,
        thought_tokens=15_000,
        total_tokens=520_000,
        duration_seconds=82.0,
        cost_breakdown=TokenCostBreakdown(
            uncached_input_usd=0.30,
            cached_input_usd=0.0225,
            output_usd=0.0375,
            thought_usd=0.1125,
        ),
    )
    self.assertEqual(
        stats.format_summary(),
        "\n".join([
            "cm-ci: scan cost — ~$0.47 | 520.0k tokens | 6 turn(s) | 1m 22s | model: gemini-4-hydrogen",
            "  Uncached input : 200.0k tokens (~$0.30)",
            "  Cached input   : 300.0k tokens (~$0.02, 60.0% cache hit)",
            "  Output         :   5.0k tokens (~$0.04)",
            "  Thinking       :  15.0k tokens (~$0.11)",
        ]),
    )

    # Unknown model omits USD segments cleanly
    unpriced = ScanStats(
        session_ids=["s2"],
        models=["unknown-model"],
        total_turns=1,
        tool_turns=0,
        input_tokens=10_000,
        cached_tokens=2_000,
        output_tokens=500,
        thought_tokens=0,
        total_tokens=10_500,
        duration_seconds=5.4,
        cost_breakdown=None,
    )
    self.assertEqual(
        unpriced.format_summary(),
        "\n".join([
            "cm-ci: scan cost — 10.5k tokens | 1 turn(s) | 5.4s | model: unknown-model",
            "  Uncached input : 8.0k tokens",
            "  Cached input   : 2.0k tokens (20.0% cache hit)",
            "  Output         :  500 tokens",
            "  Thinking       :    0 tokens",
        ]),
    )


if __name__ == "__main__":
  unittest.main()
