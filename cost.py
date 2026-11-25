"""Token pricing tables, per-token-type USD cost breakdown, and scan expense formatting."""

import dataclasses
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

# Standard-tier USD pricing per 1,000,000 tokens:
#   (uncached_input_usd, cached_input_usd, output_and_thinking_usd)
MODEL_PRICING_PER_1M: Dict[str, Tuple[float, float, float]] = {
    "gemini-4-hydrogen": (1.50, 0.075, 7.50),
    "gemini-4-neon": (3.00, 0.15, 15.00),
    "gemini-4-argon": (4.00, 0.20, 20.00),
    "gemini-4-carbon": (4.00, 0.20, 20.00),
    "gemini-3.8-flash": (0.50, 0.05, 3.00),
    "gemini-3.7-flash": (0.50, 0.05, 3.00),
    "gemini-3-flash": (0.50, 0.05, 3.00),
    "gemini-3.1-pro": (2.00, 0.20, 12.00),
    "gemini-2.5-pro": (1.25, 0.125, 10.00),
    "gemini-2.5-flash": (0.30, 0.03, 2.50),
}


@dataclasses.dataclass
class TokenCostBreakdown:
  """USD cost breakdown across uncached input, cached input, output, and thinking tokens."""

  uncached_input_usd: float = 0.0
  cached_input_usd: float = 0.0
  output_usd: float = 0.0
  thought_usd: float = 0.0

  @property
  def total_usd(self) -> float:
    return (
        self.uncached_input_usd
        + self.cached_input_usd
        + self.output_usd
        + self.thought_usd
    )

  def add(self, other: "TokenCostBreakdown") -> None:
    self.uncached_input_usd += other.uncached_input_usd
    self.cached_input_usd += other.cached_input_usd
    self.output_usd += other.output_usd
    self.thought_usd += other.thought_usd


def resolve_model_pricing(model: str) -> Optional[Tuple[float, float, float]]:
  """Returns `(uncached_in, cached_in, out_plus_thinking)` USD per 1M tokens for `model`."""
  norm = (model or "").strip().lower()
  if not norm:
    return None
  for prefix in sorted(MODEL_PRICING_PER_1M, key=len, reverse=True):
    if norm == prefix or norm.startswith((f"{prefix}-", f"{prefix}_", f"{prefix}.")):
      return MODEL_PRICING_PER_1M[prefix]
  return None


def estimate_token_cost_breakdown(
    model: str,
    input_tokens: int,
    cached_tokens: int,
    output_tokens: int,
    thought_tokens: int = 0,
) -> Optional[TokenCostBreakdown]:
  """Estimates per-token-type Standard-tier USD costs, or None if `model` has no known rate."""
  in_tok = max(0, int(input_tokens or 0))
  cached_tok = max(0, min(int(cached_tokens or 0), in_tok))
  uncached_tok = in_tok - cached_tok
  out_tok = max(0, int(output_tokens or 0))
  think_tok = max(0, int(thought_tokens or 0))
  if in_tok == 0 and out_tok == 0 and think_tok == 0:
    return TokenCostBreakdown()
  rates = resolve_model_pricing(model)
  if rates is None:
    return None
  in_rate, cache_rate, out_rate = rates
  return TokenCostBreakdown(
      uncached_input_usd=(uncached_tok * in_rate) / 1_000_000.0,
      cached_input_usd=(cached_tok * cache_rate) / 1_000_000.0,
      output_usd=(out_tok * out_rate) / 1_000_000.0,
      thought_usd=(think_tok * out_rate) / 1_000_000.0,
  )


def estimate_token_cost_usd(
    model: str,
    input_tokens: int,
    cached_tokens: int,
    output_tokens: int,
    thought_tokens: int = 0,
) -> Optional[float]:
  """Estimates total Standard-tier USD cost for a turn or session, or None if unknown."""
  breakdown = estimate_token_cost_breakdown(
      model, input_tokens, cached_tokens, output_tokens, thought_tokens
  )
  return breakdown.total_usd if breakdown is not None else None


def format_tokens_short(n: int) -> str:
  if n >= 1_000_000:
    return f"{n / 1_000_000:.2f}M"
  if n >= 1_000:
    return f"{n / 1_000:.1f}k"
  return str(n)


def format_duration_short(seconds: float) -> str:
  sec = max(0.0, float(seconds or 0.0))
  if 0.0 < sec < 10.0:
    return f"{sec:.1f}s"
  total_sec = int(round(sec))
  h, rem = divmod(total_sec, 3600)
  m, s = divmod(rem, 60)
  if h > 0:
    return f"{h}h {m:02d}m {s:02d}s"
  if m > 0:
    return f"{m}m {s:02d}s"
  return f"{s}s"


def format_usd(cost: float) -> str:
  if cost <= 0.0:
    return "$0.00"
  if cost < 0.01:
    return f"~${cost:.4f}"
  return f"~${cost:.2f}"


@dataclasses.dataclass
class ScanStats:
  """Aggregated `cm stats --json --session` token, timing, and per-type cost metrics."""

  session_ids: List[str]
  models: List[str]
  total_turns: int = 0
  tool_turns: int = 0
  input_tokens: int = 0
  cached_tokens: int = 0
  output_tokens: int = 0
  thought_tokens: int = 0
  total_tokens: int = 0
  duration_seconds: float = 0.0
  cost_breakdown: Optional[TokenCostBreakdown] = None

  @property
  def uncached_input_tokens(self) -> int:
    return max(0, self.input_tokens - self.cached_tokens)

  @property
  def cache_hit_percent(self) -> float:
    return (self.cached_tokens / self.input_tokens * 100.0) if self.input_tokens > 0 else 0.0

  @property
  def llm_turns(self) -> int:
    return self.total_turns + self.tool_turns

  @property
  def estimated_cost_usd(self) -> Optional[float]:
    return self.cost_breakdown.total_usd if self.cost_breakdown is not None else None

  def format_summary(self) -> str:
    bd = self.cost_breakdown
    cost_part = f"{format_usd(bd.total_usd)} | " if bd is not None else ""
    models_part = f" | model: {', '.join(self.models)}" if self.models else ""
    header = (
        f"cm-ci: scan cost — {cost_part}{format_tokens_short(self.total_tokens)} tokens"
        f" | {self.llm_turns} turn(s) | {format_duration_short(self.duration_seconds)}{models_part}"
    )

    uncached_tok = format_tokens_short(self.uncached_input_tokens)
    cached_tok = format_tokens_short(self.cached_tokens)
    out_tok = format_tokens_short(self.output_tokens)
    think_tok = format_tokens_short(self.thought_tokens)
    tok_width = max(len(uncached_tok), len(cached_tok), len(out_tok), len(think_tok))

    if bd is not None:
      rows = [
          ("Uncached input", uncached_tok, f"({format_usd(bd.uncached_input_usd)})"),
          (
              "Cached input",
              cached_tok,
              f"({format_usd(bd.cached_input_usd)}, {self.cache_hit_percent:.1f}% cache hit)",
          ),
          ("Output", out_tok, f"({format_usd(bd.output_usd)})"),
          ("Thinking", think_tok, f"({format_usd(bd.thought_usd)})"),
      ]
    else:
      rows = [
          ("Uncached input", uncached_tok, ""),
          ("Cached input", cached_tok, f"({self.cache_hit_percent:.1f}% cache hit)"),
          ("Output", out_tok, ""),
          ("Thinking", think_tok, ""),
      ]

    detail_lines = [
        f"  {label:<14} : {tok:>{tok_width}} tokens" + (f" {suffix}" if suffix else "")
        for label, tok, suffix in rows
    ]
    return "\n".join([header, *detail_lines])


def aggregate_scan_stats(
    session_payloads: Iterable[Tuple[str, Mapping[str, Any]]],
) -> Optional[ScanStats]:
  """Aggregates `(session_id, cm_stats_json_dict)` pairs with turn dedup and per-type pricing."""
  included_sessions: List[str] = []
  seen_session_ids: Set[str] = set()
  seen_turn_ids: Set[str] = set()
  models: List[str] = []
  total_turns = 0
  tool_turns = 0
  input_tokens = 0
  cached_tokens = 0
  output_tokens = 0
  thought_tokens = 0
  total_tokens = 0
  duration_seconds = 0.0
  breakdown = TokenCostBreakdown()
  has_unpriced_tokens = False

  def _record_model(m: Any) -> str:
    m_str = str(m or "").strip()
    if m_str and m_str not in models:
      models.append(m_str)
    return m_str

  for sid, payload in session_payloads:
    if not payload:
      continue
    resp_sid = str(payload.get("session_id") or sid)
    session_model = str(payload.get("model") or "").strip()
    raw_turns = payload.get("turns")

    if isinstance(raw_turns, list) and raw_turns:
      new_turns: List[Mapping[str, Any]] = []
      for t in raw_turns:
        if not isinstance(t, Mapping):
          continue
        tid = str(t.get("interaction_id") or t.get("turn") or "").strip()
        if tid:
          if tid in seen_turn_ids:
            continue
          seen_turn_ids.add(tid)
        new_turns.append(t)
      if not new_turns:
        continue
      if resp_sid not in seen_session_ids:
        seen_session_ids.add(resp_sid)
        included_sessions.append(resp_sid)
      for t in new_turns:
        t_model = _record_model(t.get("model") or session_model)
        t_in = int(t.get("input_tokens") or 0)
        t_ca = int(t.get("cached_tokens") or 0)
        t_out = int(t.get("output_tokens") or 0)
        t_th = int(t.get("thought_tokens") or 0)
        t_tot = int(t.get("total_tokens") or (t_in + t_out + t_th))
        input_tokens += t_in
        cached_tokens += t_ca
        output_tokens += t_out
        thought_tokens += t_th
        total_tokens += t_tot
        t_bd = estimate_token_cost_breakdown(t_model, t_in, t_ca, t_out, t_th)
        if t_bd is None:
          has_unpriced_tokens = True
        else:
          breakdown.add(t_bd)

      if len(new_turns) == len(raw_turns):
        total_turns += int(payload.get("total_turns") or len(new_turns))
        tool_turns += int(payload.get("tool_turns") or 0)
        duration_seconds += float(payload.get("duration_seconds") or 0.0)
      else:
        total_turns += len(new_turns)
        duration_seconds += max(
            (float(t.get("duration_seconds") or 0.0) for t in new_turns),
            default=0.0,
        )
    else:
      if resp_sid in seen_session_ids:
        continue
      seen_session_ids.add(resp_sid)
      included_sessions.append(resp_sid)
      s_model = _record_model(session_model)
      s_in = int(payload.get("input_tokens") or 0)
      s_ca = int(payload.get("cached_tokens") or 0)
      s_out = int(payload.get("output_tokens") or 0)
      s_th = int(payload.get("thought_tokens") or 0)
      s_tot = int(payload.get("total_tokens") or (s_in + s_out + s_th))
      input_tokens += s_in
      cached_tokens += s_ca
      output_tokens += s_out
      thought_tokens += s_th
      total_tokens += s_tot
      total_turns += int(payload.get("total_turns") or 0)
      tool_turns += int(payload.get("tool_turns") or 0)
      duration_seconds += float(payload.get("duration_seconds") or 0.0)
      s_bd = estimate_token_cost_breakdown(s_model, s_in, s_ca, s_out, s_th)
      if s_bd is None:
        has_unpriced_tokens = True
      else:
        breakdown.add(s_bd)

  if not included_sessions:
    return None

  return ScanStats(
      session_ids=included_sessions,
      models=models,
      total_turns=total_turns,
      tool_turns=tool_turns,
      input_tokens=input_tokens,
      cached_tokens=cached_tokens,
      output_tokens=output_tokens,
      thought_tokens=thought_tokens,
      total_tokens=total_tokens,
      duration_seconds=duration_seconds,
      cost_breakdown=None if has_unpriced_tokens else breakdown,
  )
