from __future__ import annotations

from typing import Any, Dict, Mapping, Optional


# --- Helper Conversion Functions ---


def _as_str(value: Any) -> Optional[str]:
  """Coerces a value to a non-empty string, or None."""
  if value is None:
    return None
  text = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
  text = text.strip()
  return text or None


def _as_int(value: Any) -> Optional[int]:
  """Coerces a value to int, returning None rather than raising."""
  if value is None or isinstance(value, bool):
    return int(value) if isinstance(value, bool) else None
  try:
    return int(value)
  except (TypeError, ValueError):
    return None


# --- Main Finding Class ---


class Finding:
  """Unified representation of a security vulnerability finding wrapping a raw dict."""

  def __init__(
      self,
      raw: Optional[Mapping[str, Any]] = None,
      **kwargs: Any,
  ):
    self._raw: Dict[str, Any] = {}
    if raw:
      self._raw.update(dict(raw.items()) if hasattr(raw, "items") else dict(raw))
    if kwargs:
      self._raw.update(kwargs)

  def _get(self, *keys: str) -> Any:
    for k in keys:
      if k in self._raw and self._raw[k] is not None:
        return self._raw[k]
    return None

  # --- Properties ---

  @property
  def analysis(self) -> Optional[str]:
    return _as_str(self._get("analysis"))

  @property
  def dismiss_reason(self) -> Optional[str]:
    return _as_str(self._get("dismiss_reason"))

  @property
  def duplicate_of(self) -> Optional[Any]:
    return self._get("duplicate_of")

  @property
  def end_line(self) -> Optional[int]:
    return _as_int(self._get("end_line"))

  @property
  def file_path(self) -> Optional[str]:
    return _as_str(self._get("file_path"))

  @property
  def finding_id(self) -> Optional[str]:
    return _as_str(self._get("finding_id"))

  @property
  def gh_issue_number(self) -> Optional[Any]:
    return self._get("gh_issue_number")

  @property
  def raw_lines(self) -> Optional[Any]:
    return self._get("raw_lines")

  @property
  def severity(self) -> Optional[str]:
    val = _as_str(self._get("severity"))
    return val.upper() if val else None

  @property
  def snippet(self) -> Optional[str]:
    return _as_str(self._get("snippet"))

  @property
  def start_line(self) -> Optional[int]:
    return _as_int(self._get("start_line"))

  @property
  def status(self) -> Optional[str]:
    val = _as_str(self._get("status", "state"))
    return val.upper() if val else None

  @property
  def title(self) -> Optional[str]:
    return _as_str(self._get("title"))

  @property
  def vuln_id(self) -> Optional[str]:
    return _as_str(self._get("vuln_id"))

  @property
  def vuln_type(self) -> Optional[str]:
    return _as_str(self._get("vuln_type"))

  # --- Factory Methods ---

  @classmethod
  def from_dict(
      cls,
      data: Mapping[str, Any],
  ) -> Finding:
    """Creates a Finding instance from a dictionary."""
    raw: Dict[str, Any] = dict(data.items()) if hasattr(data, "items") else dict(data)
    return cls(raw)

  # --- Serialization & Export Formats ---

  def to_dict(self) -> Dict[str, Any]:
    """Returns a dictionary representation of the finding."""
    return dict(self._raw)

  def __repr__(self) -> str:
    return f"Finding(finding_id={self.finding_id!r}, file_path={self.file_path!r}, status={self.status!r})"

  def __eq__(self, other: Any) -> bool:
    if isinstance(other, Finding):
      return self.finding_id == other.finding_id
    return False

  def __hash__(self) -> int:
    return hash(self.finding_id)