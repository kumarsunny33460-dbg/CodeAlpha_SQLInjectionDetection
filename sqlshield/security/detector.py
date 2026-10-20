"""SQL injection detection engine.

The engine combines a rule catalogue with a small statistical heuristic. Input
is normalised before evaluation so that common evasion tricks - URL encoding,
HTML entities, unicode look alikes, comment separated keywords and null bytes
- are unwrapped before the rules run.

Design goals:

* **No false positives on legitimate data.** Rules are scoped per field, a
  plain ``--`` inside a name does not trip the engine, but ``--`` inside a
  capability code is never inspected because secrets legitimately contain it.
* **Explainable verdicts.** Every result lists the rules that fired, the
  accumulated risk score and a severity band.
* **Deterministic and dependency free.** The engine has no I/O and no global
  state, which makes it safe to reuse from workers or CLI tooling.
"""

from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass
from dataclasses import field as dc_field
from urllib.parse import unquote

from .rules import HEURISTIC_KEYWORDS, SIGNAL_KEYWORDS, Rule, rules_for_field

#: Score at or above which a request is treated as an injection attempt.
DEFAULT_BLOCK_THRESHOLD = 40

#: Maximum number of decoding passes applied to a payload.
MAX_DECODE_PASSES = 3

_COMMENT_BLOCK = re.compile(r"/\*.*?\*/", re.DOTALL)
_VERSION_COMMENT = re.compile(r"/\*!\s*(.*?)\s*\*/", re.DOTALL)
_COMMENT_LINE = re.compile(r"(?:--|#)[^\n]*")
_WHITESPACE = re.compile(r"\s+")
_WORD = re.compile(r"[a-z_][a-z_0-9]*")

SEVERITY_BANDS = (
    (90, "critical"),
    (70, "high"),
    (55, "medium"),
    (40, "low"),
    (0, "none"),
)


@dataclass(frozen=True)
class DetectionResult:
    """Outcome of a single field evaluation."""

    is_injection: bool
    score: int
    severity: str
    categories: tuple[str, ...] = ()
    matched_rules: tuple[str, ...] = ()
    field: str = ""
    evidence: str = ""
    signals: tuple[str, ...] = dc_field(default_factory=tuple)

    @property
    def blocked(self) -> bool:
        return self.is_injection

    def to_dict(self) -> dict:
        return {
            "is_injection": self.is_injection,
            "score": self.score,
            "severity": self.severity,
            "categories": list(self.categories),
            "matched_rules": list(self.matched_rules),
            "field": self.field,
            "evidence": self.evidence,
            "signals": list(self.signals),
        }


def severity_for(score: int) -> str:
    for minimum, label in SEVERITY_BANDS:
        if score >= minimum:
            return label
    return "none"


def _decode_once(value: str) -> str:
    decoded = unquote(value)
    return html.unescape(decoded)


def normalize(value: str) -> tuple[str, str, bool]:
    """Return ``(prepared, stripped, had_encoding)`` for ``value``.

    ``prepared`` is the lower cased, decoded and whitespace collapsed input.
    ``stripped`` additionally removes SQL comments, which exposes payloads
    where keywords are split by comments such as ``UNI/**/ON``.
    ``had_encoding`` reports whether the input contained encoded data.
    """
    if value is None:
        return "", "", False

    raw = value if isinstance(value, str) else str(value)

    decoded = raw
    had_encoding = False
    for _ in range(MAX_DECODE_PASSES):
        candidate = _decode_once(decoded)
        if candidate == decoded:
            break
        decoded = candidate
        had_encoding = True

    prepared = unicodedata.normalize("NFKC", decoded)
    prepared = prepared.replace("\x00", "")
    prepared = prepared.lower()
    prepared = _WHITESPACE.sub(" ", prepared).strip()

    stripped = _strip_comments(prepared, tight=True)

    return prepared, stripped, had_encoding


def _strip_comments(value: str, tight: bool = True) -> str:
    """Remove SQL comments from ``value``.

    Two variants are produced. The tight variant removes block comments
    without inserting a space so that a keyword split by a comment is
    reassembled (``uni/**/on`` becomes ``union``). The loose variant replaces
    every comment with a space so that separate tokens stay separate.
    """
    block_replacement = "" if tight else " "
    line_replacement = " " if tight else " "

    stripped = _VERSION_COMMENT.sub(r" \1 ", value)
    stripped = _COMMENT_BLOCK.sub(block_replacement, stripped)
    stripped = _COMMENT_LINE.sub(line_replacement, stripped)

    return _WHITESPACE.sub(" ", stripped).strip()


def _loose_strip(value: str) -> str:
    """Remove comments while keeping a space between the remaining tokens."""
    return _strip_comments(value, tight=False)


def _rule_matches(rule: Rule, prepared: str, stripped: str, loose: str) -> bool:
    if rule.compare == "raw":
        return bool(rule.pattern.search(prepared))
    if rule.compare == "stripped":
        return bool(rule.pattern.search(stripped) or rule.pattern.search(loose))
    return bool(
        rule.pattern.search(prepared)
        or rule.pattern.search(stripped)
        or rule.pattern.search(loose)
    )


def _keyword_signals(stripped: str) -> list[str]:
    tokens = _WORD.findall(stripped)
    found: list[str] = []

    for token in tokens:
        if token in HEURISTIC_KEYWORDS and token not in found:
            found.append(token)

    for phrase in ("group by", "order by"):
        if phrase in stripped and phrase not in found:
            found.append(phrase)

    return found


def _broad_keywords(stripped: str) -> list[str]:
    """Return the SQL keywords present in the value, including common ones."""
    tokens = _WORD.findall(stripped)
    found: list[str] = []

    for token in tokens:
        if token in SIGNAL_KEYWORDS and token not in found:
            found.append(token)

    return found


def _quote_imbalance(value: str) -> bool:
    return value.count("'") % 2 == 1 or value.count('"') % 2 == 1


def redact(value: str, limit: int = 120) -> str:
    """Return a shortened, printable excerpt of ``value`` for evidence."""
    if value is None:
        return ""
    cleaned = "".join(char if char.isprintable() else "." for char in str(value))
    cleaned = cleaned.strip()
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[:limit] + "..."


def analyse(
    value: str,
    field_name: str = "value",
    threshold: int = DEFAULT_BLOCK_THRESHOLD,
) -> DetectionResult:
    """Evaluate a single value and return a :class:`DetectionResult`."""
    prepared, stripped, had_encoding = normalize(value)
    loose = _loose_strip(prepared)

    if not prepared:
        return DetectionResult(
            is_injection=False,
            score=0,
            severity="none",
            field=field_name,
        )

    score = 0
    categories: list[str] = []
    matched: list[str] = []
    signals: list[str] = []
    evidence = ""

    for rule in rules_for_field(field_name):
        if not _rule_matches(rule, prepared, stripped, loose):
            continue

        score += rule.weight
        matched.append(rule.id)
        if rule.category not in categories:
            categories.append(rule.category)

        if not evidence:
            match = (
                rule.pattern.search(prepared)
                or rule.pattern.search(stripped)
                or rule.pattern.search(loose)
            )
            evidence = redact(prepared) if match else redact(stripped)

    # Null bytes are stripped during normalisation, so they are checked on the
    # original value instead of the prepared text.
    if "\x00" in str(value or ""):
        score += 45
        matched.append("null_byte")
        signals.append("null_byte")
        if "Encoding Evasion" not in categories:
            categories.append("Encoding Evasion")

    keywords = _keyword_signals(stripped)
    if len(keywords) >= 2:
        score += 30
        signals.append("keyword_density")
        if "Keyword Heuristic" not in categories:
            categories.append("Keyword Heuristic")

    broad = _broad_keywords(stripped)

    if broad and _quote_imbalance(prepared):
        score += 20
        signals.append("quote_imbalance")

    if had_encoding and broad:
        score += 30
        signals.append("encoded_payload")
        if "Encoding Evasion" not in categories:
            categories.append("Encoding Evasion")

    score = min(score, 100)
    severity = severity_for(score)

    return DetectionResult(
        is_injection=score >= threshold,
        score=score,
        severity=severity,
        categories=tuple(categories),
        matched_rules=tuple(matched),
        field=field_name,
        evidence=evidence,
        signals=tuple(signals),
    )


def analyse_fields(
    fields: dict[str, str],
    threshold: int = DEFAULT_BLOCK_THRESHOLD,
) -> DetectionResult:
    """Evaluate a mapping of field names to values and return the worst hit."""
    worst: DetectionResult | None = None

    for name, value in fields.items():
        result = analyse(value, field_name=name, threshold=threshold)
        if worst is None or result.score > worst.score:
            worst = result

    if worst is None:
        return DetectionResult(is_injection=False, score=0, severity="none")

    return worst


def detect_sql_injection(value, threshold: int = DEFAULT_BLOCK_THRESHOLD) -> bool:
    """Backwards compatible helper returning a plain boolean verdict."""
    return analyse(value, field_name="value", threshold=threshold).is_injection


def scan_payload(value, field_name: str = "value") -> list[str]:
    """Return the identifiers of the rules that fired for ``value``."""
    return list(analyse(value, field_name=field_name).matched_rules)


__all__ = [
    "DetectionResult",
    "analyse",
    "analyse_fields",
    "detect_sql_injection",
    "scan_payload",
    "normalize",
    "redact",
    "severity_for",
    "DEFAULT_BLOCK_THRESHOLD",
]
