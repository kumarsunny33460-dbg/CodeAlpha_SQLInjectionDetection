"""Compatibility shim for the original ``sql_detector`` module.

The detection engine now lives in :mod:`sqlshield.security.detector`. The
helper functions below keep the original import path and the boolean contract
working for existing callers and scripts.
"""

from __future__ import annotations

from sqlshield.security.detector import (
    DetectionResult,
    analyse,
    analyse_fields,
    detect_sql_injection,
    normalize,
    redact,
    scan_payload,
)
from sqlshield.security.rules import RULES

#: The original module exposed the raw regular expressions.
SQL_ATTACK_PATTERNS = [rule.pattern.pattern for rule in RULES]

__all__ = [
    "DetectionResult",
    "SQL_ATTACK_PATTERNS",
    "analyse",
    "analyse_fields",
    "detect_sql_injection",
    "normalize",
    "redact",
    "scan_payload",
]
