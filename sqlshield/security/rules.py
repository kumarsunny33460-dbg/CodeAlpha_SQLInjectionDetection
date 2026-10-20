"""Catalogue of SQL injection detection rules.

Every rule carries an identifier, a category, a severity weight and the set of
form fields the rule is meaningful for. Weights are additive: a request is
blocked when the accumulated score for a single field reaches the configured
threshold.

Field scoping exists to avoid false positives. A password or a capability code
may legitimately contain characters such as ``--`` or ``#`` so only rules that
have no plausible appearance in ordinary secrets are applied to them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Field groups used to scope rules.
FIELDS_ALL = ("name", "email", "password", "capability_code")
FIELDS_TEXT = ("name", "email")
FIELDS_CRITICAL = ("name", "email", "password", "capability_code")


@dataclass(frozen=True)
class Rule:
    """A single detection rule.

    ``compare`` controls which normalised form the rule is evaluated against:

    ``both``
        Match against the prepared input and the comment stripped input.
    ``raw``
        Match only against the prepared input, so comment markers are seen.
    """

    id: str
    category: str
    weight: int
    pattern: re.Pattern[str]
    description: str
    fields: tuple[str, ...] = FIELDS_ALL
    compare: str = "both"

    def applies_to(self, field_name: str) -> bool:
        return field_name in self.fields


def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


RULES: tuple[Rule, ...] = (
    # -----------------------------------------------------------------
    # Critical - classic injection primitives
    # -----------------------------------------------------------------
    Rule(
        id="union_select",
        category="Union Exfiltration",
        weight=100,
        pattern=_compile(r"\bunion\b[\s/*!()\d]*\b(?:all\b[\s/*!()\d]*)?\bselect\b"),
        description="UNION ... SELECT used to graft attacker controlled rows.",
    ),
    Rule(
        id="stacked_query",
        category="Stacked Query",
        weight=95,
        pattern=_compile(
            r";\s*(?:select|insert|update|delete|drop|alter|create|truncate|"
            r"exec|execute|grant|shutdown)\b"
        ),
        description="Multiple statements chained through a semicolon.",
    ),
    Rule(
        id="system_command",
        category="Remote Command Execution",
        weight=95,
        pattern=_compile(
            r"(?:\b(?:xp_cmdshell|sp_oacreate|sp_executesql|sp_makewebtask|"
            r"utl_http\.request|dbms_pipe\.receive_message|load_file|"
            r"into\s+outfile|into\s+dumpfile)\b)"
        ),
        description="Attempt to execute operating system or file system commands.",
    ),
    Rule(
        id="time_based_blind",
        category="Time Based Blind",
        weight=90,
        pattern=_compile(
            r"(?:\b(?:sleep|benchmark|pg_sleep|dbms_pipe\.receive_message)\s*\(|"
            r"\bwaitfor\s+delay\b|\bwaitfor\s+time\b)"
        ),
        description="Timing side channel used to extract data blind.",
    ),
    Rule(
        id="boolean_tautology",
        category="Boolean Tautology",
        weight=75,
        pattern=_compile(
            r"(?:\b(?:or|and)\b\s*\(?\s*['\"]?\s*\w+\s*['\"]?\s*=\s*"
            r"['\"]?\s*\w+\s*['\"]?\s*\)?)"
        ),
        description="Condition that is always true, the classic login bypass.",
        fields=FIELDS_TEXT + ("password",),
    ),
    Rule(
        id="ddl_statement",
        category="Schema Manipulation",
        weight=70,
        pattern=_compile(
            r"\b(?:drop\s+(?:table|database|schema|index)|truncate\s+table|"
            r"alter\s+table|create\s+(?:table|database|index|user)|"
            r"rename\s+table|grant\s+all|revoke\s+all)\b"
        ),
        description="Data definition statement attempting to alter the schema.",
    ),
    Rule(
        id="dml_statement",
        category="Data Manipulation",
        weight=65,
        pattern=_compile(
            r"\b(?:delete\s+from|insert\s+into|update\s+\w+\s+set|"
            r"replace\s+into)\b"
        ),
        description="Data manipulation statement injected into a parameter.",
    ),
    Rule(
        id="schema_probe",
        category="Schema Discovery",
        weight=55,
        pattern=_compile(
            r"(?:\binformation_schema\b|\bsysobjects\b|\bsyscolumns\b|"
            r"\bsys\.tables\b|\bpg_catalog\b|\bpg_tables\b|\bmysql\.user\b|"
            r"\ball_tables\b|\bmsysobjects\b)"
        ),
        description="Catalog metadata probing used to enumerate the database.",
    ),
    Rule(
        id="quote_breach",
        category="Quote Breach",
        weight=60,
        pattern=_compile(
            r"(?:['\"][^'\"\n]*['\"]?\s*(?:or|and|union|select|from|where|"
            r"order\s+by|group\s+by|having)\b)"
        ),
        description="Quoted literal followed by SQL keywords.",
    ),
    Rule(
        id="quote_comment_breach",
        category="Quote Breach",
        weight=60,
        pattern=_compile(r"['\"]\s*(?:--|#|/\*)"),
        description="Quoted literal terminated by a comment marker.",
        compare="raw",
    ),
    Rule(
        id="blind_extraction",
        category="Blind Extraction",
        weight=60,
        pattern=_compile(
            r"(?:\band\s+(?:ascii|ord|mid|substr|substring|length|"
            r"substring_index|cast)\s*\(|\blike\s+['\"]?%|\bif\s*\(\s*\d+\s*=\s*\d+)"
        ),
        description="Character by character extraction of hidden values.",
        fields=FIELDS_TEXT,
    ),
    Rule(
        id="conditional_stack",
        category="Conditional Payload",
        weight=55,
        pattern=_compile(
            r"(?:\bcase\s+when\b|\bif\s*\(\s*\(\s*select\b|"
            r"\bexists\s*\(\s*select\b|\bnot\s+exists\s*\(\s*select\b)"
        ),
        description="Conditional payload used to probe for hidden rows.",
        fields=FIELDS_TEXT,
    ),
    Rule(
        id="keyword_obfuscation",
        category="Obfuscation",
        weight=50,
        pattern=_compile(
            r"(?:\bchar\s*\(\s*\d+\s*(?:,\s*\d+\s*)*\)|"
            r"\bconcat\s*\(\s*(?:0x[0-9a-f]+|['\"])|"
            r"\b0x[0-9a-f]{8,}\b|"
            r"\bunhex\s*\(|\bconvert\s*\(\s*0x)"
        ),
        description="Payload reconstructed at runtime to defeat static filters.",
        fields=FIELDS_TEXT,
    ),
    Rule(
        id="comment_terminator",
        category="Comment Manipulation",
        weight=20,
        pattern=_compile(r"(?:--|#|/\*)"),
        description="SQL comment marker present in the input.",
        fields=FIELDS_TEXT,
        compare="raw",
    ),
)

RULES_BY_ID = {rule.id: rule for rule in RULES}


def rules_for_field(field_name: str) -> tuple[Rule, ...]:
    """Return the rules that apply to ``field_name``.

    Known form fields use their own scope. Any other field name is treated
    like a free text field so that the engine stays useful when it is called
    on values that do not come from the registration form.
    """
    known = set(FIELDS_ALL)

    if field_name in known:
        return tuple(rule for rule in RULES if field_name in rule.fields)

    return tuple(rule for rule in RULES if "name" in rule.fields)


# Keywords used by the secondary heuristic scanner.
HEURISTIC_KEYWORDS = frozenset(
    {
        "select",
        "union",
        "insert",
        "update",
        "delete",
        "drop",
        "alter",
        "truncate",
        "exec",
        "execute",
        "sleep",
        "benchmark",
        "waitfor",
        "information_schema",
        "xp_cmdshell",
        "having",
        "group by",
        "order by",
    }
)

#: Broader keyword set used to spot an encoded payload.
SIGNAL_KEYWORDS = HEURISTIC_KEYWORDS | frozenset(
    {
        "or",
        "and",
        "from",
        "where",
        "like",
        "as",
        "between",
        "into",
        "values",
        "when",
        "case",
        "grant",
        "revoke",
        "shutdown",
        "pg_sleep",
        "load_file",
        "outfile",
    }
)

__all__ = [
    "Rule",
    "RULES",
    "RULES_BY_ID",
    "rules_for_field",
    "HEURISTIC_KEYWORDS",
    "SIGNAL_KEYWORDS",
    "FIELDS_ALL",
    "FIELDS_TEXT",
    "FIELDS_CRITICAL",
]
