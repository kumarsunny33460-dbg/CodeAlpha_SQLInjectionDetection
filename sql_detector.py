import re


SQL_ATTACK_PATTERNS = [

    # OR / AND based injection
    r"(?i)\bOR\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+",
    r"(?i)\bAND\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+",

    # UNION attacks
    r"(?i)\bUNION\s+(ALL\s+)?SELECT\b",

    # Database manipulation
    r"(?i)\bDROP\s+(TABLE|DATABASE)\b",
    r"(?i)\bDELETE\s+FROM\b",
    r"(?i)\bINSERT\s+INTO\b",
    r"(?i)\bUPDATE\s+\w+\s+SET\b",

    # SQL comments
    r"(--|/\*|\*/|#)",

    # Common SQL functions
    r"(?i)\bEXEC(\s|\()",
    r"(?i)\bXP_CMDSHELL\b",

    # Information schema
    r"(?i)\bINFORMATION_SCHEMA\b",

    # Stacked query pattern
    r";\s*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b"
]


def detect_sql_injection(value):

    if value is None:
        return False

    value = str(value).strip()

    if not value:
        return False

    for pattern in SQL_ATTACK_PATTERNS:
        if re.search(pattern, value):
            return True

    return False