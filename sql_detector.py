import re


# ==========================================
# SQL Injection Detection Patterns
# ==========================================

SQL_ATTACK_PATTERNS = [

    # Authentication bypass
    r"(\bor\b|\band\b)\s+\d+\s*=\s*\d+",
    r"'\s*or\s*'1'\s*=\s*'1",
    r'"\s*or\s*"1"\s*=\s*"1',

    # UNION attacks
    r"union\s+select",

    # Data Definition Language
    r"drop\s+table",
    r"truncate\s+table",
    r"alter\s+table",
    r"create\s+table",

    # Data Manipulation Language
    r"delete\s+from",
    r"insert\s+into",
    r"update\s+\w+\s+set",

    # Stored Procedures
    r"exec(\s|\()",
    r"execute(\s|\()",

    # Database Information
    r"information_schema",
    r"sysobjects",
    r"syscolumns",

    # SQL Comments
    r"--",
    r"#",
    r"/\*.*?\*/",

    # Time-Based SQL Injection
    r"sleep\s*\(",
    r"benchmark\s*\(",
    r"waitfor\s+delay",

    # File Operations
    r"load_file\s*\(",
    r"into\s+outfile",

    # Encoded Characters
    r"%27",
    r"%23",
    r"%3D",
]


# ==========================================
# SQL Injection Detection Function
# ==========================================

def detect_sql_injection(user_input):

    """
    Returns True if suspicious SQL keywords
    or attack patterns are detected.
    """

    if not user_input:
        return False

    text = str(user_input).strip()

    for pattern in SQL_ATTACK_PATTERNS:

        if re.search(
            pattern,
            text,
            re.IGNORECASE
        ):

            return True

    return False