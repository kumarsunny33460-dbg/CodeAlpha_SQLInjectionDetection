import re


# Advanced SQL Injection Detection Patterns

SQL_ATTACK_PATTERNS = [

    # Authentication bypass attacks
    r"(\bor\b|\band\b)\s+\d+\s*=\s*\d+",
    r"(\bor\b|\band\b)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?",

    # UNION based attacks
    r"union\s+select",
    r"union\s+all\s+select",

    # Database manipulation
    r"drop\s+table",
    r"delete\s+from",
    r"insert\s+into",
    r"update\s+\w+\s+set",

    # SQL comments
    r"--",
    r"/\*.*\*/",

    # Query termination
    r";",

    # Common injection characters
    r"'.*or.*'",
    r"'.*--",

    # Information extraction
    r"information_schema",
    r"sleep\s*\(",
    r"benchmark\s*\(",

    # Admin bypass
    r"admin\s*['\"]?\s*=",

]


def detect_sql_injection(user_input):

    if not user_input:
        return False


    user_input = user_input.lower()


    for pattern in SQL_ATTACK_PATTERNS:

        if re.search(
            pattern,
            user_input,
            re.IGNORECASE
        ):
            return True


    return False



def get_attack_type(user_input):

    if not user_input:
        return "Unknown"


    user_input = user_input.lower()


    if "union select" in user_input:
        return "UNION Based SQL Injection"


    if "drop table" in user_input:
        return "Database Destruction Attempt"


    if "--" in user_input:
        return "SQL Comment Injection"


    if " or " in user_input:
        return "Authentication Bypass"


    if ";" in user_input:
        return "Query Manipulation"


    return "Suspicious SQL Pattern"