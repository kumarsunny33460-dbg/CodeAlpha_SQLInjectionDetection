import os

from dotenv import load_dotenv

load_dotenv()


def check_capability_code(code):

    stored_code = os.getenv("CAPABILITY_CODE")

    if not stored_code:
        return False

    if not code:
        return False

    return code.strip() == stored_code.strip()