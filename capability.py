import os
import hmac
from dotenv import load_dotenv

load_dotenv()


# ==========================================
# Capability Code Verification
# ==========================================

def check_capability_code(user_code):
    """
    Verifies whether the provided capability code
    matches the secure capability code stored in
    the environment variables.

    Returns:
        True  -> Authorized
        False -> Unauthorized
    """

    secure_code = os.getenv("CAPABILITY_CODE")

    # Missing environment variable
    if secure_code is None:
        print("⚠ CAPABILITY_CODE not found in .env")
        return False

    # Empty input
    if not user_code:
        return False

    # Secure comparison (prevents timing attacks)
    return hmac.compare_digest(
        user_code.strip(),
        secure_code.strip()
    )