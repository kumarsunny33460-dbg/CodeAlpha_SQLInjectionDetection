import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()


# ==========================================
# Load Encryption Key
# ==========================================

AES_KEY = os.getenv("AES_KEY")

if not AES_KEY:
    raise ValueError(
        "AES_KEY is missing! Please add it to your .env file."
    )


try:
    cipher = Fernet(AES_KEY.encode())

except Exception as error:
    raise ValueError(
        f"Invalid AES_KEY in .env: {error}"
    )


# ==========================================
# Encrypt Data
# ==========================================

def encrypt_data(data):
    """
    Encrypts plain text using Fernet symmetric encryption.

    Args:
        data (str): Plain text

    Returns:
        str: Encrypted text
    """

    if data is None:
        return ""

    encrypted = cipher.encrypt(
        str(data).encode()
    )

    return encrypted.decode()


# ==========================================
# Decrypt Data
# ==========================================

def decrypt_data(data):
    """
    Decrypts encrypted text.

    Args:
        data (str): Encrypted text

    Returns:
        str: Original plain text
    """

    if not data:
        return ""

    decrypted = cipher.decrypt(
        data.encode()
    )

    return decrypted.decode()


# ==========================================
# Encryption Status
# ==========================================

def encryption_status():
    """
    Returns True if encryption
    is configured correctly.
    """

    return cipher is not None