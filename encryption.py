import os
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

load_dotenv()


def get_aes_key():

    key = os.getenv("AES_KEY")

    if not key:
        raise RuntimeError(
            "AES_KEY is missing from the .env file."
        )

    try:
        decoded_key = base64.urlsafe_b64decode(key)

    except Exception as error:
        raise RuntimeError(
            "AES_KEY is not valid Base64."
        ) from error

    if len(decoded_key) != 32:
        raise RuntimeError(
            "AES_KEY must decode to exactly 32 bytes for AES-256."
        )

    return decoded_key


def encrypt_data(data):

    key = get_aes_key()

    aes = AESGCM(key)

    nonce = os.urandom(12)

    encrypted = aes.encrypt(
        nonce,
        str(data).encode("utf-8"),
        None
    )

    combined = nonce + encrypted

    return base64.urlsafe_b64encode(
        combined
    ).decode("utf-8")