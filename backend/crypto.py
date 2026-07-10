"""Symmetric encryption for credential storage using AES-256-GCM.

Encryption key is derived from CREDENTIAL_PASSPHRASE env var using PBKDF2.
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

_SALT_LEN = 16
_NONCE_LEN = 12
_KEY_LEN = 32  # AES-256


def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_LEN,
        salt=salt,
        iterations=600_000,
    )
    return kdf.derive(passphrase.encode())


def encrypt(plaintext: bytes, passphrase: str) -> bytes:
    """Encrypt plaintext and return salt + nonce + ciphertext."""
    salt = os.urandom(_SALT_LEN)
    key = derive_key(passphrase, salt)
    nonce = os.urandom(_NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return salt + nonce + ct


def decrypt(blob: bytes, passphrase: str) -> bytes:
    """Decrypt a blob produced by encrypt()."""
    salt = blob[:_SALT_LEN]
    nonce = blob[_SALT_LEN:_SALT_LEN + _NONCE_LEN]
    ct = blob[_SALT_LEN + _NONCE_LEN:]
    key = derive_key(passphrase, salt)
    return AESGCM(key).decrypt(nonce, ct, None)
