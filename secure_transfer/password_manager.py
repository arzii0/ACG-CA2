"""Generate strong passwords and safely re-encrypt private keys."""

from __future__ import annotations

import secrets
from pathlib import Path

from cryptography.hazmat.primitives import serialization


PASSWORD_BYTES = 24


def generate_strong_password() -> str:
    """Return a URL-safe random password with about 192 bits of randomness."""

    return secrets.token_urlsafe(PASSWORD_BYTES)


def change_private_key_password(
    key_path: Path,
    current_password: str,
) -> str:
    """Re-encrypt one PEM private key with a newly generated password."""

    private_key = serialization.load_pem_private_key(
        key_path.read_bytes(),
        password=current_password.encode("utf-8"),
    )
    new_password = generate_strong_password()
    encrypted_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(
            new_password.encode("utf-8")
        ),
    )

    # Write to a temporary file first so an interrupted operation does not
    # damage the working private key.
    temporary_path = key_path.with_name(key_path.name + ".new")
    try:
        temporary_path.write_bytes(encrypted_key)
        temporary_path.replace(key_path)
    finally:
        temporary_path.unlink(missing_ok=True)

    return new_password
