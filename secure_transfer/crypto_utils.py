"""Cryptographic helper functions used by both client and server.

This file keeps the crypto code in one place so the main client/server files are easier
to read during demo.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def b64e(data: bytes) -> str:
    """Convert bytes to base64 text so bytes can be stored inside JSON."""

    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    """Convert base64 text back into bytes."""

    return base64.b64decode(data.encode("ascii"))


def canonical_json(data: dict[str, Any]) -> bytes:
    """Create stable JSON bytes so signing and verifying use the exact same format."""

    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Returns a SHA-256 hash as hexadecimal text."""

    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize().hex()


def load_private_key(path: Path, password: str | None):
    """Load an encrypted PEM private key from disk."""

    key_bytes = path.read_bytes()
    pw_bytes = password.encode("utf-8") if password else None
    return serialization.load_pem_private_key(key_bytes, password=pw_bytes)


def load_certificate(path: Path) -> x509.Certificate:
    """Load a PEM certificate from disk."""

    return x509.load_pem_x509_certificate(path.read_bytes())


def certificate_to_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def certificate_from_pem(pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem.encode("ascii"))


def sign_metadata(private_key_path: Path, password: str | None, metadata: dict[str, Any]) -> str:
    """Sign transfer metadata using RSA-PSS-SHA256.

    The metadata includes the SHA-256 hash of the real message/file, so signing the
    metadata also protects the uploaded content.
    """

    private_key = load_private_key(private_key_path, password)
    signature = private_key.sign(
        canonical_json(metadata),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return b64e(signature)


def verify_metadata_signature(cert: x509.Certificate, metadata: dict[str, Any], signature_b64: str) -> bool:
    """Return True only if the RSA-PSS signature is valid."""

    try:
        cert.public_key().verify(
            b64d(signature_b64),
            canonical_json(metadata),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def encrypt_for_storage(server_cert: x509.Certificate, plaintext: bytes) -> dict[str, str]:
    """Encrypt a record before saving it on the server.

    Hybrid encryption is used:
    - AES-256-GCM encrypts the actual record because it is fast for data.
    - RSA-OAEP encrypts the AES key using the server public key.
    """

    # Fresh random AES key for every stored record.
    content_key = AESGCM.generate_key(bit_length=256)

    # GCM requires a unique nonce for each encryption.
    nonce = os.urandom(12)
    ciphertext = AESGCM(content_key).encrypt(nonce, plaintext, None)

    # Wrap the AES key so only the server private key can recover it.
    public_key = server_cert.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Server certificate must contain an RSA public key")
    wrapped_key = public_key.encrypt(
        content_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return {
        "version": "1",
        "content_algorithm": "AES-256-GCM",
        "key_wrap_algorithm": "RSA-OAEP-SHA256",
        "nonce_b64": b64e(nonce),
        "wrapped_key_b64": b64e(wrapped_key),
        "ciphertext_b64": b64e(ciphertext),
    }


def decrypt_from_storage(server_private_key_path: Path, password: str | None, envelope: dict[str, str]) -> bytes:
    """Decrypt one encrypted storage envelope."""

    private_key = load_private_key(server_private_key_path, password)
    content_key = private_key.decrypt(
        b64d(envelope["wrapped_key_b64"]),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return AESGCM(content_key).decrypt(b64d(envelope["nonce_b64"]), b64d(envelope["ciphertext_b64"]), None)
