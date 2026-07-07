"""Generate keys and certificates for the demo PKI.

PKI means Public Key Infrastructure.

For this assignment demo, this file creates:
1. A local Certificate Authority (CA)
2. A server certificate and encrypted private key
3. A client certificate and encrypted private key

The CA signs the server and client certificates, so they can trust each other during
mutual TLS.
"""

from __future__ import annotations

import argparse
import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _new_key() -> rsa.RSAPrivateKey:
    """Create one RSA private key."""

    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def _write_key(path: Path, key: rsa.RSAPrivateKey, password: str) -> None:
    """Save a private key encrypted with a password."""

    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.BestAvailableEncryption(password.encode("utf-8")),
        )
    )


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    """Save a public certificate."""

    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _name(common_name: str) -> x509.Name:
    """Create a certificate subject/issuer name."""

    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "SG"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SP ST2504 Assignment 2"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _make_signed_cert(
    subject_name: x509.Name,
    subject_key: rsa.RSAPrivateKey,
    issuer_name: x509.Name,
    issuer_key: rsa.RSAPrivateKey,
    is_ca: bool,
    eku: ExtendedKeyUsageOID | None = None,
) -> x509.Certificate:
    """Create one certificate signed by the issuer key."""

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=5))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=0 if is_ca else None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), critical=False)
    )
    if not is_ca:
        # Link this certificate back to the CA key that signed it.
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False
        )
    if eku:
        # Extended Key Usage says whether the certificate is for a server or client.
        builder = builder.add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
    if subject_name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "localhost":
        # The client connects to localhost, so the server certificate must allow localhost.
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
    return builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())


def generate_pki(out_dir: Path, password: str) -> None:
    """Generate all demo certificates and encrypted keys."""

    out_dir.mkdir(parents=True, exist_ok=True)

    # The CA is the trusted root for this demo.
    ca_key = _new_key()
    ca_cert = _make_signed_cert(_name("Aetheria Demo CA"), ca_key, _name("Aetheria Demo CA"), ca_key, True)

    # Server identity for TLS and encrypted storage.
    server_key = _new_key()
    server_cert = _make_signed_cert(
        _name("localhost"), server_key, ca_cert.subject, ca_key, False, ExtendedKeyUsageOID.SERVER_AUTH
    )

    # Client identity for mutual TLS and digital signatures.
    client_key = _new_key()
    client_cert = _make_signed_cert(
        _name("student-client"), client_key, ca_cert.subject, ca_key, False, ExtendedKeyUsageOID.CLIENT_AUTH
    )

    # Save everything into deployment/pki.
    _write_key(out_dir / "ca.key", ca_key, password)
    _write_cert(out_dir / "ca.crt", ca_cert)
    _write_key(out_dir / "server.key", server_key, password)
    _write_cert(out_dir / "server.crt", server_cert)
    _write_key(out_dir / "client.key", client_key, password)
    _write_cert(out_dir / "client.crt", client_cert)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate encrypted keys and certificates for the demo PKI.")
    parser.add_argument("--out", default="deployment/pki", help="Output folder for keys and certificates")
    parser.add_argument("--password", default="changeit", help="Demo passphrase for generated private keys")
    args = parser.parse_args()
    generate_pki(Path(args.out), args.password)
    print(f"Generated CA, server, and client certificates in {args.out}")


if __name__ == "__main__":
    main()
